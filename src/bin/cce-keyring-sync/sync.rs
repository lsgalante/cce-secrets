//! The three-way merge against an `Interchange` — the 1Password path.
//!
//! Same table as KEYRING-SYNC.md's, keyed by the interchange's item id
//! (`op-item` on the keyring side). Unlike the kdbx merge this replaced,
//! there is no file, so nothing is batched — every remote write is
//! one `op` call, and the first remote failure stops the apply loop with the
//! base snapshot kept for everything not yet applied, so the next run
//! re-plans from the same place. Conflict losers need no History push:
//! 1Password records item history on every edit.
//!
//! Change detection on the remote side is by `updated_at`: an entry whose
//! timestamp still equals the base's is unchanged and never fetched. The
//! keyring side does the same by `Modified`, which gnome-keyring bumps on
//! every label, attribute and secret edit and leaves alone on a read
//! (measured 2026-10-06): an item whose time still equals the base's is not
//! read past its attributes. So a quiet tick is one `op item list`, two
//! keyring calls per item, and no secrets — until 2026-10-06 it read and
//! decrypted every password (~1,500 calls for 379 items) to find nothing.

use std::collections::HashMap;

use secret_service::{EncryptionType, SecretService};

use crate::adopt::{OP_ITEM_ATTR, OP_VAULT_ATTR};
use crate::op::{Interchange, RemoteEntry};
use crate::{journal_append, keyring_get, now_unix, take_lock, write_state, EntryState, KrEntry, State, APP};

/// Allowed clock skew before "newer" means anything (the keyring's
/// `Modified` is local time; the remote's is the server's).
pub const SKEW_TOLERANCE_SECS: i64 = 3;

/// Items the remote lists that must never reach the keyring: 1Password's
/// own account item carries the Secret Key and account password.
pub fn excluded_title(title: &str) -> bool {
    title.starts_with("1Password Account")
}

/// What one entry needs done.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Plan {
    ToKeyring,
    ToRemote,
    /// Born in the keyring (or resurrected there): create remotely, stamp.
    CreateRemote,
    /// Both changed: newer wins, tie to the remote.
    ConflictRemoteWins,
    ConflictKeyringWins,
    DeleteKeyring,
    RecycleRemote,
    InSync,
    /// Gone on both sides: drop the base.
    Forget,
}

/// One side's view of an entry for planning: its field hash and mtime.
#[derive(Debug, Clone, PartialEq)]
pub struct Side {
    pub hash: String,
    pub time: i64,
}

/// The merge table, pure. `base` is the last-synced hash, if any.
pub fn plan(base: Option<&str>, remote: Option<&Side>, keyring: Option<&Side>) -> Plan {
    let newer_remote = |r: &Side, k: &Side| (r.time - k.time).abs() <= SKEW_TOLERANCE_SECS || r.time >= k.time;
    match (base, remote, keyring) {
        (None, Some(_), None) => Plan::ToKeyring,
        (None, None, Some(_)) => Plan::CreateRemote,
        (None, Some(r), Some(k)) => {
            // Stamped but no base (a run died before writing state).
            if r.hash == k.hash {
                Plan::InSync
            } else if newer_remote(r, k) {
                Plan::ConflictRemoteWins
            } else {
                Plan::ConflictKeyringWins
            }
        }
        (Some(b), Some(r), Some(k)) => match (r.hash != b, k.hash != b) {
            (false, false) => Plan::InSync,
            (true, false) => Plan::ToKeyring,
            (false, true) => Plan::ToRemote,
            (true, true) => {
                if newer_remote(r, k) {
                    Plan::ConflictRemoteWins
                } else {
                    Plan::ConflictKeyringWins
                }
            }
        },
        // Deleted on one side; modification on the other beats deletion.
        (Some(b), None, Some(k)) => {
            if k.hash != b {
                Plan::CreateRemote
            } else {
                Plan::DeleteKeyring
            }
        }
        (Some(b), Some(r), None) => {
            if r.hash != b {
                Plan::ToKeyring
            } else {
                Plan::RecycleRemote
            }
        }
        (Some(_), None, None) | (None, None, None) => Plan::Forget,
    }
}

fn remote_to_kr(e: &RemoteEntry, modified: u64) -> KrEntry {
    KrEntry {
        title: e.title.clone(),
        username: e.username.clone(),
        password: e.password.clone(),
        url: e.url.clone(),
        notes: e.notes.clone(),
        group: e.vault.clone(),
        modified,
    }
}

fn kr_to_remote(k: &KrEntry, id: &str, vault: &str) -> RemoteEntry {
    RemoteEntry {
        id: id.to_string(),
        vault: vault.to_string(),
        title: k.title.clone(),
        username: k.username.clone(),
        password: k.password.clone(),
        url: k.url.clone(),
        notes: k.notes.clone(),
        updated: 0,
        updated_raw: String::new(),
    }
}

fn keyring_attrs<'a>(k: &'a KrEntry, id: &'a str, extra: &'a HashMap<String, String>) -> HashMap<&'a str, &'a str> {
    // Keep whatever else the item carried (kdbx-uuid, xdg:schema, …).
    let mut a: HashMap<&str, &str> = extra.iter().map(|(x, y)| (x.as_str(), y.as_str())).collect();
    a.insert(OP_ITEM_ATTR, id);
    a.insert(OP_VAULT_ATTR, k.group.as_str());
    a.insert("UserName", k.username.as_str());
    a.insert("URL", k.url.as_str());
    a.insert("Notes", k.notes.as_str());
    a
}

struct Local<'a> {
    item: secret_service::Item<'a>,
    attrs: HashMap<String, String>,
    modified: u64,
    /// The item's synced fields, or `None` when its `Modified` still equals
    /// the base's: unchanged since the last sync, so its hash is the base's
    /// and its label and secret were never read. Every plan that writes
    /// keyring fields elsewhere reads them first ([`ensure_read`]).
    entry: Option<KrEntry>,
}

/// Whether a keyring item can stand on its base unread: it has one, and its
/// `Modified` is the one the base recorded. A zero time is never trusted —
/// it is what a failed read once defaulted to.
fn unchanged_since_base(base: Option<&EntryState>, modified: u64) -> bool {
    base.is_some_and(|b| modified != 0 && b.keyring_modified == modified)
}

/// Read an item's synced fields. Any failure stops the pass (see the
/// snapshot below): a read that could not be answered never stands in as
/// an empty value.
async fn read_entry(
    item: &secret_service::Item<'_>,
    attrs: &HashMap<String, String>,
    modified: u64,
    vault: &str,
) -> Result<KrEntry, String> {
    let unreadable = |what: &str, e: &dyn std::fmt::Display| {
        let which = attrs.get(OP_ITEM_ATTR).map(String::as_str).unwrap_or("an unpaired item");
        format!("reading the {what} of {which} failed: {e}; nothing synced this pass")
    };
    let title = item.get_label().await.map_err(|e| unreadable("title", &e))?;
    let secret = item.get_secret().await.map_err(|e| unreadable("password", &e))?;
    Ok(KrEntry {
        title,
        username: attrs.get("UserName").cloned().unwrap_or_default(),
        password: String::from_utf8_lossy(&secret).into_owned(),
        url: attrs.get("URL").cloned().unwrap_or_default(),
        notes: attrs.get("Notes").cloned().unwrap_or_default(),
        group: attrs.get(OP_VAULT_ATTR).cloned().unwrap_or_else(|| vault.to_string()),
        modified,
    })
}

/// A local item's fields, reading them now if the snapshot skipped them.
async fn ensure_read(l: &mut Local<'_>, vault: &str) -> Result<(), String> {
    if l.entry.is_none() {
        l.entry = Some(read_entry(&l.item, &l.attrs, l.modified, vault).await?);
    }
    Ok(())
}

/// One merge pass. Always writes the state file on a real run (with
/// `last_result` set to the outcome, success or not) unless it could not
/// even start. Returns the one-line summary, or the error.
/// Removals one pass may make before it is refused: deletions from the
/// keyring plus archives in 1Password, at most 10% of the synced entries
/// and never fewer than this.
const MASS_REMOVAL_FLOOR: usize = 5;

/// Whether a pass removing `removals` items, with `synced` entries in the
/// base, looks like a mistake rather than an edit.
///
/// Nothing else bounded it. The vault is named, not pinned by id, and `op`
/// uses its default account, so a second account with its own "Personal"
/// vault becoming the default would list entirely different items: every
/// synced entry would read as deleted in 1Password, and the pass would
/// hard-delete all of them from the keyring. People delete a few items at a
/// time; a pass that would remove a tenth of everything stops and says so.
pub fn is_mass_removal(removals: usize, synced: usize) -> bool {
    removals > MASS_REMOVAL_FLOOR.max(synced / 10)
}

pub async fn sync_remote<I: Interchange>(
    remote: &mut I,
    state_path: &std::path::Path,
    state: &mut State,
    dry_run: bool,
    allow_mass_removal: bool,
) -> Result<String, String> {
    let Some(_lock) = take_lock() else {
        return Err("another cce-keyring-sync is running".into());
    };
    if state.backend != "onepassword" {
        return Err("the sync base is not 1Password's — run `cce-keyring-sync adopt` first".into());
    }
    let vault = state.vault.clone();

    let ss = SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(|e| format!("Secret Service unavailable: {e}"))?;
    let hash_key: [u8; 32] = match keyring_get(&ss, "state-hash-key").await {
        Ok(Some(b)) if b.len() == 32 => b.try_into().unwrap(),
        _ => return Err("no state hash key — run `cce-keyring-sync adopt` first".into()),
    };
    let col = ss.get_default_collection().await.map_err(|e| format!("no default collection: {e}"))?;
    // A read the keyring could not answer must stop the pass, never stand
    // in as an empty value. Until 2026-10-02 every read below fell back to a
    // default — a lock state of "unlocked", an empty password and title, a
    // modified time of 0 — so a keyring that locked or restarted mid-pass
    // read as every item having been blanked here, which the plan then
    // pushed to 1Password as edits (and other machines pulled back). An item
    // whose attributes failed to read was skipped, which read as deleted and
    // archived its 1Password copy. A pass that errs writes nothing: the
    // snapshot is taken before any plan is applied, and the daemon retries.
    let locked = col.is_locked().await.map_err(|e| format!("cannot tell whether the keyring is locked: {e}"))?;
    if locked && col.unlock().await.is_err() {
        return Err("collection locked".into());
    }

    // ---- keyring snapshot ----
    let mut kr: HashMap<String, Local<'_>> = HashMap::new();
    let mut born: Vec<Local<'_>> = Vec::new();
    for item in col.get_all_items().await.map_err(|e| format!("listing collection failed: {e}"))? {
        let attrs = item
            .get_attributes()
            .await
            .map_err(|e| format!("reading an item's attributes failed: {e}; nothing synced this pass"))?;
        if attrs.get("application").map(String::as_str) == Some(APP) {
            continue;
        }
        let id = attrs.get(OP_ITEM_ATTR).cloned();
        if id.is_none() && !attrs.contains_key("UserName") && !attrs.contains_key("kdbx-uuid") {
            continue; // some other app's item — never ours to sync
        }
        let modified = item.get_modified().await.map_err(|e| {
            let which = attrs.get(OP_ITEM_ATTR).map(String::as_str).unwrap_or("an unpaired item");
            format!("reading the modified time of {which} failed: {e}; nothing synced this pass")
        })?;
        // Unchanged since the base: the label and the secret are not read.
        let unchanged = unchanged_since_base(id.as_ref().and_then(|id| state.entries.get(id)), modified);
        let entry = if unchanged { None } else { Some(read_entry(&item, &attrs, modified, &vault).await?) };
        let local = Local { item, attrs, modified, entry };
        match id {
            Some(id) => {
                // Two items with one stamp (a tool that re-created rather than
                // edited): the newer one is the person's latest word.
                let newer = kr.get(&id).is_none_or(|old| local.modified >= old.modified);
                if newer {
                    kr.insert(id, local);
                }
            }
            None => born.push(local),
        }
    }

    // ---- remote snapshot: the list, then fetches only where needed ----
    let summaries = remote.list().await?;
    let mut rs: HashMap<String, crate::op::RemoteSummary> = HashMap::new();
    for s in summaries {
        if excluded_title(&s.title) {
            continue;
        }
        rs.insert(s.id.clone(), s);
    }
    let mut fetched: HashMap<String, RemoteEntry> = HashMap::new();
    let mut fetches = 0usize;

    let mut ids: Vec<String> = state.entries.keys().chain(rs.keys()).chain(kr.keys()).cloned().collect();
    ids.sort();
    ids.dedup();

    // ---- plan ----
    let mut plans: Vec<(String, Plan)> = Vec::new();
    for id in &ids {
        let base = state.entries.get(id);
        let k_side = kr.get(id).map(|l| Side {
            hash: match &l.entry {
                Some(e) => e.hash(&hash_key),
                // Not read: unchanged since the base, which is what it hashed to.
                None => base.map(|b| b.h.clone()).unwrap_or_default(),
            },
            time: l.modified as i64,
        });
        let r_side = match rs.get(id) {
            None => None,
            Some(s) => {
                let unchanged = base.is_some_and(|b| !b.op_updated_at.is_empty() && b.op_updated_at == s.updated_raw);
                if unchanged {
                    Some(Side { hash: base.unwrap().h.clone(), time: s.updated })
                } else {
                    let e = remote.fetch(id).await?;
                    fetches += 1;
                    let h = remote_to_kr(&e, 0).hash(&hash_key);
                    fetched.insert(id.clone(), e);
                    Some(Side { hash: h, time: s.updated })
                }
            }
        };
        plans.push((id.clone(), plan(base.map(|b| b.h.as_str()), r_side.as_ref(), k_side.as_ref())));
    }

    // The plans that copy keyring fields out need them read. An item left
    // unread hashes to its base, so these never pick one — but the fields
    // are read rather than trusted to that.
    for (id, p) in &plans {
        if matches!(p, Plan::ToRemote | Plan::ConflictKeyringWins | Plan::CreateRemote) {
            if let Some(l) = kr.get_mut(id) {
                ensure_read(l, &vault).await?;
            }
        }
    }
    let kr = kr;

    // ---- report ----
    let title_of = |id: &str| -> String {
        rs.get(id)
            .map(|s| s.title.clone())
            .or_else(|| kr.get(id).and_then(|l| l.entry.as_ref()).map(|e| e.title.clone()))
            .unwrap_or_else(|| id.to_string())
    };
    let mut journal = String::new();
    let mut counts: HashMap<&'static str, usize> = HashMap::new();
    for (id, p) in &plans {
        let verb = match p {
            Plan::ToKeyring => "1Password -> keyring",
            Plan::ToRemote => "keyring -> 1Password",
            Plan::CreateRemote => "create in 1Password",
            Plan::ConflictRemoteWins => "CONFLICT: 1Password wins (loser in item history)",
            Plan::ConflictKeyringWins => "CONFLICT: keyring wins (loser in item history)",
            Plan::DeleteKeyring => "delete from keyring",
            Plan::RecycleRemote => "archive in 1Password",
            Plan::InSync | Plan::Forget => continue,
        };
        *counts
            .entry(match p {
                Plan::ToKeyring | Plan::ConflictRemoteWins => "to-keyring",
                Plan::ToRemote | Plan::ConflictKeyringWins => "to-remote",
                Plan::CreateRemote => "created",
                Plan::DeleteKeyring => "deleted",
                Plan::RecycleRemote => "archived",
                _ => unreachable!(),
            })
            .or_default() += 1;
        println!("  {verb}: {}", title_of(id));
        journal.push_str(&format!("{} sync {verb}: {}\n", now_unix(), title_of(id)));
    }
    let full = |l: &Local<'_>| -> KrEntry { l.entry.clone().expect("read before the plan used it") };
    for l in &born {
        let title = &l.entry.as_ref().expect("born items are always read").title;
        println!("  create in 1Password: {title}");
        journal.push_str(&format!("{} sync create in 1Password: {title}\n", now_unix()));
        *counts.entry("created").or_default() += 1;
    }
    let c = |k: &str| counts.get(k).copied().unwrap_or(0);
    let quiet = plans.iter().all(|(_, p)| matches!(p, Plan::InSync | Plan::Forget)) && born.is_empty();
    let summary = if quiet {
        "in sync".to_string()
    } else {
        format!(
            "synced: {} -> keyring, {} -> 1Password, {} created, {} deleted, {} archived",
            c("to-keyring"),
            c("to-remote"),
            c("created"),
            c("deleted"),
            c("archived")
        )
    };
    if dry_run {
        println!("{summary} (dry run — nothing changed; {fetches} fetched)");
        return Ok(summary);
    }
    let removals = c("deleted") + c("archived");
    if !allow_mass_removal && is_mass_removal(removals, state.entries.len()) {
        return Err(format!(
            "refusing a pass that would remove {removals} of {} synced items ({}) — nothing changed. \
             If 1Password's default account or vault changed, fix that; if the removals are meant, \
             run `cce-keyring-sync sync --dry-run` to review them, then `cce-keyring-sync sync --allow-mass-delete`",
            state.entries.len(),
            summary
        ));
    }

    // ---- apply ----
    // `next` starts as the old base and is rewritten entry by entry, so a
    // remote failure mid-way leaves untouched entries with their old base.
    let mut next: HashMap<String, EntryState> = state.entries.drain().collect();
    let mut failure: Option<String> = None;
    let mut applied = 0usize;

    let snapshot = |k: &KrEntry, updated_raw: String, keyring_modified: u64| EntryState {
        h: k.hash(&hash_key),
        keyring_modified,
        op_updated_at: updated_raw,
    };
    'apply: for (id, p) in &plans {
        match p {
            Plan::InSync => {
                // Keep the base timestamp on the list's value: it was unknown
                // after adopt (the drift marker), and the server may stamp a
                // write a second later than the reply we recorded. Either way
                // the entry would be fetched every tick until this catches up.
                if let (Some(s), Some(b)) = (rs.get(id), next.get_mut(id)) {
                    if b.op_updated_at != s.updated_raw {
                        b.op_updated_at = s.updated_raw.clone();
                    }
                }
                // The keyring's time likewise: an item that was read (its
                // time moved) yet hashes to the base was touched without a
                // change. Recording the time lets the next pass skip it.
                if let (Some(l), Some(b)) = (kr.get(id), next.get_mut(id)) {
                    if l.entry.is_some() && b.keyring_modified != l.modified {
                        b.keyring_modified = l.modified;
                    }
                }
            }
            Plan::Forget => {
                next.remove(id);
            }
            Plan::ToKeyring | Plan::ConflictRemoteWins => {
                let e = match fetched.get(id) {
                    Some(e) => e.clone(),
                    None => match remote.fetch(id).await {
                        Ok(e) => {
                            fetches += 1;
                            e
                        }
                        Err(err) => {
                            failure = Some(err);
                            break 'apply;
                        }
                    },
                };
                let k = remote_to_kr(&e, 0);
                let empty = HashMap::new();
                let modified = match kr.get(id) {
                    Some(l) => {
                        let attrs = keyring_attrs(&k, id, &l.attrs);
                        let r = async {
                            l.item.set_label(&k.title).await?;
                            l.item.set_attributes(attrs).await?;
                            l.item.set_secret(k.password.as_bytes(), "text/plain").await?;
                            l.item.get_modified().await
                        }
                        .await;
                        match r {
                            Ok(m) => m,
                            Err(err) => {
                                eprintln!("  keyring write failed for {}: {err}", k.title);
                                continue;
                            }
                        }
                    }
                    None => {
                        let attrs = keyring_attrs(&k, id, &empty);
                        match col.create_item(&k.title, attrs, k.password.as_bytes(), true, "text/plain").await {
                            Ok(item) => item.get_modified().await.unwrap_or(now_unix() as u64),
                            Err(err) => {
                                eprintln!("  keyring create failed for {}: {err}", k.title);
                                continue;
                            }
                        }
                    }
                };
                next.insert(id.clone(), snapshot(&k, e.updated_raw.clone(), modified));
                applied += 1;
            }
            Plan::ToRemote | Plan::ConflictKeyringWins => {
                let k = full(&kr[id]);
                let e = kr_to_remote(&k, id, &k.group);
                match remote.update(&e).await {
                    Ok(updated_raw) => {
                        next.insert(id.clone(), snapshot(&k, updated_raw, k.modified));
                        applied += 1;
                    }
                    Err(err) => {
                        failure = Some(err);
                        break 'apply;
                    }
                }
            }
            Plan::CreateRemote => {
                // A keyring entry whose stamp points at nothing any more
                // (archived remotely, edited locally): create afresh, restamp.
                let l = &kr[id];
                let entry = full(l);
                let mut e = kr_to_remote(&entry, "", &vault);
                e.vault = vault.clone();
                match remote.create(&e).await {
                    Ok((new_id, updated_raw)) => {
                        let mut k = entry.clone();
                        k.group = vault.clone();
                        let attrs = keyring_attrs(&k, &new_id, &l.attrs);
                        let modified = match async {
                            l.item.set_attributes(attrs).await?;
                            l.item.get_modified().await
                        }
                        .await
                        {
                            Ok(m) => m,
                            Err(err) => {
                                eprintln!("  could not restamp {}: {err}", k.title);
                                entry.modified
                            }
                        };
                        next.remove(id);
                        next.insert(new_id, snapshot(&k, updated_raw, modified));
                        applied += 1;
                    }
                    Err(err) => {
                        failure = Some(err);
                        break 'apply;
                    }
                }
            }
            Plan::DeleteKeyring => {
                let l = &kr[id];
                match l.item.delete().await {
                    Ok(()) => {
                        next.remove(id);
                        applied += 1;
                    }
                    Err(err) => eprintln!("  keyring delete failed for {}: {err}", title_of(id)),
                }
            }
            Plan::RecycleRemote => match remote.recycle(id).await {
                Ok(()) => {
                    next.remove(id);
                    applied += 1;
                }
                Err(err) => {
                    failure = Some(err);
                    break 'apply;
                }
            },
        }
    }
    if failure.is_none() {
        for l in &born {
            let mut k = full(l);
            k.group = vault.clone();
            let e = kr_to_remote(&k, "", &vault);
            match remote.create(&e).await {
                Ok((new_id, updated_raw)) => {
                    let attrs = keyring_attrs(&k, &new_id, &l.attrs);
                    let modified = match async {
                        l.item.set_attributes(attrs).await?;
                        l.item.get_modified().await
                    }
                    .await
                    {
                        Ok(m) => m,
                        Err(err) => {
                            eprintln!("  could not stamp {}: {err}", k.title);
                            l.modified
                        }
                    };
                    next.insert(new_id, snapshot(&k, updated_raw, modified));
                    applied += 1;
                }
                Err(err) => {
                    failure = Some(err);
                    break;
                }
            }
        }
    }

    state.entries = next;
    state.last_run = now_unix();
    let result = match failure {
        None => Ok(summary.clone()),
        Some(err) => {
            let changes = plans.iter().filter(|(_, p)| !matches!(p, Plan::InSync | Plan::Forget)).count() + born.len();
            Err(format!("{err} (after {applied} of {changes} changes; the rest retry next run)"))
        }
    };
    state.last_result = match &result {
        Ok(s) => s.clone(),
        Err(e) => format!("failed: {e}"),
    };
    write_state(state_path, state);
    if !journal.is_empty() {
        journal_append(&journal);
    }
    if let Err(e) = &result {
        journal_append(&format!("{} sync FAILED: {e}\n", now_unix()));
    }
    println!("{} ({fetches} fetched)", state.last_result);
    result
}

#[cfg(test)]
mod mass_removal_tests {
    use super::is_mass_removal;

    #[test]
    fn a_pass_removing_a_tenth_of_the_vault_is_refused() {
        // The live vault is ~378 entries: 37 removals pass, 38 stop.
        assert!(!is_mass_removal(37, 378));
        assert!(is_mass_removal(38, 378));
        // Every entry reading as gone — the wrong-account case.
        assert!(is_mass_removal(378, 378));
        // Small vaults still allow a handful.
        assert!(!is_mass_removal(5, 12));
        assert!(is_mass_removal(6, 12));
        assert!(!is_mass_removal(0, 0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn side(h: &str, t: i64) -> Side {
        Side { hash: h.into(), time: t }
    }

    #[test]
    fn the_merge_table() {
        let b = Some("B");
        assert_eq!(plan(None, Some(&side("R", 0)), None), Plan::ToKeyring);
        assert_eq!(plan(None, None, Some(&side("K", 0))), Plan::CreateRemote);
        assert_eq!(plan(b, Some(&side("B", 0)), Some(&side("B", 0))), Plan::InSync);
        assert_eq!(plan(b, Some(&side("R", 0)), Some(&side("B", 0))), Plan::ToKeyring);
        assert_eq!(plan(b, Some(&side("B", 0)), Some(&side("K", 0))), Plan::ToRemote);
        assert_eq!(plan(b, None, Some(&side("B", 0))), Plan::DeleteKeyring);
        assert_eq!(plan(b, None, Some(&side("K", 0))), Plan::CreateRemote, "modification beats deletion");
        assert_eq!(plan(b, Some(&side("B", 0)), None), Plan::RecycleRemote);
        assert_eq!(plan(b, Some(&side("R", 0)), None), Plan::ToKeyring, "modification beats deletion");
        assert_eq!(plan(b, None, None), Plan::Forget);
        assert_eq!(plan(None, None, None), Plan::Forget);
    }

    #[test]
    fn conflicts_go_to_the_newer_side_and_ties_to_the_remote() {
        let b = Some("B");
        assert_eq!(plan(b, Some(&side("R", 100)), Some(&side("K", 50))), Plan::ConflictRemoteWins);
        assert_eq!(plan(b, Some(&side("R", 50)), Some(&side("K", 100))), Plan::ConflictKeyringWins);
        assert_eq!(plan(b, Some(&side("R", 98)), Some(&side("K", 100))), Plan::ConflictRemoteWins, "inside the skew tolerance is a tie");
        assert_eq!(plan(b, Some(&side("R", 100)), Some(&side("K", 100))), Plan::ConflictRemoteWins);
    }

    #[test]
    fn a_stamped_entry_without_a_base_is_reconciled_by_hash() {
        assert_eq!(plan(None, Some(&side("X", 0)), Some(&side("X", 0))), Plan::InSync);
        assert_eq!(plan(None, Some(&side("R", 10)), Some(&side("K", 0))), Plan::ConflictRemoteWins);
    }

    #[test]
    fn an_item_is_skipped_only_at_its_base_time() {
        let base = EntryState { h: "B".into(), keyring_modified: 1_790_000_000, op_updated_at: String::new() };
        assert!(unchanged_since_base(Some(&base), 1_790_000_000));
        assert!(!unchanged_since_base(Some(&base), 1_790_000_001), "edited since: read it");
        assert!(!unchanged_since_base(None, 1_790_000_000), "no base: read it");
        let zero = EntryState { keyring_modified: 0, ..base };
        assert!(!unchanged_since_base(Some(&zero), 0), "a zero time proves nothing");
    }

    #[test]
    fn the_account_item_is_excluded() {
        assert!(excluded_title("1Password Account (alice)"));
        assert!(!excluded_title("Account at 1Password"));
    }
}
