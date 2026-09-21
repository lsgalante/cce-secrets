//! `adopt` — the migration step the kdbx never needed.
//!
//! After the CSV import, both the keyring and 1Password hold the same
//! entries with no link between them, so the first run must **pair, not
//! copy**: match on (title, username), exact and case-sensitive, stamp
//! `op-item` / `op-vault` on each keyring match, report everything that
//! did not pair, and write a fresh base snapshot for `sync`. Duplicate keys
//! on either side make the pairing ambiguous, and a wrong pairing silently
//! cross-links two accounts — the one mistake the merge cannot undo later —
//! so any duplicate refuses the whole run until a person has sorted it.
//!
//! The kdbx attributes are kept, deliberately: while the kdbx backend still
//! exists, an accidental kdbx `sync` must keep pairing by uuid rather than
//! see 171 orphans to re-create. Phase 3 drops them with the backend.

use std::collections::HashMap;

use secret_service::{EncryptionType, SecretService};

use crate::op::{Interchange, OnePassword, RemoteSummary};
use crate::{keyring_get, now_unix, state_dir, write_state, EntryState, KrEntry, State, APP};

/// Keyring attribute holding the paired 1Password item id.
pub const OP_ITEM_ATTR: &str = "op-item";
/// Keyring attribute holding the item's vault name.
pub const OP_VAULT_ATTR: &str = "op-vault";

/// Pairing key: exact (title, username), with the url as the tiebreaker
/// when the pair alone is ambiguous (KEYRING-SYNC.md open question 2).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    pub title: String,
    pub username: String,
    pub url: String,
}

impl Key {
    fn short(&self) -> (String, String) {
        (self.title.clone(), self.username.clone())
    }
}

/// The pairing plan for one side's keys against the other's.
#[derive(Debug, Default, PartialEq)]
pub struct PairPlan {
    /// (local index, remote index)
    pub pairs: Vec<(usize, usize)>,
    pub unmatched_local: Vec<usize>,
    pub unmatched_remote: Vec<usize>,
    /// Keys that occur more than once on the local (keyring) side.
    pub dup_local: Vec<Key>,
    /// Keys that occur more than once on the remote (1Password) side.
    pub dup_remote: Vec<Key>,
}

impl PairPlan {
    /// A duplicate anywhere makes the plan unsafe to apply.
    pub fn refused(&self) -> bool {
        !self.dup_local.is_empty() || !self.dup_remote.is_empty()
    }
}

/// Pure pairing; `pinned` gives locals already stamped with a remote id
/// (from an earlier adopt), honoured before any key match so re-running is
/// idempotent and a retitled entry stays paired.
pub fn pair(local: &[Key], remote: &[Key], pinned: &[(usize, String)], remote_ids: &[String]) -> PairPlan {
    let mut plan = PairPlan::default();
    let mut local_taken = vec![false; local.len()];
    let mut remote_taken = vec![false; remote.len()];

    let remote_by_id: HashMap<&str, usize> = remote_ids.iter().enumerate().map(|(i, id)| (id.as_str(), i)).collect();
    for (li, id) in pinned {
        if let Some(&ri) = remote_by_id.get(id.as_str()) {
            if !remote_taken[ri] {
                plan.pairs.push((*li, ri));
                local_taken[*li] = true;
                remote_taken[ri] = true;
            }
        }
    }

    // One pass per key width: what is unique on both sides under the short
    // key pairs; what is not gets a second chance with the url included.
    fn pass<K: std::hash::Hash + Eq + Clone>(
        key: impl Fn(&Key) -> K,
        local: &[Key],
        remote: &[Key],
        local_taken: &mut [bool],
        remote_taken: &mut [bool],
        pairs: &mut Vec<(usize, usize)>,
    ) {
        let count = |keys: &[Key], taken: &[bool]| -> HashMap<K, Vec<usize>> {
            let mut m: HashMap<K, Vec<usize>> = HashMap::new();
            for (i, k) in keys.iter().enumerate() {
                if !taken[i] {
                    m.entry(key(k)).or_default().push(i);
                }
            }
            m
        };
        let lmap = count(local, local_taken);
        let rmap = count(remote, remote_taken);
        for (i, k) in local.iter().enumerate() {
            if local_taken[i] {
                continue;
            }
            let k = key(k);
            if let (Some([ri]), Some([_])) = (rmap.get(&k).map(Vec::as_slice), lmap.get(&k).map(Vec::as_slice)) {
                pairs.push((i, *ri));
                local_taken[i] = true;
                remote_taken[*ri] = true;
            }
        }
    }
    pass(Key::short, local, remote, &mut local_taken, &mut remote_taken, &mut plan.pairs);
    pass(Key::clone, local, remote, &mut local_taken, &mut remote_taken, &mut plan.pairs);

    // Whatever is still untaken and shares its short key with another
    // untaken entry on the same side is a duplicate the person must sort.
    let dups = |keys: &[Key], taken: &[bool]| -> Vec<Key> {
        let mut m: HashMap<(String, String), Vec<usize>> = HashMap::new();
        for (i, k) in keys.iter().enumerate() {
            if !taken[i] {
                m.entry(k.short()).or_default().push(i);
            }
        }
        let mut d: Vec<Key> = m
            .values()
            .filter(|v| v.len() > 1)
            .flat_map(|v| v.iter().map(|&i| keys[i].clone()))
            .collect();
        d.sort();
        d.dedup();
        d
    };
    plan.dup_local = dups(local, &local_taken);
    plan.dup_remote = dups(remote, &remote_taken);

    plan.unmatched_local = (0..local.len()).filter(|&i| !local_taken[i]).collect();
    plan.unmatched_remote = (0..remote.len()).filter(|&i| !remote_taken[i]).collect();
    plan.pairs.sort();
    plan
}

/// One keyring login as adopt sees it.
struct Local<'a> {
    item: secret_service::Item<'a>,
    attrs: HashMap<String, String>,
    entry: KrEntry,
}

pub async fn adopt(state_path: &std::path::Path, mut state: State, vault: &str, dry_run: bool) {
    let vault = if vault.is_empty() { state.vault.clone() } else { vault.to_string() };
    let mut remote = OnePassword::new(&vault);

    let ss = match SecretService::connect(EncryptionType::Dh).await {
        Ok(ss) => ss,
        Err(e) => {
            eprintln!("Secret Service unavailable: {e}");
            std::process::exit(1);
        }
    };
    // The state-file hash key: minted once, kept in the keyring so the
    // state file alone leaks nothing (a fresh keyring has none yet).
    let hash_key: [u8; 32] = match keyring_get(&ss, "state-hash-key").await {
        Ok(Some(b)) if b.len() == 32 => b.try_into().unwrap(),
        _ => {
            let mut k = [0u8; 32];
            getrandom::getrandom(&mut k).expect("entropy");
            if !dry_run {
                if let Err(e) = crate::keyring_put(&ss, "state-hash-key", "cce-keyring-sync: state hash key", &k).await {
                    eprintln!("could not store the hash key: {e}");
                    std::process::exit(1);
                }
            }
            k
        }
    };
    let col = match ss.get_default_collection().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("no default collection: {e}");
            std::process::exit(1);
        }
    };
    if col.is_locked().await.unwrap_or(false) && col.unlock().await.is_err() {
        eprintln!("collection locked");
        std::process::exit(1);
    }

    // The keyring's logins: anything cce-secrets or the kdbx import wrote.
    let mut locals: Vec<Local<'_>> = Vec::new();
    match col.get_all_items().await {
        Ok(items) => {
            for item in items {
                let Ok(attrs) = item.get_attributes().await else { continue };
                if attrs.get("application").map(String::as_str) == Some(APP) {
                    continue;
                }
                if !attrs.contains_key("UserName") && !attrs.contains_key("kdbx-uuid") {
                    continue;
                }
                let entry = KrEntry {
                    title: item.get_label().await.unwrap_or_default(),
                    username: attrs.get("UserName").cloned().unwrap_or_default(),
                    password: String::from_utf8_lossy(&item.get_secret().await.unwrap_or_default()).into_owned(),
                    url: attrs.get("URL").cloned().unwrap_or_default(),
                    notes: attrs.get("Notes").cloned().unwrap_or_default(),
                    group: String::new(), // becomes the vault name once paired
                    modified: item.get_modified().await.unwrap_or(0),
                };
                locals.push(Local { item, attrs, entry });
            }
        }
        Err(e) => {
            eprintln!("listing collection failed: {e}");
            std::process::exit(1);
        }
    }
    println!("keyring: {} logins", locals.len());

    println!("1Password: listing{} … (an Authorize dialog may appear)", if vault.is_empty() { "" } else { " the vault" });
    let summaries: Vec<RemoteSummary> = match remote.list().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    println!("1Password: {} logins{}", summaries.len(), if vault.is_empty() { String::new() } else { format!(" in {vault}") });

    let lkeys: Vec<Key> = locals
        .iter()
        .map(|l| Key { title: l.entry.title.clone(), username: l.entry.username.clone(), url: l.entry.url.clone() })
        .collect();
    let rkeys: Vec<Key> = summaries
        .iter()
        .map(|r| Key { title: r.title.clone(), username: r.username.clone(), url: r.url.clone() })
        .collect();
    let rids: Vec<String> = summaries.iter().map(|r| r.id.clone()).collect();
    let pinned: Vec<(usize, String)> = locals
        .iter()
        .enumerate()
        .filter_map(|(i, l)| l.attrs.get(OP_ITEM_ATTR).map(|id| (i, id.clone())))
        .collect();
    let plan = pair(&lkeys, &rkeys, &pinned, &rids);

    let show = |k: &Key| if k.username.is_empty() { k.title.clone() } else { format!("{}  ({})", k.title, k.username) };
    let when = |t: u64| -> String {
        // Local time is not worth a dependency; the date alone tells copies apart.
        let d = t / 86400;
        let (mut y, mut rem) = (1970u64, d);
        loop {
            let len = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
            if rem < len {
                break;
            }
            rem -= len;
            y += 1;
        }
        format!("{y}+{rem}d {:02}:{:02}", (t % 86400) / 3600, (t % 3600) / 60)
    };
    // Duplicates are the person's call, so show what tells the copies apart.
    let dup_keys = |d: &[Key]| -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = d.iter().map(Key::short).collect();
        v.dedup();
        v
    };
    if !plan.dup_local.is_empty() {
        println!("\nDUPLICATE (title, username) in the keyring — same url too, so nothing tells them apart:");
        for (t, u) in dup_keys(&plan.dup_local) {
            println!("  {}", show(&Key { title: t.clone(), username: u.clone(), url: String::new() }));
            for l in locals.iter().filter(|l| l.entry.title == t && l.entry.username == u) {
                println!("      url {:<40} modified {}  group {}", l.entry.url, when(l.entry.modified), l.attrs.get("kdbx-group").map(String::as_str).unwrap_or("-"));
            }
        }
    }
    if !plan.dup_remote.is_empty() {
        println!("\nDUPLICATE (title, username) in 1Password — archive the stale copies, then retry:");
        for (t, u) in dup_keys(&plan.dup_remote) {
            println!("  {}", show(&Key { title: t.clone(), username: u.clone(), url: String::new() }));
            for r in summaries.iter().filter(|r| r.title == t && r.username == u) {
                println!("      url {:<40} updated {}  id {}", r.url, r.updated_raw, r.id);
            }
        }
    }
    if !plan.unmatched_remote.is_empty() {
        println!("\nin 1Password only ({}): left alone now; sync would mirror them into the keyring", plan.unmatched_remote.len());
        for &i in &plan.unmatched_remote {
            println!("  {}", show(&rkeys[i]));
        }
    }
    if !plan.unmatched_local.is_empty() {
        println!("\nin the keyring only ({}): left alone now; sync would create them in 1Password", plan.unmatched_local.len());
        for &i in &plan.unmatched_local {
            println!("  {}", show(&lkeys[i]));
        }
    }
    println!(
        "\npairs: {} of {} keyring / {} 1Password ({} already stamped)",
        plan.pairs.len(),
        locals.len(),
        summaries.len(),
        pinned.len()
    );
    if plan.refused() {
        eprintln!("refusing: duplicates make the pairing ambiguous; nothing changed");
        std::process::exit(1);
    }

    // Field check: the CSV import may have normalised urls or notes. Those
    // entries get an unknown base timestamp so the first sync fetches and
    // reconciles them, taking 1Password's value.
    println!("fetching {} paired items to compare fields …", plan.pairs.len());
    let mut differing: Vec<usize> = Vec::new();
    let mut fetched: HashMap<usize, crate::op::RemoteEntry> = HashMap::new();
    for (n, &(li, ri)) in plan.pairs.iter().enumerate() {
        if n > 0 && n % 25 == 0 {
            println!("  {n}/{}", plan.pairs.len());
        }
        match remote.fetch(&rids[ri]).await {
            Ok(e) => {
                let l = &locals[li].entry;
                if e.password != l.password || e.url != l.url || e.notes != l.notes {
                    differing.push(li);
                }
                fetched.insert(ri, e);
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }
    if !differing.is_empty() {
        println!("\nfields differ on {} paired entries (password/url/notes); the first sync takes 1Password's value:", differing.len());
        for &li in &differing {
            let l = &locals[li].entry;
            let r = &fetched[&plan.pairs.iter().find(|(a, _)| *a == li).unwrap().1];
            let mut what = Vec::new();
            if r.password != l.password {
                what.push("password");
            }
            if r.url != l.url {
                what.push("url");
            }
            if r.notes != l.notes {
                what.push("notes");
            }
            println!("  {}  [{}]", show(&lkeys[li]), what.join(", "));
        }
    }

    if dry_run {
        println!("\ndry run — nothing changed");
        return;
    }

    // ---- apply: stamp, then state ----
    let mut stamped = 0usize;
    let mut entries: HashMap<String, EntryState> = HashMap::new();
    for &(li, ri) in &plan.pairs {
        let l = &locals[li];
        let r = &fetched[&ri];
        let mut attrs: HashMap<&str, &str> = l.attrs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        attrs.insert(OP_ITEM_ATTR, r.id.as_str());
        attrs.insert(OP_VAULT_ATTR, r.vault.as_str());
        if let Err(e) = l.item.set_attributes(attrs).await {
            eprintln!("  could not stamp {}: {e}", l.entry.title);
            continue;
        }
        stamped += 1;
        let mut base = l.entry.clone();
        base.group = r.vault.clone();
        entries.insert(
            r.id.clone(),
            EntryState {
                h: base.hash(&hash_key),
                kdbx_mtime: 0,
                keyring_modified: l.entry.modified,
                op_updated_at: if differing.contains(&li) { String::new() } else { r.updated_raw.clone() },
            },
        );
    }

    // The kdbx base is not thrown away: sync under the old backend could
    // still be wanted if this migration is rolled back.
    if state.backend != "onepassword" && state_path.exists() {
        let backup = state_dir().join(format!("state.json.kdbx-{}", now_unix()));
        if std::fs::copy(state_path, &backup).is_ok() {
            println!("kdbx sync state backed up to {}", backup.display());
        }
    }
    state.version = 2;
    state.backend = "onepassword".to_string();
    state.vault = vault.clone();
    state.entries = entries;
    state.last_run = now_unix();
    write_state(state_path, &state);
    crate::journal_append(&format!("{} adopt stamped {stamped} entries (1Password, vault {vault})\n", now_unix()));
    println!("\nadopted: {stamped} entries stamped; backend is now 1Password");
    println!("note: the kdbx timer should be stopped — `sync` refuses under this backend until the daemon lands (phase 2)");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(t: &str, u: &str) -> Key {
        Key { title: t.to_string(), username: u.to_string(), url: String::new() }
    }

    fn ku(t: &str, u: &str, url: &str) -> Key {
        Key { title: t.to_string(), username: u.to_string(), url: url.to_string() }
    }

    #[test]
    fn the_url_breaks_a_tie_when_it_can() {
        let local = vec![ku("MS", "me", "https://a.example"), ku("MS", "me", "https://b.example")];
        let remote = vec![ku("MS", "me", "https://b.example"), ku("MS", "me", "https://a.example")];
        let ids = vec!["r0".into(), "r1".into()];
        let p = pair(&local, &remote, &[], &ids);
        assert_eq!(p.pairs, vec![(0, 1), (1, 0)]);
        assert!(!p.refused());
    }

    #[test]
    fn identical_urls_stay_ambiguous() {
        let local = vec![ku("MS", "me", "https://a.example"), ku("MS", "me", "https://a.example")];
        let remote = vec![ku("MS", "me", "https://a.example"), ku("MS", "me", "https://a.example")];
        let ids = vec!["r0".into(), "r1".into()];
        let p = pair(&local, &remote, &[], &ids);
        assert!(p.refused());
        assert!(p.pairs.is_empty());
        assert_eq!(p.dup_local.len(), 1, "reported once per key, not per copy");
    }

    #[test]
    fn exact_keys_pair_and_the_rest_are_reported() {
        let local = vec![k("GitHub", "me"), k("Bank", "me"), k("Old", "x")];
        let remote = vec![k("Bank", "me"), k("GitHub", "me"), k("New", "y")];
        let ids = vec!["r0".into(), "r1".into(), "r2".into()];
        let p = pair(&local, &remote, &[], &ids);
        assert_eq!(p.pairs, vec![(0, 1), (1, 0)]);
        assert_eq!(p.unmatched_local, vec![2]);
        assert_eq!(p.unmatched_remote, vec![2]);
        assert!(!p.refused());
    }

    #[test]
    fn matching_is_case_sensitive_and_username_aware() {
        let local = vec![k("GitHub", "me"), k("Mail", "a")];
        let remote = vec![k("github", "me"), k("Mail", "b")];
        let ids = vec!["r0".into(), "r1".into()];
        let p = pair(&local, &remote, &[], &ids);
        assert!(p.pairs.is_empty());
        assert_eq!(p.unmatched_local, vec![0, 1]);
        assert_eq!(p.unmatched_remote, vec![0, 1]);
    }

    #[test]
    fn a_duplicate_on_either_side_refuses_that_key_and_the_run() {
        let local = vec![k("Bank", "me"), k("Bank", "me"), k("Mail", "a")];
        let remote = vec![k("Bank", "me"), k("Mail", "a"), k("Mail", "a")];
        let ids = vec!["r0".into(), "r1".into(), "r2".into()];
        let p = pair(&local, &remote, &[], &ids);
        assert!(p.refused());
        assert_eq!(p.dup_local, vec![k("Bank", "me")]);
        assert_eq!(p.dup_remote, vec![k("Mail", "a")]);
        assert!(p.pairs.is_empty(), "an ambiguous key never pairs, even its single-sided partner");
        assert_eq!(p.unmatched_local, vec![0, 1, 2]);
        assert_eq!(p.unmatched_remote, vec![0, 1, 2]);
    }

    #[test]
    fn a_pinned_id_wins_over_the_key_and_survives_a_retitle() {
        let local = vec![k("Bank (renamed)", "me"), k("Bank", "me")];
        let remote = vec![k("Bank", "me")];
        let ids = vec!["r0".into()];
        // local 0 was stamped r0 in an earlier run and then retitled keyring-side.
        let p = pair(&local, &remote, &[(0, "r0".into())], &ids);
        assert_eq!(p.pairs, vec![(0, 0)]);
        assert_eq!(p.unmatched_local, vec![1], "the key match loses to the pin");
        assert!(p.unmatched_remote.is_empty());
    }

    #[test]
    fn a_pin_to_a_vanished_id_falls_back_to_the_key() {
        let local = vec![k("Bank", "me")];
        let remote = vec![k("Bank", "me")];
        let ids = vec!["r-new".into()];
        let p = pair(&local, &remote, &[(0, "r-old".into())], &ids);
        assert_eq!(p.pairs, vec![(0, 0)]);
    }
}
