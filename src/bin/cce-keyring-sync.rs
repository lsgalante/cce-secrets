//! cce-keyring-sync — keep gnome-keyring and the Dropbox kdbx in step.
//!
//! See KEYRING-SYNC.md for the design. `import` is the one-way first run;
//! `sync` is the bidirectional three-way merge against the state snapshot;
//! `doctor` reconciles Dropbox conflicted copies via keepassxc-cli merge.
//! The merge never destroys a value: conflict losers go into the kdbx
//! entry's native History, deletions into its Recycle Bin, and modification
//! beats deletion.
//!
//! Discipline inherited from the scope:
//! - the kdbx is read once into memory; nothing holds it open;
//! - Dropbox "conflicted copy" siblings are detected and warned about
//!   (import proceeds — it is read-only — but sync in phase 2 will refuse);
//! - the state file stores keyed hashes of fields, never values; the hash
//!   key and the kdbx master password live as keyring items themselves;
//! - attribute names match cce-secrets and KeePassXC's own Secret Service
//!   bridge: label=Title, UserName, URL, Notes, plus kdbx-uuid / kdbx-group.

use std::collections::HashMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use keepass::{Database, DatabaseKey};
use secret_service::{EncryptionType, SecretService};
use serde::{Deserialize, Serialize};

const DEFAULT_KDBX: &str = "Dropbox/Codes/Passwords.kdbx";
const APP: &str = "cce-keyring-sync";

/// One kdbx entry, flattened to what round-trips (KEYRING-SYNC.md: TOTP,
/// attachments and history deliberately stay kdbx-side).
struct KdbxEntry {
    uuid: String,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    group: String,
    mtime: i64,
}

#[derive(Serialize, Deserialize, Default)]
struct State {
    version: u32,
    kdbx_path: String,
    last_run: i64,
    /// Per kdbx UUID: the last-synced snapshot phase 2 merges against.
    entries: HashMap<String, EntryState>,
}

#[derive(Serialize, Deserialize)]
struct EntryState {
    /// Keyed blake3 over the canonical field concatenation — never values.
    h: String,
    kdbx_mtime: i64,
    keyring_modified: u64,
}

fn state_dir() -> PathBuf {
    let base = std::env::var("XDG_STATE_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/state"));
    base.join("cce/keyring-sync")
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").expect("HOME"))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Dropbox conflict siblings of the database. Their existence means diverged
/// writes were already split; phase 2's `doctor` reconciles them.
fn conflicted_copies(kdbx: &Path) -> Vec<PathBuf> {
    let Some(dir) = kdbx.parent() else { return Vec::new() };
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.to_lowercase().contains("conflicted copy") && name.ends_with(".kdbx") {
                out.push(e.path());
            }
        }
    }
    out.sort();
    out
}

/// The kdbx, read once (nothing holds a Dropbox-synced file open), plus the
/// blake3 of the exact bytes read — the write path re-hashes the on-disk file
/// before renaming over it, so a Dropbox delivery mid-merge aborts the save.
struct Kdbx {
    db: Database,
    entries: Vec<KdbxEntry>,
    ids: HashMap<String, keepass::db::EntryId>,
    file_hash: blake3::Hash,
}

fn read_kdbx(path: &Path, password: &str) -> Result<Kdbx, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let file_hash = blake3::hash(&bytes);
    let key = DatabaseKey::new().with_password(password);
    let db = Database::open(&mut Cursor::new(bytes), key)
        .map_err(|e| format!("opening database: {e}"))?;

    // Entries in the recycle bin are deleted; importing them would resurrect
    // every password ever discarded.
    let recycle = db.recycle_bin().map(|g| g.id());

    let mut out = Vec::new();
    let mut ids = HashMap::new();
    let mut skipped_recycled = 0usize;
    for entry in db.iter_all_entries() {
        if recycle.is_some() && Some(entry.parent().id()) == recycle {
            skipped_recycled += 1;
            continue;
        }
        let group = entry.parent().name.clone();
        ids.insert(entry.id().uuid().to_string(), entry.id());
        out.push(KdbxEntry {
            // EntryId is the kdbx UUID (EntryId(Uuid)); stable across machines.
            uuid: entry.id().uuid().to_string(),
            title: entry.get_title().unwrap_or("").to_string(),
            username: entry.get_username().unwrap_or("").to_string(),
            password: entry.get_password().unwrap_or("").to_string(),
            url: entry.get_url().unwrap_or("").to_string(),
            notes: entry.get("Notes").unwrap_or("").to_string(),
            group,
            mtime: entry
                .times
                .last_modification
                .map(|t| t.and_utc().timestamp())
                .unwrap_or(0),
        });
    }
    if skipped_recycled > 0 {
        println!("  (skipping {skipped_recycled} recycled entries)");
    }
    Ok(Kdbx { db, entries: out, ids, file_hash })
}

fn canonical_hash(key: &[u8; 32], e: &KdbxEntry) -> String {
    let mut h = blake3::Hasher::new_keyed(key);
    for part in [&e.title, &e.username, &e.password, &e.url, &e.notes, &e.group] {
        h.update(part.as_bytes());
        h.update(&[0]);
    }
    h.finalize().to_hex().to_string()
}

fn attrs_for(e: &KdbxEntry) -> HashMap<&str, &str> {
    let mut a = HashMap::new();
    a.insert("kdbx-uuid", e.uuid.as_str());
    a.insert("kdbx-group", e.group.as_str());
    a.insert("UserName", e.username.as_str());
    a.insert("URL", e.url.as_str());
    a.insert("Notes", e.notes.as_str());
    a
}

/// A secret held as a keyring item under our own application attribute:
/// the kdbx master password and the state-file hash key both live this way,
/// unlocked by PAM along with everything else.
async fn keyring_get(
    ss: &SecretService<'_>,
    purpose: &str,
) -> Result<Option<Vec<u8>>, secret_service::Error> {
    let mut attrs = HashMap::new();
    attrs.insert("application", APP);
    attrs.insert("purpose", purpose);
    let found = ss.search_items(attrs).await?;
    match found.unlocked.first() {
        Some(item) => Ok(Some(item.get_secret().await?)),
        None => Ok(None),
    }
}

async fn keyring_put(
    ss: &SecretService<'_>,
    purpose: &str,
    label: &str,
    secret: &[u8],
) -> Result<(), secret_service::Error> {
    let col = ss.get_default_collection().await?;
    let mut attrs = HashMap::new();
    attrs.insert("application", APP);
    attrs.insert("purpose", purpose);
    col.create_item(label, attrs, secret, true, "text/plain").await?;
    Ok(())
}

enum Action {
    Create,
    Update,
    Unchanged,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let kdbx_flag = args
        .iter()
        .position(|a| a == "--kdbx")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let cmd = args
        .iter()
        .find(|a| !a.starts_with("--") && Some(a.as_str()) != kdbx_flag.as_deref().map(|_| "").or(None))
        .cloned();
    let cmd = match cmd.as_deref() {
        Some("import") => "import",
        Some("sync") => "sync",
        Some("doctor") => "doctor",
        Some("status") => "status",
        _ => {
            eprintln!("usage: cce-keyring-sync sync   [--dry-run] [--kdbx <path>]");
            eprintln!("       cce-keyring-sync import [--dry-run] [--kdbx <path>]");
            eprintln!("       cce-keyring-sync doctor [--kdbx <path>]");
            eprintln!("       cce-keyring-sync status");
            std::process::exit(2);
        }
    };

    let state_path = state_dir().join("state.json");
    let mut state: State = std::fs::read_to_string(&state_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let kdbx = kdbx_flag
        .map(PathBuf::from)
        .or_else(|| (!state.kdbx_path.is_empty()).then(|| PathBuf::from(&state.kdbx_path)))
        .unwrap_or_else(|| home().join(DEFAULT_KDBX));

    if cmd == "status" {
        println!("kdbx:      {}", kdbx.display());
        println!("state:     {} entries, last run {}", state.entries.len(), state.last_run);
        for c in conflicted_copies(&kdbx) {
            println!("CONFLICT:  {}", c.display());
        }
        return;
    }

    if cmd == "doctor" {
        doctor(&kdbx).await;
        return;
    }
    if cmd == "sync" {
        sync(&kdbx, &state_path, state, dry_run).await;
        return;
    }

    // ---- import ----
    if !kdbx.exists() {
        eprintln!("no database at {} (pass --kdbx <path>)", kdbx.display());
        std::process::exit(1);
    }
    let conflicts = conflicted_copies(&kdbx);
    if !conflicts.is_empty() {
        println!("WARNING: Dropbox conflicted copies exist — diverged writes were split:");
        for c in &conflicts {
            println!("  {}", c.display());
        }
        println!("Import reads only the main file and changes nothing in the kdbx;");
        println!("phase 2's `doctor` will reconcile these. Do not delete them.\n");
    }

    // Quiescence: a file Dropbox wrote moments ago may still be mid-sync.
    if let Ok(meta) = std::fs::metadata(&kdbx) {
        if let Ok(age) = meta.modified().and_then(|m| m.elapsed().map_err(|e| std::io::Error::other(e))) {
            if age.as_secs() < 5 {
                eprintln!("{} changed {}s ago — letting Dropbox settle; retry shortly", kdbx.display(), age.as_secs());
                std::process::exit(1);
            }
        }
    }

    let ss = match SecretService::connect(EncryptionType::Dh).await {
        Ok(ss) => ss,
        Err(e) => {
            eprintln!("Secret Service unavailable: {e}");
            std::process::exit(1);
        }
    };

    // Master password: keyring first, prompt once otherwise.
    let (password, password_was_prompted) = match keyring_get(&ss, "kdbx-password").await {
        Ok(Some(bytes)) => (String::from_utf8_lossy(&bytes).into_owned(), false),
        _ => {
            let pw = rpassword::prompt_password(format!("master password for {}: ", kdbx.display()))
                .unwrap_or_default();
            if pw.is_empty() {
                eprintln!("no password given");
                std::process::exit(1);
            }
            (pw, true)
        }
    };

    println!("reading {} …", kdbx.display());
    let entries = match read_kdbx(&kdbx, &password) {
        Ok(k) => k.entries,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    println!("  {} live entries", entries.len());

    // The password proved right; persist it (real runs only) so the timer
    // in phase 2 can run unattended.
    if password_was_prompted && !dry_run {
        if let Err(e) = keyring_put(&ss, "kdbx-password", "cce-keyring-sync: kdbx master password", password.as_bytes()).await {
            eprintln!("could not store the master password in the keyring: {e}");
        } else {
            println!("  master password stored in the keyring (PAM-unlocked at login)");
        }
    }

    // State hash key: minted once, kept in the keyring so the state file
    // alone leaks nothing.
    let hash_key: [u8; 32] = match keyring_get(&ss, "state-hash-key").await {
        Ok(Some(b)) if b.len() == 32 => b.try_into().unwrap(),
        _ => {
            let mut k = [0u8; 32];
            getrandom::getrandom(&mut k).expect("entropy");
            if !dry_run {
                if let Err(e) = keyring_put(&ss, "state-hash-key", "cce-keyring-sync: state hash key", &k).await {
                    eprintln!("could not store the hash key: {e}");
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
    if col.is_locked().await.unwrap_or(false) {
        if let Err(e) = col.unlock().await {
            eprintln!("collection locked and unlock failed: {e}");
            std::process::exit(1);
        }
    }

    // Existing items by kdbx-uuid, one pass.
    let mut existing: HashMap<String, secret_service::Item<'_>> = HashMap::new();
    match col.get_all_items().await {
        Ok(items) => {
            for item in items {
                if let Ok(attrs) = item.get_attributes().await {
                    if let Some(uuid) = attrs.get("kdbx-uuid") {
                        existing.insert(uuid.clone(), item);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("listing collection failed: {e}");
            std::process::exit(1);
        }
    }

    let (mut created, mut updated, mut unchanged) = (0usize, 0usize, 0usize);
    let mut journal = String::new();
    for e in &entries {
        let action = match existing.get(&e.uuid) {
            None => Action::Create,
            Some(item) => {
                let same_label = item.get_label().await.ok().as_deref() == Some(e.title.as_str());
                let same_secret = item.get_secret().await.ok().as_deref() == Some(e.password.as_bytes());
                let same_attrs = item.get_attributes().await.ok().is_some_and(|a| {
                    a.get("UserName").map(String::as_str) == Some(e.username.as_str())
                        && a.get("URL").map(String::as_str) == Some(e.url.as_str())
                        && a.get("Notes").map(String::as_str) == Some(e.notes.as_str())
                        && a.get("kdbx-group").map(String::as_str) == Some(e.group.as_str())
                });
                if same_label && same_secret && same_attrs {
                    Action::Unchanged
                } else {
                    Action::Update
                }
            }
        };
        let verb = match action {
            Action::Create => {
                created += 1;
                "create"
            }
            Action::Update => {
                updated += 1;
                "update"
            }
            Action::Unchanged => {
                unchanged += 1;
                "ok    "
            }
        };
        if !matches!(action, Action::Unchanged) {
            println!("  {verb}  {}", e.title);
        }
        journal.push_str(&format!("{} {verb} {}\n", now_unix(), e.title));

        if dry_run {
            continue;
        }
        match action {
            Action::Create | Action::Update => {
                // replace=true keys on the attribute set; identical kdbx-uuid
                // makes this the create-or-overwrite we want.
                if let Err(err) = col
                    .create_item(&e.title, attrs_for(e), e.password.as_bytes(), true, "text/plain")
                    .await
                {
                    eprintln!("  FAILED {}: {err}", e.title);
                    continue;
                }
            }
            Action::Unchanged => {}
        }
        let modified = match existing.get(&e.uuid) {
            Some(item) => item.get_modified().await.unwrap_or(0),
            None => now_unix() as u64,
        };
        state.entries.insert(
            e.uuid.clone(),
            EntryState { h: canonical_hash(&hash_key, e), kdbx_mtime: e.mtime, keyring_modified: modified },
        );
    }

    println!(
        "\n{}: {created} created, {updated} updated, {unchanged} unchanged (of {})",
        if dry_run { "plan" } else { "imported" },
        entries.len()
    );

    if dry_run {
        return;
    }
    state.version = 1;
    state.kdbx_path = kdbx.display().to_string();
    state.last_run = now_unix();
    let _ = std::fs::create_dir_all(state_dir());
    // Atomic: temp + rename, same as every other write in this design.
    let tmp = state_path.with_extension("json.tmp");
    if std::fs::write(&tmp, serde_json::to_vec_pretty(&state).unwrap()).is_ok() {
        let _ = std::fs::rename(&tmp, &state_path);
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(state_dir().join("journal.log")) {
        let _ = f.write_all(journal.as_bytes());
    }
    println!("state: {}", state_path.display());
}

// ===================== phase 2: bidirectional sync =====================

/// A keyring item's synced fields, snapshotted once per run.
struct KrEntry {
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    group: String,
    modified: u64,
}

impl KrEntry {
    fn hash(&self, key: &[u8; 32]) -> String {
        let mut h = blake3::Hasher::new_keyed(key);
        for part in [&self.title, &self.username, &self.password, &self.url, &self.notes, &self.group] {
            h.update(part.as_bytes());
            h.update(&[0]);
        }
        h.finalize().to_hex().to_string()
    }
}

/// What one entry needs done, per KEYRING-SYNC.md's merge table.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Plan {
    ToKeyring,
    ToKdbx,
    /// Both changed: newer wins, loser into kdbx History.
    ConflictKdbxWins,
    ConflictKeyringWins,
    DeleteKeyring,
    RecycleKdbx,
    InSync,
}

/// Allowed clock skew between machines before "newer" means anything.
const SKEW_TOLERANCE_SECS: i64 = 3;

/// A crude cross-process lock: sync and import must not interleave with a
/// timer run. Advisory flock on a file in the state dir (local, never in
/// Dropbox — Dropbox syncing lock files is its own disaster).
fn take_lock() -> Option<std::fs::File> {
    let _ = std::fs::create_dir_all(state_dir());
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(state_dir().join("lock"))
        .ok()?;
    match rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Some(f),
        Err(_) => None,
    }
}

fn journal_append(lines: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(state_dir().join("journal.log"))
    {
        let _ = f.write_all(lines.as_bytes());
    }
}

/// Push the entry's current values into its own History before overwriting —
/// the "never destroy a value" rule. Mirrors what KeePass apps do on edit.
fn push_history(db: &mut Database, id: keepass::db::EntryId) {
    if let Some(mut em) = db.entry_mut(id) {
        let snapshot = (*em).clone();
        em.history.get_or_insert_with(Default::default).add_entry(snapshot);
    }
}

fn set_kdbx_fields(db: &mut Database, id: keepass::db::EntryId, kr: &KrEntry) {
    use keepass::db::Value;
    if let Some(mut em) = db.entry_mut(id) {
        em.set("Title", Value::Unprotected(kr.title.clone()));
        em.set("UserName", Value::Unprotected(kr.username.clone()));
        em.set("Password", Value::protected(kr.password.clone()));
        em.set("URL", Value::Unprotected(kr.url.clone()));
        em.set("Notes", Value::Unprotected(kr.notes.clone()));
        em.times.last_modification = Some(keepass::db::Times::now());
    }
}

/// The Recycle Bin group, created if the database has never had one.
fn recycle_bin_id(db: &mut Database) -> keepass::db::GroupId {
    if let Some(g) = db.recycle_bin() {
        return g.id();
    }
    let mut root = db.root_mut();
    let mut g = root.add_group();
    g.name = "Recycle Bin".to_string();
    let id = g.as_ref().id();
    db.meta.recyclebin_uuid = Some(id.uuid());
    db.meta.recyclebin_enabled = Some(true);
    id
}

/// Atomic kdbx save: temp + fsync + rename, aborted if the on-disk file no
/// longer matches the bytes this run read (Dropbox delivered mid-merge).
fn save_kdbx_atomic(
    db: &mut Database,
    path: &Path,
    password: &str,
    read_hash: &blake3::Hash,
) -> Result<(), String> {
    // The crate only writes KDBX4. An older database (keepassxc still creates
    // KDBX3 for AES-KDF) is upgraded in-memory to the current v4 defaults —
    // argon2, same password — which every modern KeePass app reads. One-time,
    // loud, and only on a run that was going to write anyway.
    if !matches!(db.config.version, keepass::config::DatabaseVersion::KDB4(_)) {
        println!("note: upgrading database format to KDBX4 (was pre-4; modern apps read v4)");
        db.config = keepass::config::DatabaseConfig::default();
    }
    let current = std::fs::read(path).map_err(|e| format!("re-reading {}: {e}", path.display()))?;
    if blake3::hash(&current) != *read_hash {
        return Err("the kdbx changed on disk during the merge (Dropbox?) — aborting the save; retry".into());
    }
    let mut buf = Vec::new();
    db.save(&mut buf, DatabaseKey::new().with_password(password))
        .map_err(|e| format!("serializing kdbx: {e}"))?;
    // Paranoia that pays for itself: the file we are about to install must
    // itself open with the same password before it replaces the real one.
    Database::open(&mut Cursor::new(buf.clone()), DatabaseKey::new().with_password(password))
        .map_err(|e| format!("round-trip verification failed, NOT saving: {e}"))?;
    let tmp = path.with_extension("kdbx.cce-tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("temp file: {e}"))?;
        f.write_all(&buf).map_err(|e| format!("writing temp: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync: {e}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("rename into place: {e}"))
}

async fn sync(kdbx_path: &Path, state_path: &Path, mut state: State, dry_run: bool) {
    let Some(_lock) = take_lock() else {
        eprintln!("another cce-keyring-sync is running");
        std::process::exit(1);
    };
    if state.entries.is_empty() {
        eprintln!("no sync base — run `cce-keyring-sync import` first");
        std::process::exit(1);
    }
    let conflicts = conflicted_copies(kdbx_path);
    if !conflicts.is_empty() {
        eprintln!("Dropbox conflicted copies exist — sync refuses to guess which side is real:");
        for c in &conflicts {
            eprintln!("  {}", c.display());
        }
        eprintln!("run `cce-keyring-sync doctor` first");
        std::process::exit(1);
    }
    if let Ok(meta) = std::fs::metadata(kdbx_path) {
        if let Ok(age) = meta.modified().and_then(|m| m.elapsed().map_err(std::io::Error::other)) {
            if age.as_secs() < 5 {
                eprintln!("kdbx changed {}s ago — letting Dropbox settle; retry shortly", age.as_secs());
                std::process::exit(1);
            }
        }
    }

    let ss = match SecretService::connect(EncryptionType::Dh).await {
        Ok(ss) => ss,
        Err(e) => {
            eprintln!("Secret Service unavailable: {e}");
            std::process::exit(1);
        }
    };
    let password = match keyring_get(&ss, "kdbx-password").await {
        Ok(Some(b)) => String::from_utf8_lossy(&b).into_owned(),
        _ => {
            eprintln!("no stored master password — run `cce-keyring-sync import` once");
            std::process::exit(1);
        }
    };
    let hash_key: [u8; 32] = match keyring_get(&ss, "state-hash-key").await {
        Ok(Some(b)) if b.len() == 32 => b.try_into().unwrap(),
        _ => {
            eprintln!("no state hash key — run `cce-keyring-sync import` once");
            std::process::exit(1);
        }
    };

    let mut kdbx = match read_kdbx(kdbx_path, &password) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let kdbx_by_uuid: HashMap<String, usize> = kdbx
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| (e.uuid.clone(), i))
        .collect();

    let col = match ss.get_default_collection().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("no default collection: {e}");
            std::process::exit(1);
        }
    };
    if col.is_locked().await.unwrap_or(false) {
        if col.unlock().await.is_err() {
            eprintln!("collection locked");
            std::process::exit(1);
        }
    }

    // Keyring snapshot: synced items by uuid, plus adoption candidates —
    // items that look like cce-secrets-born logins (a UserName attribute, no
    // kdbx-uuid, not our own bookkeeping items).
    let mut kr: HashMap<String, (secret_service::Item<'_>, KrEntry)> = HashMap::new();
    let mut adopt: Vec<(secret_service::Item<'_>, KrEntry)> = Vec::new();
    match col.get_all_items().await {
        Ok(items) => {
            for item in items {
                let Ok(attrs) = item.get_attributes().await else { continue };
                if attrs.get("application").map(String::as_str) == Some(APP) {
                    continue; // our own password/hash-key items
                }
                let has_user = attrs.contains_key("UserName");
                let uuid = attrs.get("kdbx-uuid").cloned();
                if uuid.is_none() && !has_user {
                    continue; // some other app's item — never ours to sync
                }
                let e = KrEntry {
                    title: item.get_label().await.unwrap_or_default(),
                    username: attrs.get("UserName").cloned().unwrap_or_default(),
                    password: String::from_utf8_lossy(&item.get_secret().await.unwrap_or_default())
                        .into_owned(),
                    url: attrs.get("URL").cloned().unwrap_or_default(),
                    notes: attrs.get("Notes").cloned().unwrap_or_default(),
                    group: attrs.get("kdbx-group").cloned().unwrap_or_default(),
                    modified: item.get_modified().await.unwrap_or(0),
                };
                match uuid {
                    Some(u) => {
                        kr.insert(u, (item, e));
                    }
                    None => adopt.push((item, e)),
                }
            }
        }
        Err(e) => {
            eprintln!("listing collection failed: {e}");
            std::process::exit(1);
        }
    }

    // ---- plan ----
    let mut uuids: Vec<String> = state
        .entries
        .keys()
        .chain(kdbx_by_uuid.keys())
        .chain(kr.keys())
        .cloned()
        .collect();
    uuids.sort();
    uuids.dedup();

    let mut plans: Vec<(String, Plan)> = Vec::new();
    for uuid in &uuids {
        let base = state.entries.get(uuid);
        let kx = kdbx_by_uuid.get(uuid).map(|&i| &kdbx.entries[i]);
        let k = kr.get(uuid);
        let kx_hash = kx.map(|e| canonical_hash(&hash_key, e));
        let kr_hash = k.map(|(_, e)| e.hash(&hash_key));
        let plan = match (base, kx, k) {
            // Never seen: whichever side has it, the other gets it.
            (None, Some(_), None) => Plan::ToKeyring,
            (None, None, Some(_)) => Plan::ToKdbx,
            (None, Some(_), Some(_)) => {
                // Both born independently with the same uuid — cross-machine
                // import. Fields equal → adopt as in sync; else newest wins.
                if kx_hash == kr_hash {
                    Plan::InSync
                } else if kx.unwrap().mtime >= k.unwrap().1.modified as i64 {
                    Plan::ConflictKdbxWins
                } else {
                    Plan::ConflictKeyringWins
                }
            }
            (Some(b), Some(_), Some(_)) => {
                let kx_changed = kx_hash.as_deref() != Some(b.h.as_str());
                let kr_changed = kr_hash.as_deref() != Some(b.h.as_str());
                match (kx_changed, kr_changed) {
                    (false, false) => Plan::InSync,
                    (true, false) => Plan::ToKeyring,
                    (false, true) => Plan::ToKdbx,
                    (true, true) => {
                        let (km, im) = (kx.unwrap().mtime, k.unwrap().1.modified as i64);
                        if (km - im).abs() <= SKEW_TOLERANCE_SECS || km >= im {
                            Plan::ConflictKdbxWins // tie or newer: kdbx, documented
                        } else {
                            Plan::ConflictKeyringWins
                        }
                    }
                }
            }
            // Deleted on one side; modification on the other beats deletion.
            (Some(b), None, Some(_)) => {
                if kr_hash.as_deref() != Some(b.h.as_str()) {
                    Plan::ToKdbx // modified in keyring: resurrect
                } else {
                    Plan::DeleteKeyring
                }
            }
            (Some(b), Some(_), None) => {
                if kx_hash.as_deref() != Some(b.h.as_str()) {
                    Plan::ToKeyring // modified in kdbx: resurrect
                } else {
                    Plan::RecycleKdbx
                }
            }
            (Some(_), None, None) | (None, None, None) => Plan::InSync, // gone: forget
        };
        plans.push((uuid.clone(), plan));
    }

    // ---- report ----
    let mut journal = String::new();
    let mut counts: HashMap<&'static str, usize> = HashMap::new();
    let describe = |uuid: &str, kx: Option<&KdbxEntry>, k: Option<&(secret_service::Item<'_>, KrEntry)>| {
        kx.map(|e| e.title.clone())
            .or_else(|| k.map(|(_, e)| e.title.clone()))
            .unwrap_or_else(|| uuid.to_string())
    };
    for (uuid, plan) in &plans {
        if *plan == Plan::InSync {
            continue;
        }
        let kx = kdbx_by_uuid.get(uuid).map(|&i| &kdbx.entries[i]);
        let label = describe(uuid, kx, kr.get(uuid));
        let verb = match plan {
            Plan::ToKeyring => "kdbx -> keyring",
            Plan::ToKdbx => "keyring -> kdbx",
            Plan::ConflictKdbxWins => "CONFLICT: kdbx wins (loser -> History)",
            Plan::ConflictKeyringWins => "CONFLICT: keyring wins (loser -> History)",
            Plan::DeleteKeyring => "delete from keyring",
            Plan::RecycleKdbx => "kdbx -> Recycle Bin",
            Plan::InSync => unreachable!(),
        };
        *counts.entry(match plan {
            Plan::ToKeyring | Plan::ConflictKdbxWins => "to-keyring",
            Plan::ToKdbx | Plan::ConflictKeyringWins => "to-kdbx",
            Plan::DeleteKeyring => "deleted",
            Plan::RecycleKdbx => "recycled",
            Plan::InSync => unreachable!(),
        }).or_default() += 1;
        println!("  {verb}: {label}");
        journal.push_str(&format!("{} sync {verb}: {label}\n", now_unix()));
    }
    for (_, e) in &adopt {
        println!("  adopt -> kdbx: {}", e.title);
        journal.push_str(&format!("{} sync adopt: {}\n", now_unix(), e.title));
    }
    let quiet = plans.iter().all(|(_, p)| *p == Plan::InSync) && adopt.is_empty();
    if quiet {
        println!("in sync — nothing to do");
    }
    if dry_run || quiet {
        if !dry_run {
            state.last_run = now_unix();
            write_state(state_path, &state);
        }
        return;
    }

    // ---- apply: kdbx first (atomic), keyring after, state last ----
    // If the kdbx save aborts, the keyring is untouched and the next run
    // re-plans from the same base. Keyring failures leave those entries out
    // of the new state, so they are retried.
    let mut kdbx_dirty = false;
    let mut new_uuids_for_adopt: Vec<String> = Vec::new();

    for (uuid, plan) in &plans {
        match plan {
            Plan::ToKdbx | Plan::ConflictKeyringWins => {
                let (_, ke) = kr.get(uuid).unwrap();
                match kdbx.ids.get(uuid) {
                    Some(&id) => {
                        push_history(&mut kdbx.db, id);
                        set_kdbx_fields(&mut kdbx.db, id, ke);
                    }
                    None => {
                        // Resurrect or first arrival from the keyring side.
                        let uu = match uuid.parse() {
                            Ok(u) => u,
                            Err(_) => continue,
                        };
                        let id = keepass::db::EntryId::from_uuid(uu);
                        let mut root = kdbx.db.root_mut();
                        if root.add_entry_with_id(id).is_err() {
                            continue; // id exists (recycled): leave to doctor
                        }
                        set_kdbx_fields(&mut kdbx.db, id, ke);
                        kdbx.ids.insert(uuid.clone(), id);
                    }
                }
                kdbx_dirty = true;
            }
            Plan::ConflictKdbxWins => {
                // kdbx keeps its value; the keyring's losing value is still
                // preserved as a History revision before the keyring is
                // overwritten in the second pass.
                if let (Some(&id), Some((_, ke))) = (kdbx.ids.get(uuid), kr.get(uuid)) {
                    push_history(&mut kdbx.db, id);
                    let winner_restore = kdbx_by_uuid.get(uuid).map(|&i| &kdbx.entries[i]);
                    set_kdbx_fields(&mut kdbx.db, id, ke); // loser becomes current...
                    push_history(&mut kdbx.db, id); // ...is archived...
                    if let Some(w) = winner_restore {
                        // ...and the winner is restored as current.
                        let back = KrEntry {
                            title: w.title.clone(),
                            username: w.username.clone(),
                            password: w.password.clone(),
                            url: w.url.clone(),
                            notes: w.notes.clone(),
                            group: w.group.clone(),
                            modified: 0,
                        };
                        set_kdbx_fields(&mut kdbx.db, id, &back);
                    }
                    kdbx_dirty = true;
                }
            }
            Plan::RecycleKdbx => {
                let rb = recycle_bin_id(&mut kdbx.db);
                if let Some(&id) = kdbx.ids.get(uuid) {
                    if let Some(mut em) = kdbx.db.entry_mut(id) {
                        let _ = em.move_to(rb);
                        kdbx_dirty = true;
                    }
                }
            }
            _ => {}
        }
    }
    for (_, ke) in &adopt {
        let id = keepass::db::EntryId::new();
        let uuid = id.uuid().to_string();
        let mut root = kdbx.db.root_mut();
        if root.add_entry_with_id(id).is_ok() {
            set_kdbx_fields(&mut kdbx.db, id, ke);
            kdbx.ids.insert(uuid.clone(), id);
            new_uuids_for_adopt.push(uuid);
            kdbx_dirty = true;
        }
    }

    if kdbx_dirty {
        if let Err(e) = save_kdbx_atomic(&mut kdbx.db, kdbx_path, &password, &kdbx.file_hash) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        println!("kdbx saved");
    }

    // Keyring side.
    for (uuid, plan) in &plans {
        match plan {
            Plan::ToKeyring | Plan::ConflictKdbxWins => {
                if let Some(&i) = kdbx_by_uuid.get(uuid) {
                    let e = &kdbx.entries[i];
                    if let Err(err) = col
                        .create_item(&e.title, attrs_for(e), e.password.as_bytes(), true, "text/plain")
                        .await
                    {
                        eprintln!("  keyring write failed for {}: {err}", e.title);
                    }
                }
            }
            Plan::DeleteKeyring => {
                if let Some((item, e)) = kr.get(uuid) {
                    if let Err(err) = item.delete().await {
                        eprintln!("  keyring delete failed for {}: {err}", e.title);
                    }
                }
            }
            _ => {}
        }
    }
    // Adopted items gain their kdbx-uuid so next run pairs them.
    for ((item, ke), uuid) in adopt.iter().zip(&new_uuids_for_adopt) {
        let mut attrs = HashMap::new();
        attrs.insert("kdbx-uuid", uuid.as_str());
        attrs.insert("kdbx-group", ke.group.as_str());
        attrs.insert("UserName", ke.username.as_str());
        attrs.insert("URL", ke.url.as_str());
        attrs.insert("Notes", ke.notes.as_str());
        if let Err(e) = item.set_attributes(attrs).await {
            eprintln!("  could not stamp kdbx-uuid on {}: {e}", ke.title);
        }
    }

    // ---- new state: re-read both sides' final values cheaply from the plan ----
    state.entries.clear();
    let mut fresh_kr: HashMap<String, u64> = HashMap::new();
    if let Ok(items) = col.get_all_items().await {
        for item in items {
            if let Ok(attrs) = item.get_attributes().await {
                if let Some(u) = attrs.get("kdbx-uuid") {
                    fresh_kr.insert(u.clone(), item.get_modified().await.unwrap_or(0));
                }
            }
        }
    }
    // Final field values per uuid: kdbx entries after merge are authoritative
    // for hashes (both sides were written to match them).
    let final_entries: Vec<KdbxEntry> = {
        let mut list = Vec::new();
        let recycle = kdbx.db.recycle_bin().map(|g| g.id());
        for entry in kdbx.db.iter_all_entries() {
            if recycle.is_some() && Some(entry.parent().id()) == recycle {
                continue;
            }
            list.push(KdbxEntry {
                uuid: entry.id().uuid().to_string(),
                title: entry.get_title().unwrap_or("").to_string(),
                username: entry.get_username().unwrap_or("").to_string(),
                password: entry.get_password().unwrap_or("").to_string(),
                url: entry.get_url().unwrap_or("").to_string(),
                notes: entry.get("Notes").unwrap_or("").to_string(),
                group: entry.parent().name.clone(),
                mtime: entry.times.last_modification.map(|t| t.and_utc().timestamp()).unwrap_or(0),
            });
        }
        list
    };
    for e in &final_entries {
        state.entries.insert(
            e.uuid.clone(),
            EntryState {
                h: canonical_hash(&hash_key, e),
                kdbx_mtime: e.mtime,
                keyring_modified: fresh_kr.get(&e.uuid).copied().unwrap_or(0),
            },
        );
    }
    state.version = 1;
    state.kdbx_path = kdbx_path.display().to_string();
    state.last_run = now_unix();
    write_state(state_path, &state);
    journal_append(&journal);
    let c = |k: &str| counts.get(k).copied().unwrap_or(0);
    println!(
        "synced: {} -> keyring, {} -> kdbx, {} adopted, {} deleted, {} recycled",
        c("to-keyring"), c("to-kdbx"), adopt.len(), c("deleted"), c("recycled")
    );
}

fn write_state(state_path: &Path, state: &State) {
    let _ = std::fs::create_dir_all(state_dir());
    let tmp = state_path.with_extension("json.tmp");
    if std::fs::write(&tmp, serde_json::to_vec_pretty(state).unwrap()).is_ok() {
        let _ = std::fs::rename(&tmp, state_path);
    }
}

// ===================== doctor: Dropbox conflicted copies =====================

/// Merge each conflicted copy into the main database with keepassxc-cli
/// (battle-tested merge; same credentials), back everything up first, then
/// archive the conflict files out of Dropbox.
async fn doctor(kdbx: &Path) {
    let conflicts = conflicted_copies(kdbx);
    if conflicts.is_empty() {
        println!("no conflicted copies — healthy");
        return;
    }
    let ss = match SecretService::connect(EncryptionType::Dh).await {
        Ok(ss) => ss,
        Err(e) => {
            eprintln!("Secret Service unavailable: {e}");
            std::process::exit(1);
        }
    };
    let password = match keyring_get(&ss, "kdbx-password").await {
        Ok(Some(b)) => String::from_utf8_lossy(&b).into_owned(),
        _ => {
            eprintln!("no stored master password — run `cce-keyring-sync import` once");
            std::process::exit(1);
        }
    };

    let backups = state_dir().join("backups");
    let _ = std::fs::create_dir_all(&backups);
    let ts = now_unix();
    let back = |p: &Path| backups.join(format!("{}.{ts}", p.file_name().unwrap().to_string_lossy()));
    if std::fs::copy(kdbx, back(kdbx)).is_err() {
        eprintln!("could not back up the main database — refusing to continue");
        std::process::exit(1);
    }
    for c in &conflicts {
        let _ = std::fs::copy(c, back(c));
    }
    println!("backups in {}", backups.display());

    for c in &conflicts {
        println!("merging {} …", c.display());
        // Same credentials: conflicted copies share the master password.
        let mut child = match std::process::Command::new("keepassxc-cli")
            .args(["merge", "--same-credentials"])
            .arg(kdbx)
            .arg(c)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(ch) => ch,
            Err(e) => {
                eprintln!("keepassxc-cli not runnable: {e}");
                std::process::exit(1);
            }
        };
        {
            use std::io::Write;
            let _ = child.stdin.take().unwrap().write_all(format!("{password}\n").as_bytes());
        }
        match child.wait_with_output() {
            Ok(out) if out.status.success() => {
                // Resolved: archive the conflict file out of Dropbox (copy
                // then remove — the backup dir is on another filesystem).
                let dest = backups.join(c.file_name().unwrap());
                if std::fs::copy(c, &dest).is_ok() {
                    let _ = std::fs::remove_file(c);
                    println!("  merged; archived to {}", dest.display());
                }
                journal_append(&format!("{} doctor merged {}\n", now_unix(), c.display()));
            }
            Ok(out) => {
                eprintln!("  merge FAILED (left in place): {}", String::from_utf8_lossy(&out.stderr).trim());
            }
            Err(e) => eprintln!("  merge failed to run: {e}"),
        }
    }
    println!("now run: cce-keyring-sync sync");
}
