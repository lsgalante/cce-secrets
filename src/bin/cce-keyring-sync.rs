//! cce-keyring-sync — phase 1: one-way import, kdbx -> gnome-keyring.
//!
//! See KEYRING-SYNC.md for the full design. This phase makes cce-secrets
//! show the real entries: it reads the Dropbox kdbx (read-only — the file is
//! never written), creates or updates matching items in the default Secret
//! Service collection, and records a state snapshot that phase 2's three-way
//! merge will use as its base.
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

fn read_kdbx(path: &Path, password: &str) -> Result<Vec<KdbxEntry>, String> {
    // One read, then the file is closed: nothing holds a Dropbox-synced
    // file open across the parse.
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let key = DatabaseKey::new().with_password(password);
    let db = Database::open(&mut Cursor::new(bytes), key)
        .map_err(|e| format!("opening database: {e}"))?;

    // Entries in the recycle bin are deleted; importing them would resurrect
    // every password ever discarded.
    let recycle = db.recycle_bin().map(|g| g.id());

    let mut out = Vec::new();
    let mut skipped_recycled = 0usize;
    for entry in db.iter_all_entries() {
        if recycle.is_some() && Some(entry.parent().id()) == recycle {
            skipped_recycled += 1;
            continue;
        }
        let group = entry.parent().name.clone();
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
    Ok(out)
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
        Some("status") => "status",
        _ => {
            eprintln!("usage: cce-keyring-sync import [--dry-run] [--kdbx <path>]");
            eprintln!("       cce-keyring-sync status");
            eprintln!("(bidirectional sync and doctor arrive in phase 2 — see KEYRING-SYNC.md)");
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
        Ok(e) => e,
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
