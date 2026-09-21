//! cce-keyring-sync — keep gnome-keyring and 1Password in step.
//!
//! See KEYRING-SYNC.md for the design and its measurements. gnome-keyring
//! stays the live store (what cce-secrets and cce-browser front over the
//! Secret Service); 1Password is the cross-machine interchange, reached
//! through the `op` CLI as a child process (op.rs). `adopt` pairs what both
//! sides already hold and seeds the base; `sync` is one three-way merge
//! pass (sync.rs); `daemon` is the resident loop the systemd unit runs
//! (daemon.rs) — resident because the CLI's authorization is keyed to the
//! calling process's parent and lapses when idle.
//!
//! Discipline kept from the kdbx era this replaced (2026-09-21):
//! - the state file stores keyed hashes of fields, never values; the hash
//!   key is itself a keyring item;
//! - attribute names match cce-secrets: label=Title, UserName, URL, Notes,
//!   plus op-item / op-vault (kdbx-uuid / kdbx-group linger on old items
//!   and are ignored);
//! - the merge never destroys a value: 1Password keeps item history on
//!   every edit, keyring deletions become Archive entries, and modification
//!   beats deletion.

mod adopt;
mod daemon;
mod op;
mod sync;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use secret_service::SecretService;
use serde::{Deserialize, Serialize};

pub(crate) const APP: &str = "cce-keyring-sync";

#[derive(Serialize, Deserialize, Default)]
pub(crate) struct State {
    pub version: u32,
    pub last_run: i64,
    /// Which interchange the base snapshot belongs to: "onepassword" once
    /// `adopt` has run. (The retired kdbx backend wrote "" and keyed
    /// `entries` by kdbx UUID; such a file is refused, not misread.)
    #[serde(default)]
    pub backend: String,
    /// 1Password only: the vault new entries are created in.
    #[serde(default)]
    pub vault: String,
    /// The last run's one-line outcome ("in sync", "synced: …", "failed: …"),
    /// for cce-secrets' status line — the daemon has no stdout anyone reads.
    #[serde(default)]
    pub last_result: String,
    /// Per entry id: the last-synced snapshot the merge runs against.
    pub entries: HashMap<String, EntryState>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct EntryState {
    /// Keyed blake3 over the canonical field concatenation — never values.
    pub h: String,
    pub keyring_modified: u64,
    /// 1Password's `updated_at` at the base, verbatim. Empty means unknown:
    /// the next sync fetches the entry regardless of the list timestamp.
    #[serde(default)]
    pub op_updated_at: String,
}

pub(crate) fn state_dir() -> PathBuf {
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

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A secret held as a keyring item under our own application attribute:
/// the state-file hash key lives this way, unlocked by PAM along with
/// everything else.
pub(crate) async fn keyring_get(
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

pub(crate) async fn keyring_put(
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

/// A keyring item's synced fields, snapshotted once per run.
#[derive(Clone)]
pub(crate) struct KrEntry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    /// The vault name (`op-vault`).
    pub group: String,
    pub modified: u64,
}

impl KrEntry {
    pub fn hash(&self, key: &[u8; 32]) -> String {
        let mut h = blake3::Hasher::new_keyed(key);
        for part in [&self.title, &self.username, &self.password, &self.url, &self.notes, &self.group] {
            h.update(part.as_bytes());
            h.update(&[0]);
        }
        h.finalize().to_hex().to_string()
    }
}

/// A crude cross-process lock: a one-shot `sync` must not interleave with
/// the daemon's tick. Advisory flock on a file in the state dir.
pub(crate) fn take_lock() -> Option<std::fs::File> {
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

pub(crate) fn journal_append(lines: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(state_dir().join("journal.log"))
    {
        let _ = f.write_all(lines.as_bytes());
    }
}

pub(crate) fn write_state(state_path: &Path, state: &State) {
    let _ = std::fs::create_dir_all(state_dir());
    let tmp = state_path.with_extension("json.tmp");
    if std::fs::write(&tmp, serde_json::to_vec_pretty(state).unwrap()).is_ok() {
        let _ = std::fs::rename(&tmp, state_path);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let vault_flag = args
        .iter()
        .position(|a| a == "--vault")
        .and_then(|i| args.get(i + 1))
        .cloned();
    // The subcommand: the first word that is neither a flag nor a flag's value.
    let mut skip_next = false;
    let mut cmd = None;
    for a in &args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if a == "--vault" {
            skip_next = true;
            continue;
        }
        if !a.starts_with("--") {
            cmd = Some(a.clone());
            break;
        }
    }
    let cmd = match cmd.as_deref() {
        Some(c @ ("sync" | "status" | "adopt" | "daemon")) => c.to_string(),
        _ => {
            eprintln!("usage: cce-keyring-sync sync   [--dry-run]                  (one merge pass; raises its own Authorize dialog)");
            eprintln!("       cce-keyring-sync daemon                              (resident; what cce-keyring-sync.service runs)");
            eprintln!("       cce-keyring-sync adopt  [--dry-run] [--vault <name>]  (pair the keyring with 1Password, seed the base)");
            eprintln!("       cce-keyring-sync status");
            std::process::exit(2);
        }
    };

    let state_path = state_dir().join("state.json");
    let mut state: State = std::fs::read_to_string(&state_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    match cmd.as_str() {
        "status" => {
            if state.backend == "onepassword" {
                println!("backend:   1Password (vault {})", if state.vault.is_empty() { "*" } else { &state.vault });
            } else {
                println!("backend:   none — run `cce-keyring-sync adopt --vault <name>`");
            }
            println!("state:     {} entries, last run {}", state.entries.len(), state.last_run);
            if !state.last_result.is_empty() {
                println!("last:      {}", state.last_result);
            }
        }
        "adopt" => adopt::adopt(&state_path, state, vault_flag.as_deref().unwrap_or(""), dry_run).await,
        "daemon" => daemon::daemon(&state_path).await,
        _ => {
            // A one-shot pass; the daemon is the usual caller, and the flock
            // keeps the two apart.
            let mut remote = op::OnePassword::new(&state.vault);
            if let Err(e) = sync::sync_remote(&mut remote, &state_path, &mut state, dry_run).await {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
}
