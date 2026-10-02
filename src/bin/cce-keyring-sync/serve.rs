//! The daemon's socket: one-time codes for cce-secrets.
//!
//! The daemon holds the session's `op` authorization (daemon.rs), so it is
//! the one process that can ask 1Password for a code without raising an
//! Authorize dialog. cce-secrets asks here, one request per connection:
//!
//! ```text
//! otp <item-id>\n  →  otp <code> <seconds left>\n | none\n | err <text>\n
//! ```
//!
//! The socket is 0600 under `$XDG_RUNTIME_DIR/cce`, and only items the base
//! snapshot pairs are served — the mirror's own set, not whatever else the
//! account holds. The trade, stated plainly: a same-user process could
//! already read every mirrored password from the unlocked keyring; this
//! adds the current codes without a dialog. Never the seeds — `op item get
//! --otp` computes the code app-side (op.rs).

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::op::OnePassword;
use crate::{now_unix, State};

/// TOTP's near-universal period. A code with another period still comes
/// back right; only its countdown would be off.
const PERIOD: i64 = 30;

/// Where the daemon listens and cce-secrets connects. `None` without a
/// runtime dir — a session has one; nothing else should be serving.
pub fn socket_path() -> Option<PathBuf> {
    let dir = std::env::var("XDG_RUNTIME_DIR").ok().filter(|s| !s.is_empty())?;
    Some(PathBuf::from(dir).join("cce/keyring-sync.sock"))
}

pub async fn serve(state_path: PathBuf) {
    let Some(path) = socket_path() else {
        eprintln!("no XDG_RUNTIME_DIR; one-time codes are not served");
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // A previous daemon's socket file outlives it; bind would refuse.
    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("binding {}: {e}; one-time codes are not served", path.display());
            return;
        }
    };
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        // Its own task, so a slow reply holds no other connection. The
        // `op` call itself queues behind any in flight (op.rs, `run_as`):
        // two calls waiting on authorization would raise two dialogs.
        let state_path = state_path.clone();
        tokio::spawn(async move { handle(stream, &state_path).await });
    }
}

async fn handle(stream: UnixStream, state_path: &Path) {
    let (r, mut w) = stream.into_split();
    let mut line = String::new();
    let mut r = BufReader::new(r.take(256));
    match tokio::time::timeout(Duration::from_secs(5), r.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {}
        _ => return,
    }
    let reply = answer(line.trim(), state_path).await;
    let _ = w.write_all(reply.as_bytes()).await;
}

async fn answer(req: &str, state_path: &Path) -> String {
    let Some(id) = req.strip_prefix("otp ") else {
        return "err unknown request\n".into();
    };
    if !is_item_id(id) {
        return "err bad item id\n".into();
    }
    let state: State = std::fs::read_to_string(state_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if state.backend != "onepassword" || !state.entries.contains_key(id) {
        return "err not a mirrored item\n".into();
    }
    match OnePassword::new(&state.vault).otp(id).await {
        Ok(Some(code)) => format!("otp {code} {}\n", PERIOD - now_unix().rem_euclid(PERIOD)),
        Ok(None) => "none\n".into(),
        Err(e) => format!("err {}\n", e.replace('\n', " ")),
    }
}

/// 1Password ids are 26 lowercase base32 characters. Alphanumeric only is
/// what matters: the id lands on `op`'s argv, where a dash would read as a
/// flag.
fn is_item_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_bare_ids_reach_op() {
        assert!(is_item_id("v6ybyyfp6b2vnaqm3ar4z3kzqa"));
        assert!(!is_item_id(""));
        assert!(!is_item_id("--vault"));
        assert!(!is_item_id("abc def"));
        assert!(!is_item_id(&"a".repeat(65)));
    }

    #[tokio::test]
    async fn requests_outside_the_mirror_are_refused() {
        let dir = std::env::temp_dir().join(format!("cce-keyring-sync-serve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state_path = dir.join("state.json");
        std::fs::write(
            &state_path,
            r#"{"version":2,"last_run":0,"backend":"onepassword","vault":"Personal","entries":{}}"#,
        )
        .unwrap();
        assert_eq!(answer("otp aaaaaaaaaaaaaaaaaaaaaaaaaa", &state_path).await, "err not a mirrored item\n");
        assert_eq!(answer("otp -x", &state_path).await, "err bad item id\n");
        assert_eq!(answer("sync", &state_path).await, "err unknown request\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
