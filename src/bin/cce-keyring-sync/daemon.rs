//! `daemon` — the resident parent that keeps the `op` authorization alive.
//!
//! Phase 0 (KEYRING-SYNC.md) measured the rule this loop lives by: the
//! app's authorization is keyed to the calling process's parent and lapses
//! after ~10 idle minutes, but use extends it indefinitely. So this process
//! stays up for the session, ticks every [`TICK`], and every tick is one
//! `op item list` under its own pid. One Authorize dialog per login, then
//! none, as long as nothing (suspend, the app locking) opens a gap.
//!
//! A dialog nobody answers costs a 60-second hang and comes back as
//! `authorization prompt dismissed`; re-offering one every five minutes to an
//! empty chair is the annoyance the timer design was rejected for, so after a
//! dismissal the tick backs off (15 → 30 → 60 minutes) until something asks:
//! `SIGUSR1`, which cce-secrets sends from its Sync button and after a save.

use std::time::Duration;

use tokio::signal::unix::{signal, SignalKind};

use crate::op::{is_dismissed, OnePassword};
use crate::sync::sync_remote;
use crate::{now_unix, State};

/// Inside the ~10-minute idle window with margin.
pub const TICK: Duration = Duration::from_secs(5 * 60);
const BACKOFF: [Duration; 3] = [Duration::from_secs(15 * 60), Duration::from_secs(30 * 60), Duration::from_secs(60 * 60)];

pub async fn daemon(state_path: &std::path::Path) {
    let mut usr1 = signal(SignalKind::user_defined1()).expect("SIGUSR1 handler");
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut dismissed = 0usize;
    println!("cce-keyring-sync daemon: tick every {}s, SIGUSR1 syncs now", TICK.as_secs());

    loop {
        // Re-read every tick: adopt or a manual sync may have moved the base.
        let mut state: State = std::fs::read_to_string(state_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let wait = if state.backend != "onepassword" {
            eprintln!("{}: base is not 1Password's; idling until `adopt` runs", now_unix());
            TICK
        } else {
            let mut remote = OnePassword::new(&state.vault);
            match sync_remote(&mut remote, state_path, &mut state, false).await {
                Ok(_) => {
                    dismissed = 0;
                    TICK
                }
                Err(e) if is_dismissed(&e) => {
                    let w = BACKOFF[dismissed.min(BACKOFF.len() - 1)];
                    dismissed += 1;
                    eprintln!("authorization dialog unanswered; next try in {}m (or SIGUSR1)", w.as_secs() / 60);
                    w
                }
                Err(e) => {
                    eprintln!("sync: {e}");
                    TICK
                }
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = usr1.recv() => { dismissed = 0; }
            _ = term.recv() => { println!("cce-keyring-sync daemon: stopping"); return; }
        }
    }
}
