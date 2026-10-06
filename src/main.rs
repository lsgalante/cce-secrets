use secret_service::{EncryptionType, SecretService};
use wayland_client::QueueHandle;

use cce_ui::engine::{Application, EngineState, LogicalPosition, LogicalSize, WindowSettings};
use cce_ui::widget::{
    Bounds, Button, ElementState, Key, KeyEvent, MouseButton, MouseScrollDelta, NamedKey,
    ScrollMotion, ScrollbarActivity, TextBox, WidgetHost, LINE_PX,
};

const LIST_W: f32 = 280.0;
const ROW_H: f32 = 44.0;
const STATUS_H: f32 = 30.0;
const BTN_W: f32 = 90.0;
const CLIPBOARD_CLEAR_SECS: u64 = 30;

/// Entry fields written back as Secret Service attributes (cce-keyring-sync
/// mirrors them to 1Password's username / url / notes; Title is the label).
const EDIT_ATTRS: [&str; 3] = ["UserName", "URL", "Notes"];

/// One Secret Service item, sans secret: the secret itself is fetched on
/// demand by object path (reveal/copy) and never held in the list.
#[derive(Clone, Debug)]
struct EntryData {
    path: String,
    label: String,
    collection: String,
    attrs: Vec<(String, String)>,
}

impl EntryData {
    /// The dim second line of a list row: a username-ish attribute if present.
    fn hint(&self) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("username") || k.eq_ignore_ascii_case("user"))
            .or_else(|| self.attrs.first())
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }

    fn attr(&self, key: &str) -> &str {
        self.attrs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Purpose {
    Copy,
    Reveal,
}

#[derive(Clone)]
enum Cmd {
    Reload,
    /// Ask cce-keyring-sync for a pass and reload — the resident daemon
    /// when it runs, the one-shot binary otherwise (see `run_sync`).
    Sync,
    GetSecret { path: String, purpose: Purpose },
    CreateItem { label: String, attrs: Vec<(String, String)>, secret: String },
    UpdateItem { path: String, label: String, attrs: Vec<(String, String)>, secret: Option<String> },
    DeleteItem { path: String },
}

/// The sync daemon's answer to a one-time code request.
#[derive(Clone, Debug, PartialEq)]
enum OtpReply {
    /// The code and the seconds it has left.
    Code(String, u64),
    /// The item has no one-time password field.
    Absent,
    Failed(String),
}

/// The selected entry's one-time code, as far as the UI knows it.
enum Otp {
    /// Asked; nothing to show yet.
    Pending,
    /// `refreshing`: expired and re-asked — the old code stays up meanwhile,
    /// at 0 s, rather than blinking out for the length of an `op` call.
    Code { code: String, until: std::time::Instant, refreshing: bool },
    /// Reported on the status line; not re-asked until the selection moves.
    Failed,
}

#[derive(Clone, Debug)]
enum AppMessage {
    Loaded(Vec<EntryData>),
    Status(String, bool),
    /// A transient progress line ("Loading entries…"): shown unless a sync
    /// is in flight, and never the end of one.
    Progress(String),
    Revealed { path: String, secret: String },
    SelectPath(String),
    RefreshClicked,
    SyncClicked,
    RevealClicked,
    CopyClicked,
    CopyOtpClicked,
    Otp { path: String, reply: OtpReply },
    NewClicked,
    EditClicked,
    DeleteClicked,
    SaveClicked,
    CancelClicked,
}

/// What the detail pane shows: the read-only entry view, or the entry form
/// (`path: None` = creating a new entry).
enum Mode {
    Browse,
    Edit { path: Option<String> },
}

/// cce-keyring-sync's state file: `last_run` (unix seconds) and the last
/// run's one-line outcome. The daemon's only channel back to this UI.
fn sync_state_path() -> std::path::PathBuf {
    cce_ui::config::cce_state_dir().join("keyring-sync/state.json")
}

fn read_sync_state() -> Option<(i64, String)> {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(sync_state_path()).ok()?).ok()?;
    let last_run = v.get("last_run")?.as_i64()?;
    let last_result = v.get("last_result").and_then(|r| r.as_str()).unwrap_or("").to_string();
    Some((last_run, last_result))
}

/// Ask the resident daemon for a pass now. Its `op` authorization is the
/// live one (KEYRING-SYNC.md, phase 0), so this raises no dialog; a
/// one-shot `cce-keyring-sync sync` from here would. Fire-and-forget: a
/// save does not wait for the mirror. False when no daemon is running.
async fn poke_sync_daemon() -> bool {
    let active = tokio::process::Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", "cce-keyring-sync.service"])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    if !active {
        return false;
    }
    tokio::process::Command::new("systemctl")
        .args(["--user", "kill", "-s", "SIGUSR1", "cce-keyring-sync.service"])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The Sync button. With the daemon up: poke it and wait for its state
/// file to record a new run, then show that run's outcome. Without it: the
/// one-shot binary, whose summary line ("synced: …", "in sync") or
/// refusal text is the status.
/// Returns the status line (text, is_error). The caller shows it *after*
/// the reload that follows a sync, or the reload's "N entries" would wipe
/// it a frame later.
async fn run_sync() -> (String, bool) {
    let before = read_sync_state().map(|(t, _)| t).unwrap_or(0);
    if poke_sync_daemon().await {
        // A pass is one `op item list` plus writes; a dialog nobody
        // answers holds it 60 s. Wait a little past that.
        for _ in 0..180 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if let Some((t, result)) = read_sync_state() {
                if t > before {
                    let is_error = result.starts_with("failed");
                    let msg = if result.is_empty() { "synced".to_string() } else { result };
                    return (msg, is_error);
                }
            }
        }
        return ("sync daemon did not report within 90s".to_string(), true);
    }
    let out = tokio::process::Command::new("cce-keyring-sync")
        .arg("sync")
        .output()
        .await;
    match out {
        Ok(out) => {
            let pick = |bytes: &[u8]| {
                String::from_utf8_lossy(bytes)
                    .lines()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("")
                    .to_string()
            };
            if out.status.success() {
                let line = pick(&out.stdout);
                let msg = if line.is_empty() { "synced".to_string() } else { line };
                return (msg, false);
            } else {
                let line = pick(&out.stderr);
                let msg = if line.is_empty() { "sync failed".to_string() } else { line };
                return (msg, true);
            }
        }
        Err(e) => {
            return (format!("cce-keyring-sync not runnable: {e}"), true);
        }
    }
}

// ── One-time codes ────────────────────────────────────────────────────────
//
// Asked of the resident cce-keyring-sync daemon over its socket
// (src/bin/cce-keyring-sync/serve.rs): it holds the session's `op`
// authorization, so a code costs no Authorize dialog — this process running
// `op` itself would raise one per launch. 1Password computes the code; the
// seed never leaves it. Only entries carrying an `op-item` stamp (the ones
// the sync pairs) can have one.

fn otp_socket() -> Option<std::path::PathBuf> {
    // For a shadow test against a stand-in daemon: the shadow shares the
    // live runtime dir, and binding the real path would unseat the live one.
    if let Some(p) = std::env::var_os("CCE_KEYRING_SYNC_SOCK") {
        return Some(p.into());
    }
    let dir = std::env::var("XDG_RUNTIME_DIR").ok().filter(|s| !s.is_empty())?;
    Some(std::path::PathBuf::from(dir).join("cce/keyring-sync.sock"))
}

/// Blocking: run it off the UI thread. A request that has to raise the
/// Authorize dialog (the daemon's authorization lapsed) waits out its 60 s.
fn request_otp(item_id: &str) -> OtpReply {
    use std::io::{BufRead, Write};
    let Some(path) = otp_socket() else {
        return OtpReply::Failed("no XDG_RUNTIME_DIR".into());
    };
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&path) else {
        return OtpReply::Failed("the sync daemon is not running (cce-keyring-sync.service)".into());
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(80)));
    if writeln!(stream, "otp {item_id}").is_err() {
        return OtpReply::Failed("the sync daemon hung up".into());
    }
    let mut line = String::new();
    match std::io::BufReader::new(stream).read_line(&mut line) {
        Ok(n) if n > 0 => parse_otp_reply(line.trim_end()),
        _ => OtpReply::Failed("no answer from the sync daemon".into()),
    }
}

fn parse_otp_reply(line: &str) -> OtpReply {
    if line == "none" {
        return OtpReply::Absent;
    }
    if let Some(e) = line.strip_prefix("err ") {
        return OtpReply::Failed(e.to_string());
    }
    let mut parts = line.strip_prefix("otp ").unwrap_or("").split(' ');
    match (parts.next(), parts.next().and_then(|t| t.parse().ok())) {
        (Some(code), Some(left)) if !code.is_empty() => OtpReply::Code(code.to_string(), left),
        _ => OtpReply::Failed(format!("unreadable reply: {line}")),
    }
}

/// "123456" → "123 456"; any other length as is.
fn group_code(code: &str) -> String {
    if code.len() == 6 && code.is_ascii() {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_string()
    }
}

/// Put `text` on the clipboard, and take it off again after
/// [`CLIPBOARD_CLEAR_SECS`].
///
/// The clipboard is served by `wl-copy --foreground` under `timeout`, in a
/// process group of its own, so the clear does not depend on this app: when
/// `timeout` ends `wl-copy`, the offer it was serving goes with it. Until
/// 2026-10-02 the clear was a thread in this process while a forked
/// `wl-copy` kept serving the secret, so closing cce-secrets within the 30s
/// left the password on the clipboard indefinitely. If something else is
/// copied first, `wl-copy` has already exited on losing the selection, so
/// the timer can never wipe the newer content. `--sensitive` sets the
/// `x-kde-passwordManagerHint` that clipboard-history tools honour.
///
/// Falls back to the old in-process clear when `timeout` or `wl-copy` is
/// missing.
fn copy_then_clear(text: String) {
    use std::os::unix::process::CommandExt;
    let spawned = std::process::Command::new("timeout")
        .arg(CLIPBOARD_CLEAR_SECS.to_string())
        .args(["wl-copy", "--foreground", "--sensitive"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn();
    match spawned {
        Ok(mut child) => {
            // The secret goes in on stdin, never argv. The thread reaps the
            // child while this app lives; if the app exits first, the child
            // carries on and is reaped by whoever inherits it.
            std::thread::spawn(move || {
                if let Some(mut stdin) = child.stdin.take() {
                    use std::io::Write;
                    let _ = stdin.write_all(text.as_bytes());
                }
                let _ = child.wait();
            });
        }
        Err(e) => {
            eprintln!("cce-secrets: timeout/wl-copy unavailable ({e}); clearing in-process");
            cce_ui::widget::clipboard::copy_to_clipboard(&text);
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(CLIPBOARD_CLEAR_SECS));
                if cce_ui::widget::clipboard::read_from_clipboard().as_deref() == Some(text.as_str()) {
                    cce_ui::widget::clipboard::copy_to_clipboard("");
                }
            });
        }
    }
}

// ── Secret Service worker ─────────────────────────────────────────────────
//
// The D-Bus session lives on its own thread (single-thread tokio runtime,
// notifier pattern): the UI sends commands over an mpsc, results come back
// through the calloop channel into update(). Copied secrets go straight to
// the clipboard from here — only revealed ones cross to the UI at all.

fn spawn_worker(rx: std::sync::mpsc::Receiver<Cmd>, tx: calloop::channel::Sender<AppMessage>) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = tx.send(AppMessage::Status(format!("tokio runtime failed: {e}"), true));
                return;
            }
        };
        rt.block_on(async move {
            let mut ss = match SecretService::connect(EncryptionType::Dh).await {
                Ok(ss) => ss,
                Err(e) => {
                    let _ = tx.send(AppMessage::Status(
                        format!("Secret Service unavailable: {e} — is gnome-keyring running?"),
                        true,
                    ));
                    return;
                }
            };
            load_entries(&ss, &tx).await;
            while let Ok(cmd) = rx.recv() {
                match cmd {
                    Cmd::Reload => load_entries(&ss, &tx).await,
                    Cmd::Sync => {
                        let (msg, is_error) = run_sync().await;
                        load_entries(&ss, &tx).await;
                        let _ = tx.send(AppMessage::Status(msg, is_error));
                    }
                    op => {
                        let edits = matches!(op, Cmd::CreateItem { .. } | Cmd::UpdateItem { .. } | Cmd::DeleteItem { .. });
                        let Err(first) = run_secret_op(&ss, &tx, op.clone()).await else {
                            if edits {
                                // A saved entry reaches 1Password on the
                                // daemon's next pass; ask for it now.
                                poke_sync_daemon().await;
                            }
                            continue;
                        };
                        // The daemon may have restarted underneath us
                        // (gnome-keyring aborted on a GLib assertion and was
                        // relaunched, 2026-09-06). Listing survives that, but
                        // the session negotiated at connect died with the old
                        // process, and every secret transfer names it — so the
                        // list looks fine while Copy/Reveal/Save fail. Take a
                        // fresh connection (new session) and try exactly once
                        // more; a failure on the retry is a real one.
                        log::info!("secret op failed ({first}); reconnecting to the Secret Service and retrying once");
                        match SecretService::connect(EncryptionType::Dh).await {
                            Ok(fresh) => {
                                ss = fresh;
                                if let Err(second) = run_secret_op(&ss, &tx, op).await {
                                    let _ = tx.send(AppMessage::Status(second, true));
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(AppMessage::Status(
                                    format!("{first} (reconnect to Secret Service failed: {e})"),
                                    true,
                                ));
                            }
                        }
                    }
                }
            }
        });
    });
}

/// The session-bound commands: anything that transfers a secret (or edits
/// an item) through the session opened at connect. `Err` is the status line
/// to show; the caller decides whether to retry on a fresh connection first.
async fn run_secret_op(
    ss: &SecretService<'_>,
    tx: &calloop::channel::Sender<AppMessage>,
    cmd: Cmd,
) -> Result<(), String> {
    match cmd {
        Cmd::Reload | Cmd::Sync => Ok(()),
        Cmd::GetSecret { path, purpose } => fetch_secret(ss, tx, path, purpose).await,
        Cmd::CreateItem { label, attrs, secret } => create_item(ss, tx, label, attrs, secret).await,
        Cmd::UpdateItem { path, label, attrs, secret } => {
            update_item(ss, tx, path, label, attrs, secret).await
        }
        Cmd::DeleteItem { path } => delete_item(ss, tx, path).await,
    }
}

async fn load_entries(ss: &SecretService<'_>, tx: &calloop::channel::Sender<AppMessage>) {
    let _ = tx.send(AppMessage::Progress("Loading entries…".to_string()));
    let collections = match ss.get_all_collections().await {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(AppMessage::Status(format!("Listing collections failed: {e}"), true));
            return;
        }
    };
    let mut entries = Vec::new();
    for col in &collections {
        let label = col.get_label().await.unwrap_or_else(|_| "collection".to_string());
        // Locked collection: unlocking prompts through the Secret Service
        // provider (gnome-keyring raises its own dialog and this await blocks
        // until it's answered); a refused prompt just skips the collection.
        if col.is_locked().await.unwrap_or(false) {
            let _ = tx.send(AppMessage::Status(
                format!("Unlock \"{label}\" to load its entries…"),
                false,
            ));
            if col.unlock().await.is_err() || col.is_locked().await.unwrap_or(true) {
                let _ = tx.send(AppMessage::Status(
                    format!("Collection \"{label}\" stayed locked — Refresh to retry"),
                    true,
                ));
                continue;
            }
        }
        let items = match col.get_all_items().await {
            Ok(i) => i,
            Err(e) => {
                let _ = tx.send(AppMessage::Status(format!("Listing \"{label}\" failed: {e}"), true));
                continue;
            }
        };
        for item in items {
            let mut attrs: Vec<(String, String)> = item
                .get_attributes()
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|(k, _)| k != "xdg:schema")
                .collect();
            attrs.sort();
            entries.push(EntryData {
                path: item.item_path.to_string(),
                label: item.get_label().await.unwrap_or_default(),
                collection: label.clone(),
                attrs,
            });
        }
    }
    entries.sort_by(|a, b| a.label.to_lowercase().cmp(&b.label.to_lowercase()));
    let _ = tx.send(AppMessage::Loaded(entries));
}

async fn fetch_secret(
    ss: &SecretService<'_>,
    tx: &calloop::channel::Sender<AppMessage>,
    path: String,
    purpose: Purpose,
) -> Result<(), String> {
    let item = resolve_item(ss, &path).await?;
    let _ = item.ensure_unlocked().await;
    let bytes = item
        .get_secret()
        .await
        .map_err(|e| format!("Secret fetch failed: {e}"))?;
    let secret = String::from_utf8_lossy(&bytes).to_string();
    match purpose {
        Purpose::Copy => {
            copy_then_clear(secret);
            let _ = tx.send(AppMessage::Status(
                format!("Secret copied — clipboard clears in {CLIPBOARD_CLEAR_SECS} s"),
                false,
            ));
        }
        Purpose::Reveal => {
            let _ = tx.send(AppMessage::Revealed { path, secret });
        }
    }
    Ok(())
}

async fn resolve_item<'a>(
    ss: &'a SecretService<'a>,
    path: &str,
) -> Result<secret_service::Item<'a>, String> {
    let opath = zbus::zvariant::OwnedObjectPath::try_from(path.to_string())
        .map_err(|e| format!("Bad item path: {e}"))?;
    ss.get_item_by_path(opath)
        .await
        .map_err(|e| format!("Item lookup failed: {e}"))
}

async fn create_item(
    ss: &SecretService<'_>,
    tx: &calloop::channel::Sender<AppMessage>,
    label: String,
    attrs: Vec<(String, String)>,
    secret: String,
) -> Result<(), String> {
    let collection = ss
        .get_default_collection()
        .await
        .map_err(|e| format!("No default collection: {e}"))?;
    let _ = collection.ensure_unlocked().await;
    let attr_map = attrs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let item = collection
        .create_item(&label, attr_map, secret.as_bytes(), false, "text/plain")
        .await
        .map_err(|e| format!("Create failed: {e}"))?;
    let new_path = item.item_path.to_string();
    let _ = tx.send(AppMessage::Status(format!("Created \"{label}\""), false));
    load_entries(ss, tx).await;
    let _ = tx.send(AppMessage::SelectPath(new_path));
    Ok(())
}

/// What an edit leaves on an item: its current attributes with the form's
/// fields laid over them. A field the form left empty is removed; every
/// attribute the form does not show is kept as it is.
///
/// Until 2026-10-02 a save wrote the form's fields ALONE, and the Secret
/// Service's `set_attributes` replaces the whole set. On a 1Password-paired
/// item that dropped `op-item` / `op-vault`, so the next sync saw a new
/// keyring item and an untouched remote one: it created a bare duplicate in
/// 1Password and archived the original with its one-time-code seed and
/// custom fields. On another app's item ("Chrome Safe Storage") it dropped
/// `xdg:schema` and the lookup attributes the app finds its secret by.
fn merge_edited_attributes(
    mut current: std::collections::HashMap<String, String>,
    edits: &[(String, String)],
) -> std::collections::HashMap<String, String> {
    for (key, value) in edits {
        if value.is_empty() {
            current.remove(key);
        } else {
            current.insert(key.clone(), value.clone());
        }
    }
    current
}

async fn update_item(
    ss: &SecretService<'_>,
    tx: &calloop::channel::Sender<AppMessage>,
    path: String,
    label: String,
    attrs: Vec<(String, String)>,
    secret: Option<String>,
) -> Result<(), String> {
    let item = resolve_item(ss, &path).await?;
    let _ = item.ensure_unlocked().await;
    // Read before anything is written: `set_attributes` replaces the whole
    // set, so without the current attributes there is nothing safe to save.
    let current = item
        .get_attributes()
        .await
        .map_err(|e| format!("Reading the item's attributes failed: {e}"))?;
    item.set_label(&label)
        .await
        .map_err(|e| format!("Saving label failed: {e}"))?;
    let merged = merge_edited_attributes(current, &attrs);
    let attr_map = merged.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    item.set_attributes(attr_map)
        .await
        .map_err(|e| format!("Saving attributes failed: {e}"))?;
    if let Some(secret) = secret {
        item.set_secret(secret.as_bytes(), "text/plain")
            .await
            .map_err(|e| format!("Saving secret failed: {e}"))?;
    }
    let _ = tx.send(AppMessage::Status(format!("Saved \"{label}\""), false));
    load_entries(ss, tx).await;
    let _ = tx.send(AppMessage::SelectPath(path));
    Ok(())
}

async fn delete_item(
    ss: &SecretService<'_>,
    tx: &calloop::channel::Sender<AppMessage>,
    path: String,
) -> Result<(), String> {
    let item = resolve_item(ss, &path).await?;
    item.delete().await.map_err(|e| format!("Delete failed: {e}"))?;
    let _ = tx.send(AppMessage::Status("Entry deleted".to_string(), false));
    load_entries(ss, tx).await;
    Ok(())
}

// ── The entry list's scrollbar ────────────────────────────────────────────

/// Pointer slop either side of the bar's strip, as the toolkit's bars take.
const BAR_SLOP: f32 = 4.0;
/// The track stops this far short of each end of the list.
const BAR_TRACK_INSET: f32 = 4.0;
/// The shortest thumb, as the toolkit's bars draw it.
const BAR_MIN_THUMB: f32 = 20.0;

/// The entry list's scrollbar: the DE's one design (cce-ui/CLAUDE.md, "Every
/// scrollbar rides a centre line, behind the plate") — down the CENTRE of the
/// list's width, over the rows, pills in the shared track and thumb colours.
/// Pure geometry, so it is tested without a window.
#[derive(Clone, Copy, Debug, PartialEq)]
struct ListBar {
    x: f32,
    w: f32,
    track_y: f32,
    track_h: f32,
    thumb_y: f32,
    thumb_h: f32,
}

impl ListBar {
    /// The bar for a list at `list` (x, y, w, h) holding `content_h` of rows
    /// scrolled to `scroll_y`, `w` thick; `None` when nothing overflows.
    fn of(list: (f32, f32, f32, f32), content_h: f32, scroll_y: f32, w: f32) -> Option<Self> {
        let (lx, ly, lw, lh) = list;
        if content_h <= lh || lh <= 0.0 {
            return None;
        }
        let track_y = ly + BAR_TRACK_INSET;
        let track_h = (lh - 2.0 * BAR_TRACK_INSET).max(0.0);
        let thumb_h = if track_h <= BAR_MIN_THUMB {
            track_h
        } else {
            (track_h * lh / content_h).clamp(BAR_MIN_THUMB, track_h)
        };
        let ratio = (scroll_y / (content_h - lh)).clamp(0.0, 1.0);
        Some(Self {
            x: lx + (lw - w) * 0.5,
            w,
            track_y,
            track_h,
            thumb_y: track_y + ratio * (track_h - thumb_h),
            thumb_h,
        })
    }

    /// The bar's strip, slop included — what a pointer over it means. The
    /// caller gates presses on the bar being RAISED: a sunk one is behind
    /// the list's plate and a press on its lane is a press on the row.
    fn hits(&self, px: f32, py: f32) -> bool {
        px >= self.x - BAR_SLOP
            && px <= self.x + self.w + BAR_SLOP
            && py >= self.track_y
            && py <= self.track_y + self.track_h
    }

    fn on_thumb(&self, py: f32) -> bool {
        py >= self.thumb_y && py <= self.thumb_y + self.thumb_h
    }

    /// The scroll offset that puts the thumb's top at `thumb_top`.
    fn scroll_for(&self, thumb_top: f32, max_scroll: f32) -> f32 {
        let span = self.track_h - self.thumb_h;
        if span <= 0.0 {
            return 0.0;
        }
        ((thumb_top - self.track_y) / span).clamp(0.0, 1.0) * max_scroll
    }

    /// Track then thumb, as pills, their colours' alpha scaled by `alpha`:
    /// 1 for the idle copy under the list's plate, the activity's fade for
    /// the fore copy over the rows.
    fn paint(&self, pc: &mut cce_ui::scene::paint::PaintCtx, alpha: f32) {
        use cce_ui::scene::layout::Rect;
        let a = alpha.clamp(0.0, 1.0);
        if a <= 0.001 {
            return;
        }
        let dim = |mut c: [f32; 4]| {
            c[3] *= a;
            c
        };
        let all = (true, true, true, true);
        let track = Rect { x: self.x, y: self.track_y, width: self.w, height: self.track_h };
        pc.rounded_rect(track, self.w.min(self.track_h) * 0.5, all, dim(cce_ui::color::scrollbar_track_color()));
        let thumb = Rect { x: self.x, y: self.thumb_y, width: self.w, height: self.thumb_h };
        pc.rounded_rect(thumb, self.w.min(self.thumb_h) * 0.5, all, dim(cce_ui::color::scrollbar_thumb_color()));
    }
}

/// One frame of the bar's raise/sink: true while the frame loop must keep
/// drawing — the latch flipped, the fade is moving, or the hold is still
/// running (the sink has to be ticked to, or a still list never sinks).
fn tick_bar(activity: &mut ScrollbarActivity, dt: f32, overflowing: bool, dragging: bool) -> bool {
    activity.tick(dt, overflowing, dragging) || activity.holding()
}

// ── Application ───────────────────────────────────────────────────────────

struct SecretsApp {
    search_box: cce_ui::widget::Adapted<TextBox>,
    refresh_btn: cce_ui::widget::Adapted<Button>,
    sync_btn: cce_ui::widget::Adapted<Button>,
    new_btn: cce_ui::widget::Adapted<Button>,
    reveal_btn: cce_ui::widget::Adapted<Button>,
    copy_btn: cce_ui::widget::Adapted<Button>,
    otp_btn: cce_ui::widget::Adapted<Button>,
    edit_btn: cce_ui::widget::Adapted<Button>,
    delete_btn: cce_ui::widget::Adapted<Button>,
    save_btn: cce_ui::widget::Adapted<Button>,
    cancel_btn: cce_ui::widget::Adapted<Button>,
    // The entry form, top to bottom (Tab order).
    title_box: cce_ui::widget::Adapted<TextBox>,
    user_box: cce_ui::widget::Adapted<TextBox>,
    url_box: cce_ui::widget::Adapted<TextBox>,
    notes_box: cce_ui::widget::Adapted<TextBox>,
    pass_box: cce_ui::widget::Adapted<TextBox>,

    mode: Mode,
    entries: Vec<EntryData>,
    /// Selected entry's object path (stable across reloads and filtering).
    selected: Option<String>,
    /// Revealed (path, secret); cleared on selection change and reload.
    revealed: Option<(String, String)>,
    /// Path armed for deletion by the first Delete click.
    pending_delete: Option<String>,
    /// (entry path, its one-time code) for the selected entry; `ensure_otp`
    /// keeps it following the selection and the code's 30 s period.
    otp: Option<(String, Otp)>,
    /// Entries the daemon said have no code: not asked again this run.
    otp_absent: std::collections::HashSet<String>,
    /// The countdown second last painted, so `tick` redraws once a second.
    otp_drawn_left: u64,

    /// The DRAWN list offset — `scroll_motion` glides it (wheel) or coasts
    /// it (trackpad flick); direct writes (Escape reset, clamp) are adopted
    /// by the motion on its next step.
    scroll_y: f32,
    scroll_motion: ScrollMotion,
    /// The list's scrollbar idles behind the list's plate and a scroll
    /// raises it ([`ListBar`]); this is its hold and fade.
    bar_activity: ScrollbarActivity,
    /// A thumb drag in progress: the pointer's offset from the thumb's top.
    bar_grab: Option<f32>,
    /// List viewport (x, y, w, h), refreshed each paint for hit-testing.
    list_rect: (f32, f32, f32, f32),
    pointer: (f32, f32),
    hover_row: Option<usize>,

    status_msg: String,
    status_is_error: bool,
    /// Right side of the status line: "synced 4m ago", off the sync tool's
    /// state file. Cached — the file is only re-read every few seconds.
    sync_hint: String,
    sync_hint_at: Option<std::time::Instant>,
    /// A Sync pass is in flight: the reload it ends with must not replace
    /// "Syncing…" with "N entries" before the result line arrives.
    syncing: bool,

    cmd_tx: std::sync::mpsc::Sender<Cmd>,
    cmd_rx: Option<std::sync::mpsc::Receiver<Cmd>>,
    sender: calloop::channel::Sender<AppMessage>,
    ui_context: cce_ui::context::UiContext,
}

/// A TextBox's live content: `edit_buffer` while editing (`text` only syncs
/// on commit — TextBox landmine).
fn live_text(tb: &cce_ui::widget::Adapted<TextBox>) -> &str {
    if tb.editing {
        &tb.edit_buffer
    } else {
        &tb.text
    }
}

impl SecretsApp {
    /// Indices into `entries` matching the search box, in display order.
    fn filtered(&self) -> Vec<usize> {
        let query = live_text(&self.search_box).to_lowercase();
        (0..self.entries.len())
            .filter(|&i| {
                if query.is_empty() {
                    return true;
                }
                let e = &self.entries[i];
                e.label.to_lowercase().contains(&query)
                    || e.collection.to_lowercase().contains(&query)
                    || e.attrs.iter().any(|(_, v)| v.to_lowercase().contains(&query))
            })
            .collect()
    }

    fn selected_entry(&self) -> Option<&EntryData> {
        let sel = self.selected.as_deref()?;
        self.entries.iter().find(|e| e.path == sel)
    }

    fn revealed_secret(&self) -> Option<&str> {
        let (path, secret) = self.revealed.as_ref()?;
        (self.selected.as_deref() == Some(path.as_str())).then_some(secret.as_str())
    }

    fn max_scroll(&self) -> f32 {
        (self.filtered().len() as f32 * ROW_H - self.list_rect.3).max(0.0)
    }

    /// The list's scrollbar as it stands, `None` while nothing overflows.
    fn list_scrollbar(&self) -> Option<ListBar> {
        ListBar::of(
            self.list_rect,
            self.filtered().len() as f32 * ROW_H,
            self.scroll_y,
            cce_ui::layout::centred_scrollbar_width(),
        )
    }

    /// A direct write to `scroll_y` (a clamp, the Escape reset) is a scroll
    /// like any other: if it moved the list, the bar comes up.
    fn note_scroll_from(&mut self, before: f32) {
        if (self.scroll_y - before).abs() > 1e-3 {
            self.bar_activity.bump();
        }
    }

    /// Advance the wheel glide / flick coast; true while the offset is moving
    /// (the frame loop keeps drawing). Hover follows the rows under the pointer.
    fn tick_scroll(&mut self, dt: f32) -> bool {
        self.scroll_motion.reconcile(0.0, self.scroll_y);
        if !self.scroll_motion.is_animating() {
            return false;
        }
        let moved = self.scroll_motion.tick(dt, Bounds::max(0.0), Bounds::max(self.max_scroll()));
        self.scroll_y = self.scroll_motion.y.pos();
        if moved {
            // A glide or coast in motion keeps the bar raised.
            self.bar_activity.bump();
            self.hover_row = self.row_at(self.pointer.0, self.pointer.1);
        }
        moved || self.scroll_motion.is_animating()
    }

    fn row_at(&self, px: f32, py: f32) -> Option<usize> {
        let (lx, ly, lw, lh) = self.list_rect;
        if px < lx || px > lx + lw || py < ly || py > ly + lh {
            return None;
        }
        let row = ((py - ly + self.scroll_y) / ROW_H).floor();
        (row >= 0.0 && (row as usize) < self.filtered().len()).then_some(row as usize)
    }

    fn editing(&self) -> bool {
        matches!(self.mode, Mode::Edit { .. })
    }

    /// The code to show for the selected entry, with its seconds left.
    fn shown_otp(&self) -> Option<(&str, u64)> {
        let sel = self.selected.as_deref()?;
        match &self.otp {
            Some((path, Otp::Code { code, until, .. })) if path == sel => {
                let left = until.saturating_duration_since(std::time::Instant::now()).as_secs_f32().ceil() as u64;
                Some((code.as_str(), left))
            }
            _ => None,
        }
    }

    /// Keep `otp` on the selected entry: ask the daemon when the selection
    /// lands on a paired entry, and again when the code runs out. True when
    /// anything visible changed.
    fn ensure_otp(&mut self) -> bool {
        let want = self
            .selected_entry()
            .filter(|e| !e.attr("op-item").is_empty() && !self.otp_absent.contains(&e.path))
            .map(|e| (e.path.clone(), e.attr("op-item").to_string()));
        let Some((path, item_id)) = want.filter(|_| !self.editing()) else {
            return self.otp.take().is_some();
        };
        let ask = match &mut self.otp {
            Some((p, _)) if *p != path => true,
            None => true,
            Some((_, Otp::Code { until, refreshing, .. })) => {
                if !*refreshing && std::time::Instant::now() >= *until {
                    *refreshing = true;
                    true
                } else {
                    false
                }
            }
            Some((_, Otp::Pending | Otp::Failed)) => false,
        };
        if !ask {
            return false;
        }
        let changed = !matches!(&self.otp, Some((p, Otp::Code { .. })) if *p == path);
        if changed {
            self.otp = Some((path.clone(), Otp::Pending));
        }
        let tx = self.sender.clone();
        std::thread::spawn(move || {
            let reply = request_otp(&item_id);
            let _ = tx.send(AppMessage::Otp { path, reply });
        });
        changed
    }

    fn form_boxes_mut(&mut self) -> [&mut cce_ui::widget::Adapted<TextBox>; 5] {
        [
            &mut self.title_box,
            &mut self.user_box,
            &mut self.url_box,
            &mut self.notes_box,
            &mut self.pass_box,
        ]
    }

    /// Open the form prefilled from `entry` (or blank for a new one).
    fn open_form(&mut self, entry: Option<&EntryData>) {
        let (title, user, url, notes) = match entry {
            Some(e) => (e.label.clone(), e.attr("UserName").to_string(), e.attr("URL").to_string(), e.attr("Notes").to_string()),
            None => Default::default(),
        };
        self.title_box.set_value(&title);
        self.user_box.set_value(&user);
        self.url_box.set_value(&url);
        self.notes_box.set_value(&notes);
        self.pass_box.set_value("");
        self.pass_box.placeholder = Some(
            if entry.is_some() { "leave blank to keep current" } else { "password" }.to_string(),
        );
        self.mode = Mode::Edit { path: entry.map(|e| e.path.clone()) };
        self.pending_delete = None;
        self.revealed = None;
        for b in self.form_boxes_mut() {
            b.unfocus();
        }
        self.title_box.focus();
    }

    fn close_form(&mut self) {
        for b in self.form_boxes_mut() {
            b.unfocus();
        }
        self.mode = Mode::Browse;
    }

    /// Gather the form into a save command; errors go straight to the status line.
    fn save_form(&mut self) -> Option<Cmd> {
        let title = live_text(&self.title_box).trim().to_string();
        if title.is_empty() {
            self.status_msg = "Title is required".to_string();
            self.status_is_error = true;
            return None;
        }
        let values = [&self.user_box, &self.url_box, &self.notes_box]
            .map(|b| live_text(b).trim().to_string());
        // Every edited field, empty ones included: an update removes what was
        // cleared (`merge_edited_attributes`); a new item just skips them.
        let attrs: Vec<(String, String)> = EDIT_ATTRS
            .iter()
            .zip(values)
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let password = live_text(&self.pass_box).to_string();
        let Mode::Edit { path } = &self.mode else { return None };
        Some(match path {
            Some(path) => Cmd::UpdateItem {
                path: path.clone(),
                label: title,
                attrs,
                secret: (!password.is_empty()).then_some(password),
            },
            None => Cmd::CreateItem {
                label: title,
                attrs: attrs.into_iter().filter(|(_, v)| !v.is_empty()).collect(),
                secret: password,
            },
        })
    }

    /// "synced 4m ago" from cce-keyring-sync's state file, refreshed at most
    /// every 5s — the daemon ticks every 5 minutes, so staleness is invisible.
    fn refresh_sync_hint(&mut self) {
        if self.sync_hint_at.is_some_and(|t| t.elapsed().as_secs() < 5) {
            return;
        }
        self.sync_hint_at = Some(std::time::Instant::now());
        self.sync_hint = read_sync_state()
            .map(|(t, _)| t)
            .filter(|&t| t > 0)
            .map(|t| {
                let ago = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0)
                    - t)
                    .max(0);
                match ago {
                    0..=90 => "synced just now".to_string(),
                    91..=5400 => format!("synced {}m ago", ago / 60),
                    _ => format!("synced {}h ago", ago / 3600),
                }
            })
            .unwrap_or_default();
    }

    fn buttons_mut(&mut self) -> [&mut cce_ui::widget::Adapted<Button>; 10] {
        [
            &mut self.refresh_btn,
            &mut self.sync_btn,
            &mut self.new_btn,
            &mut self.reveal_btn,
            &mut self.copy_btn,
            &mut self.otp_btn,
            &mut self.edit_btn,
            &mut self.delete_btn,
            &mut self.save_btn,
            &mut self.cancel_btn,
        ]
    }

    fn widgets_iter(&self) -> Vec<&dyn WidgetHost> {
        vec![
            &self.search_box,
            &self.refresh_btn,
            &self.sync_btn,
            &self.new_btn,
            &self.reveal_btn,
            &self.copy_btn,
            &self.otp_btn,
            &self.edit_btn,
            &self.delete_btn,
            &self.save_btn,
            &self.cancel_btn,
            &self.title_box,
            &self.user_box,
            &self.url_box,
            &self.notes_box,
            &self.pass_box,
        ]
    }
}

fn park(btn: &mut cce_ui::widget::Adapted<Button>) {
    btn.set_rect(-1000.0, -1000.0, BTN_W, cce_ui::layout::button_height());
}

fn srgb_u8(linear: [f32; 4]) -> [u8; 3] {
    let srgb = cce_ui::colors::to_srgb(linear);
    [
        (srgb[0] * 255.0) as u8,
        (srgb[1] * 255.0) as u8,
        (srgb[2] * 255.0) as u8,
    ]
}

impl Application for SecretsApp {
    type Message = AppMessage;

    fn ui_context(&self) -> Option<&cce_ui::context::UiContext> {
        Some(&self.ui_context)
    }

    fn new(_qh: &QueueHandle<EngineState<Self>>, sender: calloop::channel::Sender<Self::Message>) -> Self {
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        Self {
            search_box: TextBox::new(String::new()).with_placeholder("Search"),
            refresh_btn: Button::new(0.0, 0.0, BTN_W, cce_ui::layout::button_height()).with_label("Refresh"),
            sync_btn: Button::new(0.0, 0.0, BTN_W, cce_ui::layout::button_height()).with_label("Sync"),
            new_btn: Button::new(0.0, 0.0, BTN_W, cce_ui::layout::button_height()).with_label("New"),
            reveal_btn: Button::new(0.0, 0.0, BTN_W, cce_ui::layout::button_height()).with_label("Reveal"),
            copy_btn: Button::new(0.0, 0.0, BTN_W, cce_ui::layout::button_height()).with_label("Copy"),
            otp_btn: Button::new(0.0, 0.0, BTN_W, cce_ui::layout::button_height()).with_label("Copy code"),
            edit_btn: Button::new(0.0, 0.0, BTN_W, cce_ui::layout::button_height()).with_label("Edit"),
            delete_btn: Button::new(0.0, 0.0, BTN_W, cce_ui::layout::button_height()).with_label("Delete"),
            save_btn: Button::new(0.0, 0.0, BTN_W, cce_ui::layout::button_height()).with_label("Save"),
            cancel_btn: Button::new(0.0, 0.0, BTN_W, cce_ui::layout::button_height()).with_label("Cancel"),
            title_box: TextBox::new(String::new()).with_placeholder("title"),
            user_box: TextBox::new(String::new()).with_placeholder("username"),
            url_box: TextBox::new(String::new()).with_placeholder("url"),
            notes_box: TextBox::new(String::new()).with_placeholder("notes"),
            pass_box: TextBox::new(String::new()).with_password(true).with_placeholder("password"),
            mode: Mode::Browse,
            entries: Vec::new(),
            selected: None,
            revealed: None,
            pending_delete: None,
            otp: None,
            otp_absent: std::collections::HashSet::new(),
            otp_drawn_left: 0,
            scroll_y: 0.0,
            scroll_motion: ScrollMotion::new(),
            bar_activity: ScrollbarActivity::new(),
            bar_grab: None,
            // Placed by the first frame; empty until then so nothing hit-tests.
            list_rect: (0.0, 0.0, 0.0, 0.0),
            pointer: (0.0, 0.0),
            hover_row: None,
            status_msg: "Connecting to Secret Service…".to_string(),
            status_is_error: false,
            sync_hint: String::new(),
            sync_hint_at: None,
            syncing: false,
            cmd_tx,
            cmd_rx: Some(cmd_rx),
            sender,
            ui_context: cce_ui::context::UiContext::new(),
        }
    }

    fn settings(&self) -> WindowSettings {
        WindowSettings {
            title: "CCE Secrets".to_string(),
            app_id: "cce-secrets".to_string(),
            width: 760,
            height: 520,
            fullscreen: false,
            min_size: Some((560, 380)),
        }
    }

    fn register_sources(&mut self, _handle: &calloop::LoopHandle<'_, EngineState<Self>>) {
        if let Some(rx) = self.cmd_rx.take() {
            spawn_worker(rx, self.sender.clone());
        }
    }

    fn update(&mut self, msg: Self::Message, needs_rebuild: &mut bool, _exit: &mut bool) {
        *needs_rebuild = true;
        match msg {
            AppMessage::Loaded(entries) => {
                self.entries = entries;
                self.revealed = None;
                self.pending_delete = None;
                if self.selected_entry().is_none() {
                    self.selected = None;
                }
                let before = self.scroll_y;
                self.scroll_y = self.scroll_y.clamp(0.0, self.max_scroll());
                self.note_scroll_from(before);
                if self.syncing {
                    return;
                }
                self.status_msg = if self.entries.is_empty() {
                    "No entries — run `cce-keyring-sync adopt --vault <name>` to seed the keyring from 1Password".to_string()
                } else {
                    format!("{} entries", self.entries.len())
                };
                self.status_is_error = false;
            }
            AppMessage::Status(msg, is_error) => {
                self.syncing = false;
                self.status_msg = msg;
                self.status_is_error = is_error;
            }
            AppMessage::Progress(msg) => {
                if !self.syncing {
                    self.status_msg = msg;
                    self.status_is_error = false;
                }
            }
            AppMessage::Revealed { path, secret } => {
                if self.selected.as_deref() == Some(path.as_str()) {
                    self.revealed = Some((path, secret));
                }
            }
            AppMessage::SelectPath(path) => {
                self.selected = Some(path);
                self.revealed = None;
                self.pending_delete = None;
            }
            AppMessage::RefreshClicked => {
                let _ = self.cmd_tx.send(Cmd::Reload);
            }
            AppMessage::SyncClicked => {
                self.syncing = true;
                self.status_msg = "Syncing…".to_string();
                self.status_is_error = false;
                let _ = self.cmd_tx.send(Cmd::Sync);
            }
            AppMessage::RevealClicked => {
                if let Some(sel) = self.selected.clone() {
                    if self.revealed_secret().is_some() {
                        self.revealed = None;
                    } else {
                        let _ = self.cmd_tx.send(Cmd::GetSecret { path: sel, purpose: Purpose::Reveal });
                    }
                }
            }
            AppMessage::CopyClicked => {
                if let Some(sel) = self.selected.clone() {
                    let _ = self.cmd_tx.send(Cmd::GetSecret { path: sel, purpose: Purpose::Copy });
                }
            }
            AppMessage::CopyOtpClicked => {
                if let Some((code, _)) = self.shown_otp() {
                    copy_then_clear(code.to_string());
                    self.status_msg = format!("Code copied — clipboard clears in {CLIPBOARD_CLEAR_SECS} s");
                    self.status_is_error = false;
                }
            }
            AppMessage::Otp { path, reply } => {
                // A reply for an entry no longer selected is dropped; the
                // next selection asks afresh.
                if self.otp.as_ref().is_none_or(|(p, _)| *p != path) {
                    return;
                }
                self.otp = match reply {
                    OtpReply::Code(code, left) => Some((
                        path,
                        Otp::Code {
                            code,
                            until: std::time::Instant::now() + std::time::Duration::from_secs(left),
                            refreshing: false,
                        },
                    )),
                    OtpReply::Absent => {
                        self.otp_absent.insert(path);
                        None
                    }
                    OtpReply::Failed(e) => {
                        self.status_msg = format!("One-time code: {e}");
                        self.status_is_error = true;
                        Some((path, Otp::Failed))
                    }
                };
            }
            AppMessage::NewClicked => self.open_form(None),
            AppMessage::EditClicked => {
                if let Some(entry) = self.selected_entry().cloned() {
                    self.open_form(Some(&entry));
                }
            }
            AppMessage::DeleteClicked => {
                if let Some(sel) = self.selected.clone() {
                    if self.pending_delete.as_deref() == Some(sel.as_str()) {
                        self.pending_delete = None;
                        self.status_msg = "Deleting…".to_string();
                        self.status_is_error = false;
                        let _ = self.cmd_tx.send(Cmd::DeleteItem { path: sel });
                    } else {
                        self.pending_delete = Some(sel);
                        self.status_msg = "Click Confirm to delete this entry".to_string();
                        self.status_is_error = false;
                    }
                }
            }
            AppMessage::SaveClicked => {
                if let Some(cmd) = self.save_form() {
                    self.status_msg = "Saving…".to_string();
                    self.status_is_error = false;
                    let _ = self.cmd_tx.send(cmd);
                    self.close_form();
                }
            }
            AppMessage::CancelClicked => self.close_form(),
        }
    }

    fn tick(&mut self, dt: f32, needs_rebuild: &mut bool) {
        if self.tick_scroll(dt) {
            *needs_rebuild = true;
        }
        let overflowing = self.filtered().len() as f32 * ROW_H > self.list_rect.3;
        if tick_bar(&mut self.bar_activity, dt, overflowing, self.bar_grab.is_some()) {
            *needs_rebuild = true;
        }
        if self.ensure_otp() {
            *needs_rebuild = true;
        }
        if self.shown_otp().is_some_and(|(_, left)| left != self.otp_drawn_left) {
            *needs_rebuild = true;
        }
    }

    /// While a code is up, wake often enough to step its countdown (tick
    /// dt is not wall clock; the deadline is an `Instant`).
    fn idle_poll_interval(&self) -> Option<std::time::Duration> {
        self.shown_otp().map(|_| std::time::Duration::from_millis(250))
    }

    fn display_list(&mut self, size: LogicalSize, scale: f64) -> Option<cce_ui::scene::paint::DisplayList> {
        use cce_ui::scene::layout::Rect;
        cce_ui::scale::set_scale_factor(scale as f32);
        let sw = size.width as f32;
        let sh = size.height as f32;

        // Widget roots re-registered every frame (idempotent; the frame is
        // assembled by hand, so nothing else registers them).
        {
            let (id, ptr) = (self.search_box.id(), self.search_box.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            {
                let (id, ptr) = (self.sync_btn.id(), self.sync_btn.as_ptr_mut());
                self.ui_context.register_widget(id, ptr);
            }
            let (id, ptr) = (self.refresh_btn.id(), self.refresh_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.new_btn.id(), self.new_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.reveal_btn.id(), self.reveal_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.copy_btn.id(), self.copy_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.otp_btn.id(), self.otp_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.edit_btn.id(), self.edit_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.delete_btn.id(), self.delete_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.save_btn.id(), self.save_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.cancel_btn.id(), self.cancel_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.title_box.id(), self.title_box.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.user_box.id(), self.user_box.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.url_box.id(), self.url_box.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.notes_box.id(), self.notes_box.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.pass_box.id(), self.pass_box.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
        }

        let mut pc = cce_ui::scene::paint::PaintCtx::new();
        let quad = |pc: &mut cce_ui::scene::paint::PaintCtx, x: f32, y: f32, w: f32, h: f32, c: [f32; 4]| {
            pc.quad(Rect { x, y, width: w, height: h }, c);
        };

        // The standard root plate (cce-ui PlateSpec::window): the DE root
        // material at its opacity, the shared silhouette arc, the rolled rim.
        pc.root_plate(sw, sh);

        // Spacing is the ladder (cce-ui/CLAUDE.md): the window edge is
        // `inset`, siblings on the root plate stand `gap` apart, and inside
        // the two panes content sits `pad` off the rim with `pgap` between
        // blocks. The literals that remain are sizes and text line advances.
        let inset = cce_ui::layout::root_plate_inset();
        let gap = cce_ui::layout::root_plate_gap();
        let pad = cce_ui::layout::plate_padding();
        let pgap = cce_ui::layout::plate_gap();
        let btn_h = cce_ui::layout::button_height();
        let box_h = cce_ui::layout::textbox_height();

        // ── Left panel: search + entry list ──
        self.search_box.set_rect(inset, inset, LIST_W, box_h);
        self.refresh_btn.set_rect(sw - inset - BTN_W, inset, BTN_W, btn_h);
        self.new_btn.set_rect(sw - inset - BTN_W * 2.0 - gap, inset, BTN_W, btn_h);
        self.sync_btn.set_rect(sw - inset - BTN_W * 3.0 - 2.0 * gap, inset, BTN_W, btn_h);

        // Below the taller of the search box and the button row beside it.
        let list_y = inset + box_h.max(btn_h) + gap;
        let list_h = (sh - list_y - STATUS_H - gap).max(0.0);
        self.list_rect = (inset, list_y, LIST_W, list_h);
        // The scrollbar's idle copy, at full alpha UNDER the list's
        // translucent plate, every frame — raised or not, since the fore copy
        // fades in over it and dropping this at the latch would blink the bar.
        let bar = self.list_scrollbar();
        if let Some(bar) = bar {
            bar.paint(&mut pc, 1.0);
        }
        quad(&mut pc, inset, list_y, LIST_W, list_h, cce_ui::color::list_bg_color());

        let filtered = self.filtered();
        let list_bounds = Some([inset, list_y, inset + LIST_W, list_y + list_h]);
        for (row, &ei) in filtered.iter().enumerate() {
            let ry = list_y + row as f32 * ROW_H - self.scroll_y;
            if ry + ROW_H < list_y || ry > list_y + list_h {
                continue;
            }
            let entry = &self.entries[ei];
            let is_selected = self.selected.as_deref() == Some(entry.path.as_str());
            if is_selected {
                quad(&mut pc, inset, ry, LIST_W, ROW_H, [0.10, 0.28, 0.17, 1.0]);
            } else if self.hover_row == Some(row) {
                quad(&mut pc, inset, ry, LIST_W, ROW_H, [1.0, 1.0, 1.0, 0.04]);
            }
            // TODO(style): the two text lines sit at fixed offsets inside the
            // ROW_H row — a line rhythm, not a rung.
            pc.text_with(
                entry.label.clone(),
                inset + pad,
                ry + 8.0,
                12.0,
                srgb_u8(cce_ui::colors::TEXT_HEADER),
                None,
                list_bounds,
            );
            if let Some(hint) = entry.hint() {
                pc.text_with(
                    hint.to_string(),
                    inset + pad,
                    ry + 25.0,
                    10.0,
                    srgb_u8(cce_ui::colors::TEXT_DIM),
                    None,
                    list_bounds,
                );
            }
        }

        // The scrollbar's fore copy, over the rows at the activity's fade:
        // a scroll raises it out of the plate, and it sinks back once idle.
        if let Some(bar) = bar {
            bar.paint(&mut pc, self.bar_activity.fade());
        }

        // ── Right panel: detail view or the entry form ──
        let dx = inset + LIST_W + gap;
        let dw = (sw - dx - inset).max(0.0);
        let detail_bounds = Some([dx, list_y, dx + dw, list_y + list_h]);
        // The pane's content starts one plate padding below its top; the
        // 22.0 under the 15px header is that line's advance, not a rung.
        let hy = list_y + pad;
        match &self.mode {
            Mode::Edit { path } => {
                let header = if path.is_some() { "Edit entry" } else { "New entry" };
                pc.text_with(header.to_string(), dx, hy, 15.0, srgb_u8(cce_ui::colors::TEXT_HEADER), None, detail_bounds);
                let labels = ["Title", "UserName", "URL", "Notes", "Password"];
                let mut fy = hy + 22.0 + pgap;
                let box_w = (dw - 4.0).min(320.0); // TODO(style): 4px slack on the field width, not a rung
                // Each field is a 10px label strip (14.0) over a textbox. The
                // fields are `pgap` apart rather than `control_gap()`: five
                // control-height gaps overrun the default window height.
                for (label, tb) in labels.iter().zip(self.form_boxes_mut()) {
                    tb.set_rect(dx, fy + 14.0, box_w, box_h);
                    pc.text_with(label.to_string(), dx, fy, 10.0, srgb_u8(cce_ui::colors::TEXT_DIM), None, None);
                    fy += 14.0 + box_h + pgap;
                }
                self.save_btn.set_rect(dx, fy, BTN_W, btn_h);
                self.cancel_btn.set_rect(dx + BTN_W + pgap, fy, BTN_W, btn_h);
                for b in [&mut self.reveal_btn, &mut self.copy_btn, &mut self.otp_btn, &mut self.edit_btn, &mut self.delete_btn, &mut self.new_btn] {
                    park(b);
                }
            }
            Mode::Browse => {
                park(&mut self.save_btn);
                park(&mut self.cancel_btn);
                for tb in self.form_boxes_mut() {
                    tb.set_rect(-1000.0, -1000.0, 10.0, 10.0);
                }
                if let Some(entry) = self.selected_entry().cloned() {
                    pc.text_with(entry.label.clone(), dx, hy, 15.0, srgb_u8(cce_ui::colors::TEXT_HEADER), None, detail_bounds);
                    pc.text_with(entry.collection.clone(), dx, hy + 22.0, 10.0, srgb_u8(cce_ui::colors::TEXT_DIM), None, detail_bounds);

                    // The header block (a 15px line, a 10px line), a pane gap,
                    // then the attribute rows at their 22.0 line advance.
                    let mut ay = hy + 22.0 + 14.0 + pgap;
                    for (key, value) in &entry.attrs {
                        pc.text_with(key.clone(), dx, ay, 10.0, srgb_u8(cce_ui::colors::TEXT_DIM), None, detail_bounds);
                        pc.text_with(value.clone(), dx + 120.0, ay, 11.0, srgb_u8(cce_ui::colors::TEXT_FG), None, detail_bounds);
                        ay += 22.0;
                    }

                    ay += pgap;
                    pc.text_with("secret".to_string(), dx, ay, 10.0, srgb_u8(cce_ui::colors::TEXT_DIM), None, detail_bounds);
                    let (secret_text, revealed) = match self.revealed_secret() {
                        Some(s) => (s.to_string(), true),
                        None => ("••••••••••••".to_string(), false),
                    };
                    pc.text_with(secret_text, dx + 120.0, ay, 11.0, srgb_u8(cce_ui::colors::TEXT_FG), None, detail_bounds);

                    let otp = self.shown_otp().map(|(code, left)| (group_code(code), left));
                    if let Some((code, left)) = &otp {
                        self.otp_drawn_left = *left;
                        ay += 22.0;
                        pc.text_with("one-time code".to_string(), dx, ay, 10.0, srgb_u8(cce_ui::colors::TEXT_DIM), None, detail_bounds);
                        pc.text_with(format!("{code}  ·  {left}s"), dx + 120.0, ay, 11.0, srgb_u8(cce_ui::colors::TEXT_FG), None, detail_bounds);
                    }

                    self.reveal_btn.set_label(if revealed { "Hide" } else { "Reveal" });
                    self.delete_btn.set_label(
                        if self.pending_delete.as_deref() == Some(entry.path.as_str()) { "Confirm" } else { "Delete" },
                    );
                    // Two button rows under the secret line (14.0, its advance).
                    let by = ay + 14.0 + pgap;
                    self.reveal_btn.set_rect(dx, by, BTN_W, btn_h);
                    self.copy_btn.set_rect(dx + BTN_W + pgap, by, BTN_W, btn_h);
                    self.edit_btn.set_rect(dx, by + btn_h + pgap, BTN_W, btn_h);
                    self.delete_btn.set_rect(dx + BTN_W + pgap, by + btn_h + pgap, BTN_W, btn_h);
                    // Copy code ends the first row when the pane is wide
                    // enough, else opens a third.
                    if otp.is_some() {
                        let third = dx + 2.0 * (BTN_W + pgap);
                        if third + BTN_W <= dx + dw {
                            self.otp_btn.set_rect(third, by, BTN_W, btn_h);
                        } else {
                            self.otp_btn.set_rect(dx, by + 2.0 * (btn_h + pgap), BTN_W, btn_h);
                        }
                    } else {
                        park(&mut self.otp_btn);
                    }
                } else {
                    let hint = if self.entries.is_empty() { "" } else { "Select an entry" };
                    pc.text_with(hint.to_string(), dx, hy, 11.0, srgb_u8(cce_ui::colors::TEXT_DIM), None, detail_bounds);
                    for b in [&mut self.reveal_btn, &mut self.copy_btn, &mut self.otp_btn, &mut self.edit_btn, &mut self.delete_btn] {
                        park(b);
                    }
                }
            }
        }

        // ── Widgets + status line ──
        for w in &self.widgets_iter() {
            let (wx, wy, ww, wh) = w.rect();
            quad(&mut pc, wx, wy, ww, wh, w.color());
            for (qx, qy, qw, qh, qc) in w.extra_quads() {
                quad(&mut pc, qx, qy, qw, qh, qc);
            }
        }
        for w in self.widgets_iter() {
            cce_ui::scene::painter::append_widget_text(&self.ui_context, w, &mut pc);
        }

        let status_color = if self.status_is_error { [0xee, 0x5c, 0x5c] } else { srgb_u8(cce_ui::colors::TEXT_DIM) };
        pc.text_with(
            self.status_msg.clone(),
            inset,
            sh - STATUS_H + 6.0, // TODO(style): seats the 10px line in the STATUS_H band, not a rung
            10.0,
            status_color,
            None,
            Some([inset, sh - STATUS_H, sw - inset, sh]),
        );
        self.refresh_sync_hint();
        if !self.sync_hint.is_empty() {
            let w = cce_ui::widget::display::measure_text_width(&self.sync_hint, &cce_ui::layout::read_preferred_fonts().0, 10.0);
            pc.text_with(
                self.sync_hint.clone(),
                sw - inset - w,
                sh - STATUS_H + 6.0,
                10.0,
                srgb_u8(cce_ui::colors::TEXT_DIM),
                None,
                Some([inset, sh - STATUS_H, sw - inset, sh]),
            );
        }

        Some(pc.finish())
    }

    fn display_list_text(&self) -> bool {
        true
    }

    fn handle_pointer_move(&mut self, pos: LogicalPosition, needs_rebuild: &mut bool) {
        self.pointer = (pos.x, pos.y);
        let bar = self.list_scrollbar();
        // Hover only SUSTAINS a raised bar; the activity ignores it on a sunk one.
        self.bar_activity.set_hover(bar.is_some_and(|b| b.hits(pos.x, pos.y)));
        if let (Some(grab), Some(bar)) = (self.bar_grab, bar) {
            let before = self.scroll_y;
            self.scroll_y = bar.scroll_for(pos.y - grab, self.max_scroll());
            self.scroll_motion.y.jump_to(self.scroll_y);
            if (self.scroll_y - before).abs() > 1e-3 {
                *needs_rebuild = true;
            }
        }
        let mv = cce_ui::widget::Event::PointerMove { x: pos.x, y: pos.y, local_x: pos.x, local_y: pos.y };
        let mut roots = vec![self.search_box.id()];
        roots.extend(self.buttons_mut().map(|b| b.id()));
        roots.extend(self.form_boxes_mut().map(|b| b.id()));
        for root in roots {
            if self.ui_context.propagate_event(&mv, root) {
                *needs_rebuild = true;
            }
        }
        let hover = self.row_at(pos.x, pos.y);
        if hover != self.hover_row {
            self.hover_row = hover;
            *needs_rebuild = true;
        }
    }

    fn handle_mouse_input(
        &mut self,
        button: MouseButton,
        state: ElementState,
        pos: LogicalPosition,
        needs_rebuild: &mut bool,
    ) -> Option<Self::Message> {
        let (lx, ly) = (pos.x, pos.y);
        let ev = cce_ui::widget::Event::MouseButton { button, state, x: lx, y: ly, local_x: lx, local_y: ly };

        // A thumb drag ends wherever the button comes up; the release
        // refreshes the hold, as a scroll does.
        if button == MouseButton::Left && state == ElementState::Released && self.bar_grab.take().is_some() {
            self.bar_activity.bump();
            *needs_rebuild = true;
        }

        // Buttons: propagate, then drain clicks into messages.
        let button_roots: Vec<_> = {
            let bs = self.buttons_mut();
            bs.iter().map(|b| b.id()).collect()
        };
        for root in button_roots {
            if self.ui_context.propagate_event(&ev, root) {
                *needs_rebuild = true;
            }
        }
        if self.refresh_btn.take_click() {
            return Some(AppMessage::RefreshClicked);
        }
        if self.sync_btn.take_click() {
            return Some(AppMessage::SyncClicked);
        }
        if self.new_btn.take_click() {
            return Some(AppMessage::NewClicked);
        }
        if self.reveal_btn.take_click() {
            return Some(AppMessage::RevealClicked);
        }
        if self.copy_btn.take_click() {
            return Some(AppMessage::CopyClicked);
        }
        if self.otp_btn.take_click() {
            return Some(AppMessage::CopyOtpClicked);
        }
        if self.edit_btn.take_click() {
            return Some(AppMessage::EditClicked);
        }
        if self.delete_btn.take_click() {
            return Some(AppMessage::DeleteClicked);
        }
        if self.save_btn.take_click() {
            return Some(AppMessage::SaveClicked);
        }
        if self.cancel_btn.take_click() {
            return Some(AppMessage::CancelClicked);
        }

        // Text boxes: unfocus the ones the press missed, then propagate.
        let mut box_roots = vec![self.search_box.id()];
        if self.editing() {
            box_roots.extend(self.form_boxes_mut().map(|b| b.id()));
        }
        if state == ElementState::Pressed {
            if !self.search_box.hit_test(lx, ly, &self.ui_context) {
                self.search_box.unfocus();
            }
            if self.editing() {
                if !self.title_box.hit_test(lx, ly, &self.ui_context) {
                    self.title_box.unfocus();
                }
                if !self.user_box.hit_test(lx, ly, &self.ui_context) {
                    self.user_box.unfocus();
                }
                if !self.url_box.hit_test(lx, ly, &self.ui_context) {
                    self.url_box.unfocus();
                }
                if !self.notes_box.hit_test(lx, ly, &self.ui_context) {
                    self.notes_box.unfocus();
                }
                if !self.pass_box.hit_test(lx, ly, &self.ui_context) {
                    self.pass_box.unfocus();
                }
            }
        }
        for root in box_roots {
            if self.ui_context.propagate_event(&ev, root) {
                *needs_rebuild = true;
            }
        }

        // The scrollbar takes a press only while RAISED: sunk, it is behind
        // the list's plate and the press is the row's. On the thumb it grabs
        // where it was pressed; on the track the thumb jumps under the pointer.
        if button == MouseButton::Left && state == ElementState::Pressed && self.bar_activity.raised() {
            if let Some(bar) = self.list_scrollbar().filter(|b| b.hits(lx, ly)) {
                let grab = if bar.on_thumb(ly) { ly - bar.thumb_y } else { bar.thumb_h * 0.5 };
                self.bar_grab = Some(grab);
                self.scroll_y = bar.scroll_for(ly - grab, self.max_scroll());
                self.scroll_motion.y.jump_to(self.scroll_y);
                self.bar_activity.bump();
                self.hover_row = self.row_at(lx, ly);
                *needs_rebuild = true;
                return None;
            }
        }

        // List selection only while browsing — the form keeps its state.
        if !self.editing() && button == MouseButton::Left && state == ElementState::Pressed {
            if let Some(row) = self.row_at(lx, ly) {
                let filtered = self.filtered();
                let path = self.entries[filtered[row]].path.clone();
                if self.selected.as_deref() != Some(path.as_str()) {
                    self.selected = Some(path);
                    self.revealed = None;
                    self.pending_delete = None;
                    *needs_rebuild = true;
                }
            }
        }
        None
    }

    fn handle_mouse_wheel(&mut self, delta: &MouseScrollDelta, pos: LogicalPosition, needs_rebuild: &mut bool) {
        let (lx, ly, lw, lh) = self.list_rect;
        if pos.x < lx || pos.x > lx + lw || pos.y < ly || pos.y > ly + lh {
            return;
        }
        self.scroll_motion.reconcile(0.0, self.scroll_y);
        let moved = self.scroll_motion.apply(delta, (LINE_PX, LINE_PX), Bounds::max(0.0), Bounds::max(self.max_scroll()));
        self.scroll_y = self.scroll_motion.y.pos();
        // A wheel raises the bar, even one that meets the end of the list.
        self.bar_activity.bump();
        if moved {
            self.hover_row = self.row_at(self.pointer.0, self.pointer.1);
            *needs_rebuild = true;
        }
    }

    fn handle_key_input(&mut self, event: &KeyEvent, needs_rebuild: &mut bool) -> Option<Self::Message> {
        if event.state == ElementState::Pressed && !event.repeat {
            match &event.logical_key {
                Key::Named(NamedKey::Escape) => {
                    if self.editing() {
                        return Some(AppMessage::CancelClicked);
                    }
                    // TextBox never tracks ctx focus — `editing` is its focus signal.
                    if self.search_box.editing {
                        self.search_box.text.clear();
                        self.search_box.edit_buffer.clear();
                        self.search_box.unfocus();
                        let before = self.scroll_y;
                        self.scroll_y = 0.0;
                        self.note_scroll_from(before);
                        *needs_rebuild = true;
                        return None;
                    }
                }
                Key::Named(NamedKey::Tab) if self.editing() => {
                    // TextBox never tracks ctx focus — `editing` is its focus signal.
                    let focused = [
                        self.title_box.editing,
                        self.user_box.editing,
                        self.url_box.editing,
                        self.notes_box.editing,
                        self.pass_box.editing,
                    ]
                    .iter()
                    .position(|&f| f);
                    let next = focused.map(|i| (i + 1) % 5).unwrap_or(0);
                    for (i, tb) in self.form_boxes_mut().into_iter().enumerate() {
                        if i == next {
                            tb.focus();
                        } else {
                            tb.unfocus();
                        }
                    }
                    *needs_rebuild = true;
                    return None;
                }
                Key::Named(NamedKey::Enter) if self.editing() => {
                    return Some(AppMessage::SaveClicked);
                }
                _ => {}
            }
        }
        let kev = cce_ui::widget::Event::KeyInput(event.clone());
        let mut roots = vec![self.search_box.id()];
        if self.editing() {
            roots.extend(self.form_boxes_mut().map(|b| b.id()));
        }
        for root in roots {
            if self.ui_context.propagate_event(&kev, root) {
                *needs_rebuild = true;
            }
        }
        let before = self.scroll_y;
        self.scroll_y = self.scroll_y.clamp(0.0, self.max_scroll());
        self.note_scroll_from(before);
        None
    }
}

fn main() {
    env_logger::init();
    cce_ui::engine::run::<SecretsApp>();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_edit_keeps_every_attribute_the_form_does_not_show() {
        let current: std::collections::HashMap<String, String> = [
            ("op-item", "abc123"),
            ("op-vault", "Personal"),
            ("xdg:schema", "org.freedesktop.Secret.Generic"),
            ("UserName", "old@example.org"),
            ("URL", "https://old.example.org"),
            ("Notes", "keep me"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let edits = vec![
            ("UserName".to_string(), "new@example.org".to_string()),
            ("URL".to_string(), String::new()),
            ("Notes".to_string(), "keep me".to_string()),
        ];
        let merged = merge_edited_attributes(current, &edits);
        // The pairing and the schema survive: losing them is what duplicated
        // and archived 1Password items.
        assert_eq!(merged.get("op-item").map(String::as_str), Some("abc123"));
        assert_eq!(merged.get("op-vault").map(String::as_str), Some("Personal"));
        assert_eq!(merged.get("xdg:schema").map(String::as_str), Some("org.freedesktop.Secret.Generic"));
        // The form's fields are what it says: changed, cleared, unchanged.
        assert_eq!(merged.get("UserName").map(String::as_str), Some("new@example.org"));
        assert!(!merged.contains_key("URL"), "a cleared field is removed");
        assert_eq!(merged.get("Notes").map(String::as_str), Some("keep me"));
        assert_eq!(merged.len(), 5);
    }

    #[test]
    fn the_list_bar_rides_the_centre_line_and_only_when_it_overflows() {
        let list = (10.0, 100.0, 280.0, 200.0);
        assert_eq!(ListBar::of(list, 200.0, 0.0, 6.0), None, "nothing to scroll, no bar");

        // 800 px of rows in a 200 px list.
        let top = ListBar::of(list, 800.0, 0.0, 6.0).unwrap();
        assert!((top.x + top.w * 0.5 - (10.0 + 140.0)).abs() < 1e-4, "down the list's centre line");
        assert_eq!((top.track_y, top.track_h), (104.0, 192.0), "the track stops 4 px short of each end");
        assert!((top.thumb_h - 48.0).abs() < 1e-4, "a quarter of the rows is a quarter of the track");
        assert_eq!(top.thumb_y, top.track_y);

        let end = ListBar::of(list, 800.0, 600.0, 6.0).unwrap();
        assert!((end.thumb_y + end.thumb_h - (end.track_y + end.track_h)).abs() < 1e-4, "scrolled to the end");
        assert!((end.scroll_for(end.thumb_y, 600.0) - 600.0).abs() < 1e-3);
        assert!((top.scroll_for(top.thumb_y, 600.0)).abs() < 1e-3);

        // A long list keeps the toolkit's shortest thumb.
        let long = ListBar::of(list, 100_000.0, 0.0, 6.0).unwrap();
        assert_eq!(long.thumb_h, BAR_MIN_THUMB);

        // The strip with its slop, and nothing past the track's ends.
        assert!(top.hits(top.x - BAR_SLOP, 150.0));
        assert!(top.hits(top.x + top.w + BAR_SLOP, 150.0));
        assert!(!top.hits(top.x - BAR_SLOP - 1.0, 150.0));
        assert!(!top.hits(top.x + 1.0, top.track_y - 1.0));
    }

    #[test]
    fn the_list_bar_keeps_frames_coming_until_it_has_sunk() {
        let mut a = ScrollbarActivity::new();
        // Hover never raises a sunk bar.
        a.set_hover(true);
        assert!(!tick_bar(&mut a, 0.016, true, false));
        assert!(!a.raised());
        a.set_hover(false);

        // A scroll raises it, and frames keep coming until the sink has
        // faded all the way out — then they stop.
        a.bump();
        let mut frames = 0;
        while tick_bar(&mut a, 0.016, true, false) {
            frames += 1;
            assert!(frames < 1000, "the bar never settled");
        }
        assert!(frames > 0);
        assert!(!a.raised());
        assert_eq!(a.fade(), 0.0);

        // A pointer over a RAISED bar holds it up past the hold.
        a.bump();
        tick_bar(&mut a, 0.016, true, false);
        assert!(a.raised());
        a.set_hover(true);
        for _ in 0..200 {
            tick_bar(&mut a, 0.016, true, false);
        }
        assert!(a.raised(), "hover sustains a raised bar");
    }

    #[test]
    fn daemon_replies_parse() {
        assert_eq!(parse_otp_reply("otp 123456 17"), OtpReply::Code("123456".into(), 17));
        assert_eq!(parse_otp_reply("none"), OtpReply::Absent);
        assert_eq!(parse_otp_reply("err not a mirrored item"), OtpReply::Failed("not a mirrored item".into()));
        assert!(matches!(parse_otp_reply("otp 123456"), OtpReply::Failed(_)));
        assert!(matches!(parse_otp_reply(""), OtpReply::Failed(_)));
        assert_eq!(group_code("123456"), "123 456");
        assert_eq!(group_code("12345678"), "12345678");
    }
}
