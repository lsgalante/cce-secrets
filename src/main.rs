use secret_service::{EncryptionType, SecretService};
use wayland_client::QueueHandle;

use cce_ui::engine::{Application, EngineState, LogicalPosition, LogicalSize, WindowSettings};
use cce_ui::widget::{
    Bounds, Button, ElementState, Key, KeyEvent, MouseButton, MouseScrollDelta, NamedKey,
    ScrollMotion, TextBox, WidgetHost, LINE_PX,
};

const PAD: f32 = 16.0;
const LIST_W: f32 = 280.0;
const ROW_H: f32 = 44.0;
const STATUS_H: f32 = 30.0;
const BTN_W: f32 = 90.0;
const BTN_H: f32 = 28.0;
const CLIPBOARD_CLEAR_SECS: u64 = 30;

/// Entry fields written back as Secret Service attributes (KeePassXC maps
/// them onto its UserName / URL / Notes entry fields; Title is the label).
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

enum Cmd {
    Reload,
    /// Run one `cce-keyring-sync sync` pass and reload. The sync logic stays
    /// in the one binary the timer also runs; the UI only invokes it, so the
    /// flock naturally serializes a button press against a timer tick.
    Sync,
    GetSecret { path: String, purpose: Purpose },
    CreateItem { label: String, attrs: Vec<(String, String)>, secret: String },
    UpdateItem { path: String, label: String, attrs: Vec<(String, String)>, secret: Option<String> },
    DeleteItem { path: String },
}

#[derive(Clone, Debug)]
enum AppMessage {
    Loaded(Vec<EntryData>),
    Status(String, bool),
    Revealed { path: String, secret: String },
    SelectPath(String),
    RefreshClicked,
    SyncClicked,
    RevealClicked,
    CopyClicked,
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

/// One pass of the external sync tool. Success reports its own summary line
/// ("synced: … " or "in sync"); refusals — conflicted copies, Dropbox
/// settling, the flock — arrive as the error text, which is exactly the
/// guidance the user needs ("run doctor").
async fn run_sync(tx: &calloop::channel::Sender<AppMessage>) {
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
                let _ = tx.send(AppMessage::Status(msg, false));
            } else {
                let line = pick(&out.stderr);
                let msg = if line.is_empty() { "sync failed".to_string() } else { line };
                let _ = tx.send(AppMessage::Status(msg, true));
            }
        }
        Err(e) => {
            let _ = tx.send(AppMessage::Status(format!("cce-keyring-sync not runnable: {e}"), true));
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
            let ss = match SecretService::connect(EncryptionType::Dh).await {
                Ok(ss) => ss,
                Err(e) => {
                    let _ = tx.send(AppMessage::Status(
                        format!("Secret Service unavailable: {e} — is KeePassXC running with Secret Service integration enabled?"),
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
                        run_sync(&tx).await;
                        load_entries(&ss, &tx).await;
                    }
                    Cmd::GetSecret { path, purpose } => fetch_secret(&ss, &tx, path, purpose).await,
                    Cmd::CreateItem { label, attrs, secret } => {
                        create_item(&ss, &tx, label, attrs, secret).await
                    }
                    Cmd::UpdateItem { path, label, attrs, secret } => {
                        update_item(&ss, &tx, path, label, attrs, secret).await
                    }
                    Cmd::DeleteItem { path } => delete_item(&ss, &tx, path).await,
                }
            }
        });
    });
}

async fn load_entries(ss: &SecretService<'_>, tx: &calloop::channel::Sender<AppMessage>) {
    let _ = tx.send(AppMessage::Status("Loading entries…".to_string(), false));
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
        // Locked collection: unlocking prompts through the daemon (KeePassXC
        // raises its own dialog and this await blocks until it's answered);
        // a refused prompt just skips the collection.
        if col.is_locked().await.unwrap_or(false) {
            let _ = tx.send(AppMessage::Status(
                format!("Unlock \"{label}\" in KeePassXC to load its entries…"),
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
) {
    let status_err = |msg: String| {
        let _ = tx.send(AppMessage::Status(msg, true));
    };
    let item = match resolve_item(ss, &path).await {
        Ok(i) => i,
        Err(e) => return status_err(e),
    };
    let _ = item.ensure_unlocked().await;
    let bytes = match item.get_secret().await {
        Ok(b) => b,
        Err(e) => return status_err(format!("Secret fetch failed: {e}")),
    };
    let secret = String::from_utf8_lossy(&bytes).to_string();
    match purpose {
        Purpose::Copy => {
            cce_ui::widget::clipboard::copy_to_clipboard(&secret);
            let _ = tx.send(AppMessage::Status(
                format!("Secret copied — clipboard clears in {CLIPBOARD_CLEAR_SECS} s"),
                false,
            ));
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(CLIPBOARD_CLEAR_SECS));
                // Only clear if the clipboard still holds our secret.
                if cce_ui::widget::clipboard::read_from_clipboard().as_deref() == Some(secret.as_str()) {
                    cce_ui::widget::clipboard::copy_to_clipboard("");
                }
            });
        }
        Purpose::Reveal => {
            let _ = tx.send(AppMessage::Revealed { path, secret });
        }
    }
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
) {
    let collection = match ss.get_default_collection().await {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(AppMessage::Status(format!("No default collection: {e}"), true));
            return;
        }
    };
    let _ = collection.ensure_unlocked().await;
    let attr_map = attrs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    match collection
        .create_item(&label, attr_map, secret.as_bytes(), false, "text/plain")
        .await
    {
        Ok(item) => {
            let new_path = item.item_path.to_string();
            let _ = tx.send(AppMessage::Status(format!("Created \"{label}\""), false));
            load_entries(ss, tx).await;
            let _ = tx.send(AppMessage::SelectPath(new_path));
        }
        Err(e) => {
            let _ = tx.send(AppMessage::Status(format!("Create failed: {e}"), true));
        }
    }
}

async fn update_item(
    ss: &SecretService<'_>,
    tx: &calloop::channel::Sender<AppMessage>,
    path: String,
    label: String,
    attrs: Vec<(String, String)>,
    secret: Option<String>,
) {
    let item = match resolve_item(ss, &path).await {
        Ok(i) => i,
        Err(e) => {
            let _ = tx.send(AppMessage::Status(e, true));
            return;
        }
    };
    let _ = item.ensure_unlocked().await;
    if let Err(e) = item.set_label(&label).await {
        let _ = tx.send(AppMessage::Status(format!("Saving label failed: {e}"), true));
        return;
    }
    let attr_map = attrs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    if let Err(e) = item.set_attributes(attr_map).await {
        let _ = tx.send(AppMessage::Status(format!("Saving attributes failed: {e}"), true));
        return;
    }
    if let Some(secret) = secret {
        if let Err(e) = item.set_secret(secret.as_bytes(), "text/plain").await {
            let _ = tx.send(AppMessage::Status(format!("Saving secret failed: {e}"), true));
            return;
        }
    }
    let _ = tx.send(AppMessage::Status(format!("Saved \"{label}\""), false));
    load_entries(ss, tx).await;
    let _ = tx.send(AppMessage::SelectPath(path));
}

async fn delete_item(ss: &SecretService<'_>, tx: &calloop::channel::Sender<AppMessage>, path: String) {
    let item = match resolve_item(ss, &path).await {
        Ok(i) => i,
        Err(e) => {
            let _ = tx.send(AppMessage::Status(e, true));
            return;
        }
    };
    match item.delete().await {
        Ok(()) => {
            let _ = tx.send(AppMessage::Status("Entry deleted".to_string(), false));
            load_entries(ss, tx).await;
        }
        Err(e) => {
            let _ = tx.send(AppMessage::Status(format!("Delete failed: {e}"), true));
        }
    }
}

// ── Application ───────────────────────────────────────────────────────────

struct SecretsApp {
    search_box: cce_ui::widget::Adapted<TextBox>,
    refresh_btn: cce_ui::widget::Adapted<Button>,
    sync_btn: cce_ui::widget::Adapted<Button>,
    new_btn: cce_ui::widget::Adapted<Button>,
    reveal_btn: cce_ui::widget::Adapted<Button>,
    copy_btn: cce_ui::widget::Adapted<Button>,
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

    /// The DRAWN list offset — `scroll_motion` glides it (wheel) or coasts
    /// it (trackpad flick); direct writes (Escape reset, clamp) are adopted
    /// by the motion on its next step.
    scroll_y: f32,
    scroll_motion: ScrollMotion,
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
        let attrs: Vec<(String, String)> = EDIT_ATTRS
            .iter()
            .zip(values)
            .filter(|(_, v)| !v.is_empty())
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
            None => Cmd::CreateItem { label: title, attrs, secret: password },
        })
    }

    /// "synced 4m ago" from cce-keyring-sync's state file, refreshed at most
    /// every 5s — the timer runs every 15 minutes, so staleness is invisible.
    fn refresh_sync_hint(&mut self) {
        if self.sync_hint_at.is_some_and(|t| t.elapsed().as_secs() < 5) {
            return;
        }
        self.sync_hint_at = Some(std::time::Instant::now());
        let path = std::env::var("XDG_STATE_HOME")
            .ok()
            .filter(|s| !s.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".local/state")
            })
            .join("cce/keyring-sync/state.json");
        self.sync_hint = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| v.get("last_run").and_then(|n| n.as_i64()))
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

    fn buttons_mut(&mut self) -> [&mut cce_ui::widget::Adapted<Button>; 9] {
        [
            &mut self.refresh_btn,
            &mut self.sync_btn,
            &mut self.new_btn,
            &mut self.reveal_btn,
            &mut self.copy_btn,
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
    btn.set_rect(-1000.0, -1000.0, BTN_W, BTN_H);
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
            refresh_btn: Button::new(0.0, 0.0, BTN_W, BTN_H).with_label("Refresh"),
            sync_btn: Button::new(0.0, 0.0, BTN_W, BTN_H).with_label("Sync"),
            new_btn: Button::new(0.0, 0.0, BTN_W, BTN_H).with_label("New"),
            reveal_btn: Button::new(0.0, 0.0, BTN_W, BTN_H).with_label("Reveal"),
            copy_btn: Button::new(0.0, 0.0, BTN_W, BTN_H).with_label("Copy"),
            edit_btn: Button::new(0.0, 0.0, BTN_W, BTN_H).with_label("Edit"),
            delete_btn: Button::new(0.0, 0.0, BTN_W, BTN_H).with_label("Delete"),
            save_btn: Button::new(0.0, 0.0, BTN_W, BTN_H).with_label("Save"),
            cancel_btn: Button::new(0.0, 0.0, BTN_W, BTN_H).with_label("Cancel"),
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
            scroll_y: 0.0,
            scroll_motion: ScrollMotion::new(),
            list_rect: (PAD, PAD + 38.0, LIST_W, 0.0),
            pointer: (0.0, 0.0),
            hover_row: None,
            status_msg: "Connecting to Secret Service…".to_string(),
            status_is_error: false,
            sync_hint: String::new(),
            sync_hint_at: None,
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
                self.scroll_y = self.scroll_y.clamp(0.0, self.max_scroll());
                self.status_msg = if self.entries.is_empty() {
                    "No entries — expose a KeePassXC group via Tools → Settings → Secret Service Integration".to_string()
                } else {
                    format!("{} entries", self.entries.len())
                };
                self.status_is_error = false;
            }
            AppMessage::Status(msg, is_error) => {
                self.status_msg = msg;
                self.status_is_error = is_error;
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

        quad(&mut pc, 0.0, 0.0, sw, sh, cce_ui::colors::CONTENT_BG);

        // ── Left panel: search + entry list ──
        self.search_box.set_rect(PAD, PAD, LIST_W, 30.0);
        self.refresh_btn.set_rect(sw - PAD - BTN_W, PAD, BTN_W, BTN_H);
        self.new_btn.set_rect(sw - PAD - BTN_W * 2.0 - 10.0, PAD, BTN_W, BTN_H);
        self.sync_btn.set_rect(sw - PAD - BTN_W * 3.0 - 20.0, PAD, BTN_W, BTN_H);

        let list_y = PAD + 38.0;
        let list_h = (sh - list_y - STATUS_H - 8.0).max(0.0);
        self.list_rect = (PAD, list_y, LIST_W, list_h);
        quad(&mut pc, PAD, list_y, LIST_W, list_h, cce_ui::color::list_bg_color());

        let filtered = self.filtered();
        let list_bounds = Some([PAD, list_y, PAD + LIST_W, list_y + list_h]);
        for (row, &ei) in filtered.iter().enumerate() {
            let ry = list_y + row as f32 * ROW_H - self.scroll_y;
            if ry + ROW_H < list_y || ry > list_y + list_h {
                continue;
            }
            let entry = &self.entries[ei];
            let is_selected = self.selected.as_deref() == Some(entry.path.as_str());
            if is_selected {
                quad(&mut pc, PAD, ry, LIST_W, ROW_H, [0.10, 0.28, 0.17, 1.0]);
            } else if self.hover_row == Some(row) {
                quad(&mut pc, PAD, ry, LIST_W, ROW_H, [1.0, 1.0, 1.0, 0.04]);
            }
            pc.text_with(
                entry.label.clone(),
                PAD + 12.0,
                ry + 8.0,
                12.0,
                srgb_u8(cce_ui::colors::TEXT_HEADER),
                None,
                list_bounds,
            );
            if let Some(hint) = entry.hint() {
                pc.text_with(
                    hint.to_string(),
                    PAD + 12.0,
                    ry + 25.0,
                    10.0,
                    srgb_u8(cce_ui::colors::TEXT_DIM),
                    None,
                    list_bounds,
                );
            }
        }

        // Scrollbar (wheel-driven; thumb is display-only).
        let content_h = filtered.len() as f32 * ROW_H;
        if content_h > list_h {
            let sb_w = 4.0;
            let sb_x = PAD + LIST_W - sb_w - 3.0;
            let visible_ratio = list_h / content_h;
            let thumb_h = (list_h * visible_ratio).clamp(20.0, list_h);
            let scroll_ratio = if self.max_scroll() > 0.0 { self.scroll_y / self.max_scroll() } else { 0.0 };
            let thumb_y = list_y + scroll_ratio * (list_h - thumb_h);
            quad(&mut pc, sb_x, list_y, sb_w, list_h, cce_ui::color::scrollbar_track_color());
            quad(&mut pc, sb_x, thumb_y, sb_w, thumb_h, cce_ui::color::scrollbar_thumb_color());
        }

        // ── Right panel: detail view or the entry form ──
        let dx = PAD + LIST_W + 20.0;
        let dw = (sw - dx - PAD).max(0.0);
        let detail_bounds = Some([dx, list_y, dx + dw, list_y + list_h]);
        match &self.mode {
            Mode::Edit { path } => {
                let header = if path.is_some() { "Edit entry" } else { "New entry" };
                pc.text_with(header.to_string(), dx, list_y + 4.0, 15.0, srgb_u8(cce_ui::colors::TEXT_HEADER), None, detail_bounds);
                let labels = ["Title", "UserName", "URL", "Notes", "Password"];
                let mut fy = list_y + 36.0;
                let box_w = (dw - 4.0).min(320.0);
                for (label, tb) in labels.iter().zip(self.form_boxes_mut()) {
                    tb.set_rect(dx, fy + 14.0, box_w, 28.0);
                    pc.text_with(label.to_string(), dx, fy, 10.0, srgb_u8(cce_ui::colors::TEXT_DIM), None, None);
                    fy += 52.0;
                }
                self.save_btn.set_rect(dx, fy + 4.0, BTN_W, BTN_H);
                self.cancel_btn.set_rect(dx + BTN_W + 10.0, fy + 4.0, BTN_W, BTN_H);
                for b in [&mut self.reveal_btn, &mut self.copy_btn, &mut self.edit_btn, &mut self.delete_btn, &mut self.new_btn] {
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
                    pc.text_with(entry.label.clone(), dx, list_y + 4.0, 15.0, srgb_u8(cce_ui::colors::TEXT_HEADER), None, detail_bounds);
                    pc.text_with(entry.collection.clone(), dx, list_y + 26.0, 10.0, srgb_u8(cce_ui::colors::TEXT_DIM), None, detail_bounds);

                    let mut ay = list_y + 56.0;
                    for (key, value) in &entry.attrs {
                        pc.text_with(key.clone(), dx, ay, 10.0, srgb_u8(cce_ui::colors::TEXT_DIM), None, detail_bounds);
                        pc.text_with(value.clone(), dx + 120.0, ay, 11.0, srgb_u8(cce_ui::colors::TEXT_FG), None, detail_bounds);
                        ay += 22.0;
                    }

                    ay += 8.0;
                    pc.text_with("secret".to_string(), dx, ay, 10.0, srgb_u8(cce_ui::colors::TEXT_DIM), None, detail_bounds);
                    let (secret_text, revealed) = match self.revealed_secret() {
                        Some(s) => (s.to_string(), true),
                        None => ("••••••••••••".to_string(), false),
                    };
                    pc.text_with(secret_text, dx + 120.0, ay, 11.0, srgb_u8(cce_ui::colors::TEXT_FG), None, detail_bounds);

                    self.reveal_btn.set_label(if revealed { "Hide" } else { "Reveal" });
                    self.delete_btn.set_label(
                        if self.pending_delete.as_deref() == Some(entry.path.as_str()) { "Confirm" } else { "Delete" },
                    );
                    self.reveal_btn.set_rect(dx, ay + 28.0, BTN_W, BTN_H);
                    self.copy_btn.set_rect(dx + BTN_W + 10.0, ay + 28.0, BTN_W, BTN_H);
                    self.edit_btn.set_rect(dx, ay + 28.0 + BTN_H + 8.0, BTN_W, BTN_H);
                    self.delete_btn.set_rect(dx + BTN_W + 10.0, ay + 28.0 + BTN_H + 8.0, BTN_W, BTN_H);
                } else {
                    let hint = if self.entries.is_empty() { "" } else { "Select an entry" };
                    pc.text_with(hint.to_string(), dx, list_y + 4.0, 11.0, srgb_u8(cce_ui::colors::TEXT_DIM), None, detail_bounds);
                    for b in [&mut self.reveal_btn, &mut self.copy_btn, &mut self.edit_btn, &mut self.delete_btn] {
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
            PAD,
            sh - STATUS_H + 6.0,
            10.0,
            status_color,
            None,
            Some([PAD, sh - STATUS_H, sw - PAD, sh]),
        );
        self.refresh_sync_hint();
        if !self.sync_hint.is_empty() {
            let w = cce_ui::widget::display::measure_text_width(&self.sync_hint, &cce_ui::layout::read_preferred_fonts().0, 10.0);
            pc.text_with(
                self.sync_hint.clone(),
                sw - PAD - w,
                sh - STATUS_H + 6.0,
                10.0,
                srgb_u8(cce_ui::colors::TEXT_DIM),
                None,
                Some([PAD, sh - STATUS_H, sw - PAD, sh]),
            );
        }

        Some(pc.finish())
    }

    fn display_list_text(&self) -> bool {
        true
    }

    fn handle_pointer_move(&mut self, pos: LogicalPosition, needs_rebuild: &mut bool) {
        self.pointer = (pos.x, pos.y);
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
                        self.scroll_y = 0.0;
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
        self.scroll_y = self.scroll_y.clamp(0.0, self.max_scroll());
        None
    }
}

fn main() {
    env_logger::init();
    cce_ui::engine::run::<SecretsApp>();
}
