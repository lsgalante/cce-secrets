use secret_service::{EncryptionType, SecretService};
use wayland_client::QueueHandle;

use cce_ui::engine::{Application, EngineState, LogicalPosition, LogicalSize, WindowSettings};
use cce_ui::widget::{
    Button, ElementState, Key, KeyEvent, MouseButton, MouseScrollDelta, NamedKey, TextBox,
    WidgetHost,
};

const PAD: f32 = 16.0;
const LIST_W: f32 = 280.0;
const ROW_H: f32 = 44.0;
const STATUS_H: f32 = 30.0;
const CLIPBOARD_CLEAR_SECS: u64 = 30;

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
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Purpose {
    Copy,
    Reveal,
}

enum Cmd {
    Reload,
    GetSecret { path: String, purpose: Purpose },
}

#[derive(Clone, Debug)]
enum AppMessage {
    Loaded(Vec<EntryData>),
    Status(String, bool),
    Revealed { path: String, secret: String },
    RefreshClicked,
    RevealClicked,
    CopyClicked,
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
                    Cmd::GetSecret { path, purpose } => fetch_secret(&ss, &tx, path, purpose).await,
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
    let opath = match zbus::zvariant::OwnedObjectPath::try_from(path.clone()) {
        Ok(p) => p,
        Err(e) => return status_err(format!("Bad item path: {e}")),
    };
    let item = match ss.get_item_by_path(opath).await {
        Ok(i) => i,
        Err(e) => return status_err(format!("Item lookup failed: {e}")),
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

// ── Application ───────────────────────────────────────────────────────────

struct SecretsApp {
    search_box: cce_ui::widget::Adapted<TextBox>,
    refresh_btn: cce_ui::widget::Adapted<Button>,
    reveal_btn: cce_ui::widget::Adapted<Button>,
    copy_btn: cce_ui::widget::Adapted<Button>,

    entries: Vec<EntryData>,
    /// Selected entry's object path (stable across reloads and filtering).
    selected: Option<String>,
    /// Revealed (path, secret); cleared on selection change and reload.
    revealed: Option<(String, String)>,

    scroll_y: f32,
    /// List viewport (x, y, w, h), refreshed each paint for hit-testing.
    list_rect: (f32, f32, f32, f32),
    pointer: (f32, f32),
    hover_row: Option<usize>,

    status_msg: String,
    status_is_error: bool,

    cmd_tx: std::sync::mpsc::Sender<Cmd>,
    cmd_rx: Option<std::sync::mpsc::Receiver<Cmd>>,
    sender: calloop::channel::Sender<AppMessage>,
    ui_context: cce_ui::context::UiContext,
}

impl SecretsApp {
    /// The search box's live content: `edit_buffer` while editing (`text`
    /// only syncs on commit — TextBox landmine).
    fn query_text(&self) -> &str {
        if self.search_box.editing {
            &self.search_box.edit_buffer
        } else {
            &self.search_box.text
        }
    }

    /// Indices into `entries` matching the search box, in display order.
    fn filtered(&self) -> Vec<usize> {
        let query = self.query_text().to_lowercase();
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

    fn row_at(&self, px: f32, py: f32) -> Option<usize> {
        let (lx, ly, lw, lh) = self.list_rect;
        if px < lx || px > lx + lw || py < ly || py > ly + lh {
            return None;
        }
        let row = ((py - ly + self.scroll_y) / ROW_H).floor();
        (row >= 0.0 && (row as usize) < self.filtered().len()).then_some(row as usize)
    }

    fn widgets_iter(&self) -> Vec<&dyn WidgetHost> {
        vec![&self.search_box, &self.refresh_btn, &self.reveal_btn, &self.copy_btn]
    }
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
            refresh_btn: Button::new(0.0, 0.0, 90.0, 28.0).with_label("Refresh"),
            reveal_btn: Button::new(0.0, 0.0, 90.0, 28.0).with_label("Reveal"),
            copy_btn: Button::new(0.0, 0.0, 90.0, 28.0).with_label("Copy"),
            entries: Vec::new(),
            selected: None,
            revealed: None,
            scroll_y: 0.0,
            list_rect: (PAD, PAD + 38.0, LIST_W, 0.0),
            pointer: (0.0, 0.0),
            hover_row: None,
            status_msg: "Connecting to Secret Service…".to_string(),
            status_is_error: false,
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
            AppMessage::RefreshClicked => {
                self.status_msg = "Refreshing…".to_string();
                self.status_is_error = false;
                let _ = self.cmd_tx.send(Cmd::Reload);
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
        }
    }

    fn tick(&mut self, _dt: f32, _needs_rebuild: &mut bool) {}

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
            let (id, ptr) = (self.refresh_btn.id(), self.refresh_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.reveal_btn.id(), self.reveal_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
            let (id, ptr) = (self.copy_btn.id(), self.copy_btn.as_ptr_mut());
            self.ui_context.register_widget(id, ptr);
        }

        let mut pc = cce_ui::scene::paint::PaintCtx::new();
        let quad = |pc: &mut cce_ui::scene::paint::PaintCtx, x: f32, y: f32, w: f32, h: f32, c: [f32; 4]| {
            pc.quad(Rect { x, y, width: w, height: h }, c);
        };

        quad(&mut pc, 0.0, 0.0, sw, sh, cce_ui::colors::CONTENT_BG);

        // ── Left panel: search + entry list ──
        self.search_box.set_rect(PAD, PAD, LIST_W, 30.0);
        self.refresh_btn.set_rect(sw - PAD - 90.0, PAD, 90.0, 28.0);

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

        // ── Right panel: selected entry detail ──
        let dx = PAD + LIST_W + 20.0;
        let dw = (sw - dx - PAD).max(0.0);
        let detail_bounds = Some([dx, list_y, dx + dw, list_y + list_h]);
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
            self.reveal_btn.set_rect(dx, ay + 28.0, 90.0, 28.0);
            self.copy_btn.set_rect(dx + 100.0, ay + 28.0, 90.0, 28.0);
        } else {
            let hint = if self.entries.is_empty() { "" } else { "Select an entry" };
            pc.text_with(hint.to_string(), dx, list_y + 4.0, 11.0, srgb_u8(cce_ui::colors::TEXT_DIM), None, detail_bounds);
            // Parked out of reach so stale rects can't swallow clicks.
            self.reveal_btn.set_rect(-1000.0, -1000.0, 90.0, 28.0);
            self.copy_btn.set_rect(-1000.0, -1000.0, 90.0, 28.0);
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

        Some(pc.finish())
    }

    fn display_list_text(&self) -> bool {
        true
    }

    fn handle_pointer_move(&mut self, pos: LogicalPosition, needs_rebuild: &mut bool) {
        self.pointer = (pos.x, pos.y);
        let mv = cce_ui::widget::Event::PointerMove { x: pos.x, y: pos.y, local_x: pos.x, local_y: pos.y };
        let ctx = &mut self.ui_context;
        if ctx.propagate_event(&mv, self.search_box.id()) { *needs_rebuild = true; }
        if ctx.propagate_event(&mv, self.refresh_btn.id()) { *needs_rebuild = true; }
        if ctx.propagate_event(&mv, self.reveal_btn.id()) { *needs_rebuild = true; }
        if ctx.propagate_event(&mv, self.copy_btn.id()) { *needs_rebuild = true; }

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

        if { let root = self.refresh_btn.id(); self.ui_context.propagate_event(&ev, root) } {
            *needs_rebuild = true;
        }
        if self.refresh_btn.take_click() {
            return Some(AppMessage::RefreshClicked);
        }
        if { let root = self.reveal_btn.id(); self.ui_context.propagate_event(&ev, root) } {
            *needs_rebuild = true;
        }
        if self.reveal_btn.take_click() {
            return Some(AppMessage::RevealClicked);
        }
        if { let root = self.copy_btn.id(); self.ui_context.propagate_event(&ev, root) } {
            *needs_rebuild = true;
        }
        if self.copy_btn.take_click() {
            return Some(AppMessage::CopyClicked);
        }

        let tb = &mut self.search_box;
        if state == ElementState::Pressed && !tb.hit_test(lx, ly, &self.ui_context) {
            tb.unfocus();
        }
        if { let root = tb.id(); self.ui_context.propagate_event(&ev, root) } {
            *needs_rebuild = true;
        }

        if button == MouseButton::Left && state == ElementState::Pressed {
            if let Some(row) = self.row_at(lx, ly) {
                let filtered = self.filtered();
                let path = self.entries[filtered[row]].path.clone();
                if self.selected.as_deref() != Some(path.as_str()) {
                    self.selected = Some(path);
                    self.revealed = None;
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
        let dy = match delta {
            MouseScrollDelta::LineDelta(_, y) => -y * 24.0,
            MouseScrollDelta::PixelDelta(p) => -p.y as f32,
        };
        let old = self.scroll_y;
        self.scroll_y = (self.scroll_y + dy).clamp(0.0, self.max_scroll());
        if (self.scroll_y - old).abs() > 0.01 {
            self.hover_row = self.row_at(self.pointer.0, self.pointer.1);
            *needs_rebuild = true;
        }
    }

    fn handle_key_input(&mut self, event: &KeyEvent, needs_rebuild: &mut bool) -> Option<Self::Message> {
        if event.state == ElementState::Pressed && !event.repeat {
            if let Key::Named(NamedKey::Escape) = event.logical_key {
                if self.search_box.focused(&self.ui_context) {
                    self.search_box.text.clear();
                    self.search_box.edit_buffer.clear();
                    self.search_box.unfocus();
                    self.scroll_y = 0.0;
                    *needs_rebuild = true;
                    return None;
                }
            }
        }
        let kev = cce_ui::widget::Event::KeyInput(event.clone());
        let root = self.search_box.id();
        if self.ui_context.propagate_event(&kev, root) {
            self.scroll_y = self.scroll_y.clamp(0.0, self.max_scroll());
            *needs_rebuild = true;
        }
        None
    }
}

fn main() {
    env_logger::init();
    cce_ui::engine::run::<SecretsApp>();
}
