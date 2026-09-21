//! The interchange seam, and 1Password behind it.
//!
//! KEYRING-SYNC.md ("Scoping: 1Password as the interchange") is the design.
//! Everything 1Password-specific is a child `op` process with JSON on stdout
//! and, for writes, a JSON item template on stdin — **never a value on
//! argv**, which every same-user process can read. Each spawn runs under
//! [`OP_TIMEOUT`]: an unanswered Authorize dialog holds `op` for 60 s before
//! it gives up, and a wedged app must not hold a tick forever.
//!
//! The `Interchange` trait is what the merge loop (sync.rs) calls; 1Password
//! is its only implementation since the kdbx backend retired.

use std::time::Duration;

use serde_json::{json, Value};

/// Longer than the app's own 60-second dialog timeout, so a dismissed
/// prompt reports itself as such instead of as a kill.
pub const OP_TIMEOUT: Duration = Duration::from_secs(75);

/// The text `op` prints when the Authorize dialog timed out unanswered.
const DISMISSED: &str = "authorization prompt dismissed";

/// One remote entry, whole: the six fields the merge hashes plus identity.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct RemoteEntry {
    pub id: String,
    /// 1Password: the vault name (stored keyring-side as `op-vault`).
    pub vault: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    /// Server-side modification time, unix seconds (0 when unparseable).
    pub updated: i64,
    /// `updated` as canonical RFC 3339 UTC text (`2026-09-21T16:27:42Z`),
    /// the form the base snapshot stores. Canonical because `op` itself is
    /// not consistent: `item list` prints UTC to the second, `item get` and
    /// `item edit` print local time with an offset and nanoseconds, and a
    /// base written from one must still match a list read from the other.
    pub updated_raw: String,
}

/// What `list` returns: everything but the secret fields, so a quiet run
/// never touches a password.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct RemoteSummary {
    pub id: String,
    pub vault: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub updated: i64,
    pub updated_raw: String,
}

/// The cross-machine store the keyring is mirrored against.
pub trait Interchange {
    /// Every login the store holds — no secrets.
    async fn list(&mut self) -> Result<Vec<RemoteSummary>, String>;
    /// One entry in full.
    async fn fetch(&mut self, id: &str) -> Result<RemoteEntry, String>;
    /// Store a new entry; returns its id and its timestamp text. `e.id` is ignored.
    async fn create(&mut self, e: &RemoteEntry) -> Result<(String, String), String>;
    /// Overwrite an existing entry's synced fields, leaving the rest alone;
    /// returns the entry's new timestamp text, so the base can record it
    /// without another fetch.
    async fn update(&mut self, e: &RemoteEntry) -> Result<String, String>;
    /// Soft-delete: 1Password's Archive.
    async fn recycle(&mut self, id: &str) -> Result<(), String>;
}

/// True when the error text is the app's dialog timing out — a refusal to
/// back off from, not a fault to log as one.
pub fn is_dismissed(err: &str) -> bool {
    err.contains(DISMISSED)
}

// ───────────────────────────── 1Password ─────────────────────────────

pub struct OnePassword {
    /// Vault to list from and create into. Empty means every vault `op`
    /// can read; creates then need a name, so `create` refuses.
    pub vault: String,
    /// `--account`, for a person with several signed in. Empty: op's default.
    pub account: String,
}

impl OnePassword {
    pub fn new(vault: &str) -> Self {
        OnePassword { vault: vault.to_string(), account: String::new() }
    }

    /// Spawn `op` as a direct child (the authorization is keyed to *our*
    /// pid as its parent — never via a shell, setsid, or a double fork),
    /// feed `stdin`, and return stdout. Stderr's last line is the error.
    async fn run(&self, args: &[&str], stdin: Option<Vec<u8>>) -> Result<Vec<u8>, String> {
        use tokio::io::AsyncWriteExt;
        let mut cmd = tokio::process::Command::new("op");
        cmd.args(args).arg("--format").arg("json").arg("--no-color");
        if !self.account.is_empty() {
            cmd.arg("--account").arg(&self.account);
        }
        cmd.stdin(if stdin.is_some() { std::process::Stdio::piped() } else { std::process::Stdio::null() })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| format!("op not runnable: {e}"))?;
        if let Some(bytes) = stdin {
            let mut pipe = child.stdin.take().expect("piped stdin");
            // A closed pipe (op exited early) is reported by wait, not here.
            let _ = pipe.write_all(&bytes).await;
            drop(pipe);
        }
        let out = match tokio::time::timeout(OP_TIMEOUT, child.wait_with_output()).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => return Err(format!("op failed to run: {e}")),
            Err(_) => return Err(format!("op timed out after {}s (app wedged?)", OP_TIMEOUT.as_secs())),
        };
        if out.status.success() {
            return Ok(out.stdout);
        }
        let err = String::from_utf8_lossy(&out.stderr);
        let last = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim();
        // op prefixes "[ERROR] 2026/09/21 10:15:39 "; keep what follows.
        let msg = last.splitn(4, ' ').nth(3).unwrap_or(last);
        Err(format!("op {}: {msg}", args.first().copied().unwrap_or("")))
    }

    async fn run_json(&self, args: &[&str], stdin: Option<Vec<u8>>) -> Result<Value, String> {
        let bytes = self.run(args, stdin).await?;
        serde_json::from_slice(&bytes).map_err(|e| format!("op {}: unparseable JSON: {e}", args.join(" ")))
    }
}

impl Interchange for OnePassword {
    async fn list(&mut self) -> Result<Vec<RemoteSummary>, String> {
        let mut args = vec!["item", "list", "--categories", "Login"];
        if !self.vault.is_empty() {
            args.extend(["--vault", self.vault.as_str()]);
        }
        let v = self.run_json(&args, None).await?;
        let items = v.as_array().ok_or("op item list: not an array")?;
        Ok(items.iter().map(summary_from_json).collect())
    }

    async fn fetch(&mut self, id: &str) -> Result<RemoteEntry, String> {
        let v = self.run_json(&["item", "get", id], None).await?;
        Ok(entry_from_json(&v))
    }

    async fn create(&mut self, e: &RemoteEntry) -> Result<(String, String), String> {
        if self.vault.is_empty() {
            return Err("no vault configured for new entries (adopt --vault <name>)".into());
        }
        let template = serde_json::to_vec(&create_template(e)).unwrap();
        let v = self
            .run_json(&["item", "create", "--vault", self.vault.as_str(), "-"], Some(template))
            .await?;
        let id = v.get("id").and_then(Value::as_str).ok_or("op item create: no id in reply")?;
        Ok((id.to_string(), updated_of(&v).1))
    }

    async fn update(&mut self, e: &RemoteEntry) -> Result<String, String> {
        // Round-trip the whole item so sections, custom fields and tags
        // survive; only the synced fields are rewritten.
        let mut v = self.run_json(&["item", "get", &e.id], None).await?;
        apply_entry(&mut v, e);
        let body = serde_json::to_vec(&v).unwrap();
        let reply = self.run_json(&["item", "edit", &e.id], Some(body)).await?;
        Ok(updated_of(&reply).1)
    }

    async fn recycle(&mut self, id: &str) -> Result<(), String> {
        // `delete --archive` prints nothing; run, not run_json.
        self.run(&["item", "delete", id, "--archive"], None).await.map(|_| ())
    }
}

// ───────────────────────────── JSON shapes ─────────────────────────────
//
// Captured from op 2.39.0 (2026-09-21). `item list` gives id, title,
// vault{id,name}, category, urls[{href,primary}], additional_information
// (the username for logins), created_at, updated_at. `item get` adds
// fields[{id,type,purpose,label,value,…}] with purpose USERNAME / PASSWORD /
// NOTES; a NOTES field with no value has no `value` key at all.

fn s(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn primary_url(v: &Value) -> String {
    let Some(urls) = v.get("urls").and_then(Value::as_array) else { return String::new() };
    urls.iter()
        .find(|u| u.get("primary").and_then(Value::as_bool) == Some(true))
        .or_else(|| urls.first())
        .map(|u| s(u, "href"))
        .unwrap_or_default()
}

fn field_by_purpose<'a>(v: &'a Value, purpose: &str) -> Option<&'a Value> {
    v.get("fields")?
        .as_array()?
        .iter()
        .find(|f| f.get("purpose").and_then(Value::as_str) == Some(purpose))
}

/// The (unix, canonical text) pair for an item's `updated_at`.
pub fn updated_of(v: &Value) -> (i64, String) {
    match parse_rfc3339(&s(v, "updated_at")) {
        Some(t) => (t, format_rfc3339(t)),
        None => (0, String::new()),
    }
}

pub fn summary_from_json(v: &Value) -> RemoteSummary {
    let (updated, updated_raw) = updated_of(v);
    RemoteSummary {
        id: s(v, "id"),
        vault: v.get("vault").map(|x| s(x, "name")).unwrap_or_default(),
        title: s(v, "title"),
        username: s(v, "additional_information"),
        url: primary_url(v),
        updated,
        updated_raw,
    }
}

pub fn entry_from_json(v: &Value) -> RemoteEntry {
    let sum = summary_from_json(v);
    let field = |p: &str| field_by_purpose(v, p).map(|f| s(f, "value")).unwrap_or_default();
    RemoteEntry {
        id: sum.id,
        vault: sum.vault,
        title: sum.title,
        // The field is authoritative; additional_information is its echo.
        username: field("USERNAME"),
        password: field("PASSWORD"),
        url: sum.url,
        notes: field("NOTES"),
        updated: sum.updated,
        updated_raw: sum.updated_raw,
    }
}

/// The Login template `op item template get Login` prints, filled in.
pub fn create_template(e: &RemoteEntry) -> Value {
    let mut t = json!({
        "title": e.title,
        "category": "LOGIN",
        "fields": [
            {"id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username", "value": e.username},
            {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": e.password},
            {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": e.notes},
        ]
    });
    if !e.url.is_empty() {
        t["urls"] = json!([{"label": "website", "primary": true, "href": e.url}]);
    }
    t
}

/// Rewrite the synced fields of a fetched item in place.
pub fn apply_entry(v: &mut Value, e: &RemoteEntry) {
    v["title"] = json!(e.title);
    // The primary URL is replaced (or added); other URLs are left alone.
    let urls = v.get_mut("urls").and_then(Value::as_array_mut);
    match urls {
        Some(list) if !list.is_empty() => {
            let idx = list
                .iter()
                .position(|u| u.get("primary").and_then(Value::as_bool) == Some(true))
                .unwrap_or(0);
            if e.url.is_empty() {
                list.remove(idx);
            } else {
                list[idx]["href"] = json!(e.url);
            }
        }
        _ => {
            if !e.url.is_empty() {
                v["urls"] = json!([{"label": "website", "primary": true, "href": e.url}]);
            }
        }
    }
    let set = |v: &mut Value, purpose: &str, id: &str, kind: &str, value: &str| {
        let fields = v
            .as_object_mut()
            .expect("item object")
            .entry("fields")
            .or_insert_with(|| json!([]));
        let list = fields.as_array_mut().expect("fields array");
        match list.iter_mut().find(|f| f.get("purpose").and_then(Value::as_str) == Some(purpose)) {
            Some(f) => f["value"] = json!(value),
            None => list.push(json!({"id": id, "type": kind, "purpose": purpose, "label": id, "value": value})),
        }
    };
    set(v, "USERNAME", "username", "STRING", &e.username);
    set(v, "PASSWORD", "password", "CONCEALED", &e.password);
    set(v, "NOTES", "notesPlain", "STRING", &e.notes);
}

/// RFC 3339 → unix seconds: `2026-09-21T15:41:14Z`, or with a fraction,
/// or with a `±HH:MM` offset (what `op item get`/`edit` print). Fractions
/// are dropped: the list side only has seconds, and the two must agree.
pub fn parse_rfc3339(t: &str) -> Option<i64> {
    let (date, rest) = t.split_once('T')?;
    let (time, offset_secs) = if let Some(r) = rest.strip_suffix('Z') {
        (r, 0)
    } else {
        let i = rest.rfind(['+', '-'])?;
        let (r, off) = rest.split_at(i);
        let sign = if off.starts_with('-') { -1 } else { 1 };
        let (oh, om) = off[1..].split_once(':')?;
        (r, sign * (oh.parse::<i64>().ok()? * 3600 + om.parse::<i64>().ok()? * 60))
    };
    let mut d = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let time = time.split('.').next()?;
    let mut c = time.split(':').map(|p| p.parse::<i64>().ok());
    let (h, mi, sec) = (c.next()??, c.next()??, c.next()??);
    Some(days_from_civil(y, m, day) * 86400 + h * 3600 + mi * 60 + sec - offset_secs)
}

/// unix seconds → `2026-09-21T16:27:42Z`, the canonical base form.
pub fn format_rfc3339(t: i64) -> String {
    let days = t.div_euclid(86400);
    let rem = t.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

// Howard Hinnant's civil-date algorithms.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST_ITEM: &str = r#"{
        "id": "abc", "title": "Example", "tags": [], "version": 1,
        "vault": {"id": "v1", "name": "Personal"}, "category": "LOGIN",
        "created_at": "2026-09-21T15:41:14Z", "updated_at": "2026-09-21T15:41:14Z",
        "additional_information": "someone",
        "urls": [{"href": "https://old.example.com"}, {"primary": true, "href": "https://example.com"}]
    }"#;

    #[test]
    fn a_list_item_yields_a_summary_with_no_secret() {
        let v: Value = serde_json::from_str(LIST_ITEM).unwrap();
        let s = summary_from_json(&v);
        assert_eq!(s.id, "abc");
        assert_eq!(s.vault, "Personal");
        assert_eq!(s.username, "someone");
        assert_eq!(s.url, "https://example.com", "the primary url wins over the first");
        assert_eq!(s.updated, 1790005274);
        assert_eq!(s.updated_raw, "2026-09-21T15:41:14Z");
    }

    #[test]
    fn a_full_item_reads_its_fields_by_purpose() {
        let mut v: Value = serde_json::from_str(LIST_ITEM).unwrap();
        v["fields"] = json!([
            {"id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username", "value": "someone"},
            {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": "hunter2"},
            {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain"}
        ]);
        let e = entry_from_json(&v);
        assert_eq!(e.password, "hunter2");
        assert_eq!(e.notes, "", "a notes field without a value is empty, not missing");
        assert_eq!(e.username, "someone");
    }

    #[test]
    fn a_missing_url_list_is_empty() {
        let v: Value = json!({"id": "x", "title": "t", "updated_at": "nope"});
        let s = summary_from_json(&v);
        assert_eq!(s.url, "");
        assert_eq!(s.updated, 0);
    }

    #[test]
    fn the_create_template_matches_op_s_login_shape() {
        let e = RemoteEntry {
            title: "T".into(),
            username: "u".into(),
            password: "p".into(),
            url: "https://x.example".into(),
            notes: "n".into(),
            ..Default::default()
        };
        let t = create_template(&e);
        assert_eq!(t["category"], "LOGIN");
        assert_eq!(t["urls"][0]["primary"], true);
        assert_eq!(t["urls"][0]["href"], "https://x.example");
        let e2 = entry_from_json(&t);
        assert_eq!((e2.title, e2.username, e2.password, e2.url, e2.notes), ("T".into(), "u".into(), "p".into(), "https://x.example".into(), "n".into()));
        let no_url = create_template(&RemoteEntry::default());
        assert!(no_url.get("urls").is_none(), "an empty url adds no urls key");
    }

    #[test]
    fn apply_entry_rewrites_synced_fields_and_keeps_the_rest() {
        let mut v: Value = serde_json::from_str(LIST_ITEM).unwrap();
        v["fields"] = json!([
            {"id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username", "value": "someone"},
            {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": "old"},
            {"id": "custom", "type": "STRING", "label": "pin", "value": "1234", "section": {"id": "s1"}}
        ]);
        let e = RemoteEntry {
            id: "abc".into(),
            title: "Renamed".into(),
            username: "someone".into(),
            password: "new".into(),
            url: "https://new.example.com".into(),
            notes: "added".into(),
            ..Default::default()
        };
        apply_entry(&mut v, &e);
        assert_eq!(v["title"], "Renamed");
        assert_eq!(v["urls"][1]["href"], "https://new.example.com", "the primary url is replaced in place");
        assert_eq!(v["urls"][0]["href"], "https://old.example.com", "other urls survive");
        let got = entry_from_json(&v);
        assert_eq!(got.password, "new");
        assert_eq!(got.notes, "added", "a missing purpose field is appended");
        assert_eq!(v["fields"][2]["value"], "1234", "custom fields survive");
        assert_eq!(v["tags"], json!([]), "unrelated keys survive");
    }

    #[test]
    fn rfc3339_parses_both_forms_op_prints_to_the_same_second() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-09-21T15:41:14Z"), Some(1790005274));
        assert_eq!(parse_rfc3339("2026-09-21T15:41:14.5Z"), Some(1790005274));
        // `op item edit` printed this for the item `op item list` showed as 2026-09-21T16:27:42Z.
        assert_eq!(parse_rfc3339("2026-09-21T12:27:42.39627885-04:00"), parse_rfc3339("2026-09-21T16:27:42Z"));
        assert_eq!(parse_rfc3339("2026-09-21T18:27:42+02:00"), parse_rfc3339("2026-09-21T16:27:42Z"));
        assert_eq!(parse_rfc3339(""), None);
        assert_eq!(parse_rfc3339("nope"), None);
    }

    #[test]
    fn the_canonical_form_round_trips() {
        for t in [0i64, 951782400, 1790005274, 1790008062, 4102444799] {
            assert_eq!(parse_rfc3339(&format_rfc3339(t)), Some(t), "{t}");
        }
        assert_eq!(format_rfc3339(1790005274), "2026-09-21T15:41:14Z");
        assert_eq!(format_rfc3339(951782400), "2000-02-29T00:00:00Z");
        let v: Value = json!({"updated_at": "2026-09-21T12:27:42.39627885-04:00"});
        assert_eq!(updated_of(&v).1, "2026-09-21T16:27:42Z", "a get/edit reply stores as the list form");
    }

    #[test]
    fn a_dismissed_prompt_is_recognised() {
        assert!(is_dismissed("op item list: authorization prompt dismissed, please try again"));
        assert!(!is_dismissed("op item list: account is not signed in"));
    }
}
