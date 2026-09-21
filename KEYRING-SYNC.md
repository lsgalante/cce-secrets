# Scoping: cce-keyring-sync — passwords synced across machines, cce-native UI here

Status: **phase 1 shipped** (2026-08-31) — `cce-keyring-sync import` with
`--dry-run`, `status`, the state file, quiescence + conflicted-copy detection.
Verified end to end in an isolated `dbus-run-session` keyring against a fixture
kdbx: create, idempotent re-run, update, secret round-trip, and a state file
holding only keyed hashes. Phase 2 shipped the same day: `sync`
(the full three-way merge), `doctor`, and the 15-minute timer units. The whole
merge table was exercised in an isolated keyring — kdbx→keyring edit, keyring
deletion → kdbx Recycle Bin (verified in keepassxc-cli's own listing), new
entries both directions, adoption of a keyring-born entry with UUID stamping,
conflicted-copy refusal, and doctor merging a staged conflict whose entry then
synced through. Files written by the `keepass` crate re-open in keepassxc-cli,
and pre-KDBX4 databases are upgraded loudly on first write. Phase 3 shipped: a Sync button in
cce-secrets (runs the same binary the timer runs, so the flock serializes a
click against a timer tick; its summary or refusal text lands in the status
line, and the list reloads after), plus a right-aligned "synced Nm ago" hint
read from the sync state file. **Next: replacing the kdbx with 1Password as the
interchange — scoped at the bottom of this file (2026-09-21).**

## Goal

cce-secrets becomes the only password UI on this machine, without giving up
cross-machine sync. Concretely:

- **gnome-keyring stays the live store** on this machine — it already owns
  `org.freedesktop.secrets`, is PAM-unlocked at login, and is what cce-secrets
  fronts today.
- **The Dropbox kdbx stays the interchange**: `~/Dropbox/Codes/Passwords.kdbx`,
  usable from other machines and phones with ordinary KeePass apps, unchanged.
- **`cce-keyring-sync`** is a small non-resident tool that merges the two.
- **KeePassXC retires on this machine only.** Elsewhere it keeps working against
  the same file; that is a feature of choosing kdbx as the interchange, not a
  compromise.

Explicitly not the goal: replacing the Secret Service provider (route rejected —
a hand-rolled secrets daemon is weeks of security-critical work for the same
user-visible result), syncing kdbx attachments/history (they stay kdbx-side,
untouched), or any resident process holding the Dropbox file open — a daemon
with the kdbx open all day is precisely what produced the old sync grief.

## The evidence this design answers

Next to the main kdbx sit **two Dropbox conflicted copies right now** — one
labelled `archlinux… 2026-08-28`. The write-loss hazard is not hypothetical; it
has already happened, and whatever diverged in those files may be entries nobody
has missed yet. Handling this is in scope from day one (see `doctor`).

## Shape

A second `[[bin]]` in this crate — it shares the `secret-service` dependency,
and `ccebuild` derives binaries from cargo metadata, so it ships with
`ccebuild install cce-secrets` automatically (never hand-listed anywhere).

```
cce-keyring-sync              # bidirectional sync (the default)
cce-keyring-sync --dry-run    # print the plan, change nothing
cce-keyring-sync import       # first run: kdbx -> keyring (the 168 entries)
cce-keyring-sync status       # last sync, pending differences, hazards
cce-keyring-sync doctor       # reconcile Dropbox conflicted copies
```

State lives in `~/.local/state/cce/keyring-sync/state.json`: a per-entry
snapshot of the last synced state (UUID, timestamps, **keyed hashes of fields —
never values**; the hash key is itself a keyring item, so the state file alone
leaks nothing). The state file is what turns two-way comparison into a real
three-way merge, and it is local — never in Dropbox.

## Pairing and field mapping

- kdbx entries have UUIDs; keyring items get a `kdbx-uuid` attribute. Entries
  born in cce-secrets (no UUID yet) get one minted at first sync.
- Everything lands in the **`login` collection** — the one PAM unlocks. Other
  collections would mean separate unlock prompts, defeating the point. The kdbx
  group path is recorded as a `kdbx-group` attribute (cce-secrets can filter on
  it later); it is not mapped to collections.
- Fields, matching what KeePassXC's own Secret Service bridge used — the exact
  mapping cce-secrets' code comments already assume:
  Title ↔ label, Password ↔ the secret, UserName / URL / Notes ↔ attributes.
- **TOTP seeds do not go to attributes** — Secret Service attributes are
  searchable metadata, not secret storage. v1 leaves `otp` fields kdbx-side
  untouched; if TOTP should move into the DE, that is `cce-authenticator`'s
  door to knock on, as its own decision.

## The merge, precisely

Three-way, with the state file as base. Per entry:

| kdbx since base | keyring since base | action |
| --- | --- | --- |
| changed | unchanged | → keyring |
| unchanged | changed | → kdbx |
| changed | changed | **newer modification time wins**; the losing value is written into the kdbx entry's native History, so nothing is destroyed |
| deleted | unchanged | delete from keyring |
| unchanged | deleted | move to the kdbx Recycle Bin group (not purged) |
| deleted | changed (or vice versa) | **modification beats deletion** — the entry is resurrected; for passwords, the failure mode of a wrong resurrect is annoyance, of a wrong delete is lockout |

Timestamps: kdbx `LastModificationTime` vs the service's own `Modified`
(exposed by `secret-service 5.1.0` — verified). Compared with a skew tolerance;
a true tie is logged and the kdbx side wins, arbitrarily but documented.

## Dropbox discipline

- **Open briefly, atomically**: read once → merge in memory → write to a temp
  file in the same directory → fsync → rename. Rename is the pattern Dropbox
  tolerates best.
- **Quiescence check**: refuse to start if the kdbx mtime moved in the last few
  seconds; re-hash before the final rename and abort if the file changed under
  us (retry next run).
- **Conflicted-copy detection**: any `*conflicted copy*.kdbx` sibling → normal
  sync refuses and points at `doctor`.
- `doctor` merges conflicted copies into the main kdbx via **`keepassxc-cli
  merge`** (battle-tested; present at `/usr/sbin/keepassxc-cli`) with a backup
  of everything first, then archives the conflict files. Its first real job is
  the two copies that already exist. (The `keepass` crate's own `_merge` feature
  is underscore-experimental — not trusted with this.)
- **Never invoke `dropbox status`** — no CLI exists on this machine and the
  binary spawns a second daemon (documented prior incident).
- Concurrency: an flock on the state file, so a timer run and a manual run
  cannot interleave.

## Unlock and bootstrap

The kdbx master password is stored as a keyring item; sync reads it at runtime,
so it runs unattended once the keyring is unlocked — which PAM does at login.
Entered once, on first run. If the database also uses a keyfile (the old
`cce-keyring-unlock-setup <user> <database.kdbx> [keyfile]` signature suggests
it may), its path is stored alongside — **open question below.**

The kdbx KDF (argon2) costs real CPU per open; at a timer cadence of minutes
that is irrelevant, and there is no resident unlock to keep warm.

## Library facts (checked 2026-08-31)

- `keepass` 0.13.25, updated 2026-08-30, 400k downloads; `save_kdbx4` is a
  first-class feature. Read+write of the real database goes through it.
- `secret-service` 5.1.0 (already this crate's dependency) exposes
  `get_modified()`. Sessions should use `EncryptionType::Dh` so secrets do not
  cross the bus in the clear.
- Fallback and doctor's merge engine: `keepassxc-cli`.

## Risks, ranked

1. **A merge bug eats a password.** The design never destroys a value: losers
   go to kdbx History, deletions to the Recycle Bin, and Dropbox's own file
   versioning backstops the file itself. Plus `--dry-run`, and a journal line
   per action.
2. **A Dropbox race corrupts the kdbx.** Atomic rename + re-hash-before-commit
   makes the window tiny; the residual case (offline edits on two machines) is
   exactly a conflicted copy, which `doctor` owns.
3. **Secret exposure.** Secrets transit only the encrypted bus session and the
   kdbx; the state file holds keyed hashes; logs hold labels, never values.
4. **Timestamp skew across machines** mis-picks a winner. Tolerance + history
   preservation caps the damage at "restore from History".

## Phases

1. **`import` + `--dry-run` + state file** — one-way kdbx → keyring. Ships
   alone; cce-secrets immediately shows the real 168 entries.
2. **Bidirectional sync + `doctor` + systemd user timer** (15 min, jittered).
   Reconcile the two existing conflicted copies as its acceptance test.
3. **cce-secrets UI**: a Sync action and status line; KeePassXC removed from
   this machine's session.

## Open questions

1. Does `Passwords.kdbx` use a keyfile in addition to the master password?
2. Merge policy sign-off: "newer wins, loser to History; modification beats
   deletion" — acceptable?
3. Timer cadence, and whether sync should also fire on cce-secrets edits.

---

# Scoping: 1Password as the interchange (option 1, 2026-09-21)

Status: **complete (2026-09-21).** The resident daemon is the
`cce-keyring-sync.service` unit, ticking every five minutes against the
Personal vault; the kdbx backend, `import`, `doctor`, the `keepass`
dependency and the stored master password are gone. Everything above this
line up to "Scoping: 1Password as the interchange" describes the retired
kdbx design and is kept as history. Results per phase at the end.

## Goal

Swap the kdbx for 1Password in the role the kdbx plays above: the
cross-machine interchange. Everything downstream stays exactly as it is —
gnome-keyring remains the live store, cce-secrets keeps fronting it, and
cce-browser's account autocomplete (`cce-browser/src/accounts.rs`, a second
Secret Service client) needs **zero changes**. The only code that learns
about 1Password is `cce-keyring-sync`, which grows a second backend.

Why this door and not another (checked 2026-09-20):

- **1Password for Linux is a Secret Service *client*, not a provider.** It
  stores its own unlock material in gnome-keyring and never puts vault items
  on `org.freedesktop.secrets`. So nothing either crate does today can see a
  1Password item, and no setting changes that.
- **The browser extension route is closed.** 1Password's browser side is a
  Chrome/Firefox/Safari extension over native messaging; WPE WebKit has no
  extension support.
- **The official SDKs are Go, JavaScript and Python** (desktop auth over a
  Unix socket; no Rust SDK, official or blessed). From Rust the honest path
  is a subprocess around the `op` CLI, which has the same desktop-app
  authentication.
- The alternative — a store trait in both cce-secrets and cce-browser with a
  1Password implementation — keeps 1Password the sole store but makes every
  reveal wait on a polkit prompt and touches both crates. Rejected for now;
  the mirror is the drop-in for the design already shipped above.

The trade being made, stated plainly: every password is mirrored into the
session-unlocked keyring, and 1Password's per-fetch approval is lost. That is
the posture this machine has had since phase 1 with the kdbx — nothing gets
worse, and the kdbx (plus its Dropbox conflicted-copy hazard) goes away.

## Prerequisites (manual, once)

1. `1password` and `1password-cli` from the AUR. The app **requires** a
   Secret Service provider to run at all; gnome-keyring already is one here.
2. In the app: Settings → Security → *Unlock using system authentication*,
   then Settings → Developer → *Integrate with 1Password CLI*. On Linux this
   authenticates through **polkit**, and `cce-authenticator` is this
   session's polkit agent — so the prompt is a native cce window, not a GTK
   dialog that cannot take focus. Verify once that the `op` prompt actually
   reaches it (`pkexec true` does; `op` should look identical to polkit).
3. `op account add` once, interactively. If more than one account ends up
   signed in, the sync passes `--account`.
4. Migrate the data: export the kdbx (`keepassxc-cli export --format csv`)
   into 1Password's importer, then check the count against the 168. TOTP
   seeds: 1Password's importer takes them if the CSV carries them; verify
   on one entry. cce-keyring-sync never touches them either way.

## Shape

`cce-keyring-sync` gets a backend switch. The kdbx code does not go away
until the 1Password path has run clean for a while; both live behind one
`Interchange` trait the merge loop calls:

```rust
trait Interchange {
    fn list(&mut self) -> Result<Vec<RemoteEntry>, String>;  // no secrets
    fn fetch(&mut self, id: &str) -> Result<RemoteEntry, String>; // full entry
    fn create(&mut self, e: &KrEntry) -> Result<String, String>; // -> new id
    fn update(&mut self, id: &str, e: &KrEntry) -> Result<(), String>;
    fn recycle(&mut self, id: &str) -> Result<(), String>;
}
```

`sync` and `import` already work on `KdbxEntry`/`KrEntry` + `Plan`; the
trait is the seam that lets `sync()` stop knowing which side is remote. The
backend is chosen by a `backend "onepassword"` key in the state file (set by
the new `adopt` subcommand, below), not by a flag, so the timer unit does
not change.

Commands become:

```
cce-keyring-sync adopt            # one-time: pair keyring items to 1Password items
cce-keyring-sync adopt --dry-run  # the pairing plan; unmatched on both sides
cce-keyring-sync sync             # unchanged: the three-way merge
cce-keyring-sync status           # unchanged, plus "backend: onepassword"
cce-keyring-sync doctor           # kdbx-only; refuses under the 1Password backend
```

## `op` invocations, exactly

All read paths are JSON over stdout of a child process; **no secret ever
goes on argv** (argv is readable by every same-user process via
`/proc/*/cmdline`; stdout of a pipe is not).

| need | invocation | note |
| --- | --- | --- |
| list | `op item list --categories Login --vault <v> --format json` | ids, titles, `updated_at`, `urls[]`, `additional_information` (= username); **no secrets** |
| full entry | `op item get <id> --format json` | fields with `purpose` USERNAME / PASSWORD / NOTES; `--reveal` is for human output, JSON is plain |
| create | `op item create --format json` with the item JSON **on stdin** | returns the new id |
| update | `op item edit <id>` with the patched item JSON **on stdin** | the template form, never `password=…` assignments on argv |
| recycle | `op item delete <id> --archive` | the Recycle Bin analogue; archived items drop out of `list` |

`list` is one call per run; `get` is called only for items whose
`updated_at` moved since the base snapshot or that have no snapshot yet, so
a quiet run is one `op` process and a few hundred bytes of JSON. That also
keeps the timer's steady state from touching a single secret.

## Pairing and field mapping

Same table as the kdbx, with the id attribute renamed:

| 1Password | keyring |
| --- | --- |
| item `id` | `op-item` attribute (replaces `kdbx-uuid`) |
| `vault.name` | `op-vault` attribute (replaces `kdbx-group`; cce-secrets can filter on it later) |
| `title` | label |
| field purpose USERNAME | `UserName` |
| field purpose PASSWORD | the secret |
| first `urls[]` with `primary: true`, else the first | `URL` |
| field purpose NOTES | `Notes` |

Entries born in cce-secrets (no `op-item`) get created in 1Password at the
next sync and stamped, as kdbx UUIDs are minted today. Which vault new
entries land in is a state-file setting (`vault "Personal"` by default);
several vaults can be mirrored, each entry keeping its `op-vault`.

`adopt` is the migration step the kdbx never needed: the keyring already
holds the 168 entries, and after the CSV import so does 1Password, so the
first run must **pair, not copy**. Match on (title, username), exact and
case-sensitive, with the url as the tiebreaker when that alone is
ambiguous; stamp `op-item`/`op-vault` on the match (the `kdbx-*`
attributes stay until the kdbx backend retires, so an accidental kdbx run
still pairs by uuid instead of re-creating everything); print
every entry unmatched on either side and stop there. Duplicated
(title, username) pairs on either side are refused, listed, and left to the
person — a wrong pairing here silently cross-links two accounts, which is
the one mistake the merge cannot recover from later. Writes a fresh state
snapshot at the end, so the next `sync` has a base.

## The merge, what changes

The table is the same. Three rows get cheaper:

- **Conflict, loser to History:** 1Password records item history on every
  edit server-side, so the loser is already preserved by the winning write.
  No separate history push; the journal still names the loser.
- **Deleted in keyring:** `--archive`, not delete. Recoverable in the app.
- **Deleted in 1Password** (archived or trashed): the item leaves `list`,
  which reads as "deleted since base" exactly as a kdbx removal does today.
  Same "modification beats deletion" resurrection rule.

Timestamps: `updated_at` (RFC 3339, server clock) vs the keyring's
`Modified`. The server clock is better than a Dropbox mtime — no per-machine
skew — but `SKEW_TOLERANCE_SECS` stays, because the keyring side is still
local time.

State file: `entries` keyed by 1Password item id; `EntryState` gains
`op_updated_at` beside the keyed hash. Values still never land in it.

## What the Dropbox discipline becomes

Most of it evaporates — there is no file, so no quiescence check, no
atomic rename, no conflicted copies, and `doctor` has no job. What replaces
it:

- **`op` failures are refusals, not errors.** A non-zero exit or unparseable
  JSON (network down, app locked, prompt dismissed) ends the run with the
  keyring untouched, exit 1, and the timer retries next tick. Never
  half-apply a plan: list, plan, then apply, and any `op` failure mid-apply
  stops the loop and leaves the state snapshot for the entries already
  applied.
- The flock stays; a click on Sync and a timer tick still serialize.
- `op` needs `DBUS_SESSION_BUS_ADDRESS`/`XDG_RUNTIME_DIR` to reach polkit and
  the app's socket; the user unit already has both (it reaches gnome-keyring
  the same way).

## The open problem: authorization from a timer (superseded — see phase 0 results below)

This is the one thing that decides whether the timer survives, and it is
**not documented**: how often `op` re-prompts under desktop-app integration.
The SDK's desktop auth expires after ten minutes idle; if the CLI behaves
the same, a 15-minute timer means a polkit prompt every tick, which is
unacceptable however native the window is. Measure it before anything else
(phase 0). Then, depending on the answer:

- **Prompts once per app unlock** → keep the timer as is.
- **Prompts per idle window** → drop the timer to hourly, and make
  cce-secrets fire a sync after each of its own saves (open question 3
  above, now answered yes), so keyring-side edits still reach 1Password
  promptly and the interactive prompt lands while the person is already
  in the app. A tick that would prompt while the seat is idle is the
  wrong moment; check `loginctl show-session -p IdleHint` and skip.
- A **service account** would run silently, but service accounts cannot
  see the Private/Personal vault, so it would mean moving everything into
  a shared vault. Available, not preferred.

## Risks, ranked

1. **A bad `adopt` pairing cross-links two accounts.** Exact-match only,
   duplicates refused, `--dry-run` first, and the plan is printed in full
   before anything is stamped.
2. **Secret exposure via the subprocess.** Read paths are stdout of a pipe;
   write paths are stdin templates; argv never carries a value; the journal
   holds titles. `op` itself may log — check `~/.config/op` after the first
   write for anything it persisted.
3. **The `op` prompt does not reach `cce-authenticator`.** Then every timer
   run blocks until polkit times it out. Phase 0 catches it.
4. **`updated_at` moves without a field change** (1Password re-saving an
   item on its own, e.g. after a client upgrade). Harmless: the entry is
   fetched, hashes equal, `InSync`. Costs one `get`.
5. **Two machines editing the same item** is now 1Password's problem, not
   Dropbox's — the server has one copy and item history. The residual
   conflict is keyring-vs-1Password, which the merge table already owns.

## Phases

0. **Measure.** ~~Install, integrate, run `op item list` from a terminal and
   from a `systemd-run --user` unit; time how long the authorization lasts
   and whether the prompt appears in `cce-authenticator`.~~ **Done 2026-09-21,
   results below.** The timer is dead; the daemon replaces it.
1. ~~**`Interchange` trait + `OnePassword` backend + `adopt --dry-run`.**~~
   **Done 2026-09-21** (fab49c8, 28c7389); results below. The kdbx backend
   did *not* move behind the trait yet — an unexercised impl is dead code;
   it joins when phase 2 rewires `sync`.
2. ~~**`sync` on the new backend.**~~ **Done 2026-09-21**; results below.
   The table is exercised by `scripts/e2e-1password.sh` (isolated keyring,
   throwaway vault, every pass through one daemon), 19 checks.
3. ~~**Retire the kdbx path** after a month clean~~ **Done 2026-09-21**,
   the same day, on the person's call: the isolated run covered the table
   and the daemon's live passes were quiet. Deleted the backend, `import`,
   `doctor`, the `keepass` and `rpassword` dependencies, the `--kdbx`
   flag, `State.kdbx_path` / `EntryState.kdbx_mtime` (unknown fields are
   ignored on read, so the live base needed no migration), and the
   master-password keyring item. main.rs went from 1198 lines to 242.

## Open questions

1. Which vault(s) to mirror — Personal only, or everything `op item list`
   can read?
2. ~~`adopt` match key: (title, username) exact, or also fall back to URL
   host + username for retitled entries?~~ Answered: url as the tiebreaker
   for duplicate (title, username) only — two Microsoft tenants needed it.
3. Does the CSV round trip carry TOTP seeds, and should
   `cce-authenticator` then read them from 1Password directly (its own
   decision, as before)?

## Phase 0 results (2026-09-21)

Measured with `op` 2.39.0 against 1Password for Linux 8.12.36, CLI
integration on, system authentication on, app unlocked throughout.
Everything below comes from timed calls plus the app's own log
(`~/.config/1Password/logs/1Password_r00000.log`, UTC).

**The integration works, and the JSON is as scoped.** `op item list --format
json` carries `id`, `title`, `updated_at`, `urls[{href,primary}]`, `vault`
and `additional_information` (the username), and no secrets. `op vault
list` shows the one vault, `Personal`.

**Authorization is the app's own "Authorize" dialog, not polkit.** Across
some twenty authorizations neither polkitd nor `cce-authenticator` logged
a line. The "system authentication" setting only governs unlocking the
app; risk 3 above is void. An unanswered dialog times out after **60 s**
and `op` exits 1 with `authorization prompt dismissed, please try again`.

**Authorization is keyed to the caller's parent process, nothing else.**
The app log says it on every request: `no top level process found,
falling back to the caller process`. The consequences, each measured:

| shape | result |
| --- | --- |
| second `op` call under the same parent, 5–20 s later | passes, no dialog |
| new parent 30 s later (a second oneshot unit) | new dialog |
| `setsid` under the same shell | refused (new parent) |
| scrubbed environment, same parent | passes — the environment is irrelevant |
| `op` as a unit's main process (parent = `systemd --user`) | app aborts with `executable path is missing for caller process`; `op` hangs the full 60 s |
| `op` under a shell inside the unit | works like anywhere else |
| private `--config` dir | still routes through the app; no escape into the non-integrated mode |

So **a oneshot timer run is one dialog per tick**, full stop, and the
timer design above cannot ship.

**The authorization is idle-limited and use extends it.** Under one
long-lived parent: calls 3 minutes apart passed for 12 minutes with no
dialog; a 12-minute gap then produced a fresh dialog. A second run with
calls 5 minutes apart passed for 25 minutes after the click, to the end of the run. That is the
SDK's documented rule (ten minutes of inactivity) applied to the CLI, and
it is the whole design: **a resident parent that calls `op` at least every
few minutes holds its authorization for as long as it lives.**

### What changes in the shape

`cce-keyring-sync` becomes resident under the 1Password backend, as
`cce-keyring-sync daemon`, a systemd user service (`WantedBy=
graphical-session.target`, like the polkit agent), replacing the timer.
The objection to a resident process above was a daemon holding the
Dropbox kdbx open all day; there is no file any more, so it lapses.

- **Tick every 5 minutes.** That is inside the idle window with margin, so
  the tick doubles as the keepalive; a quiet tick is one `op item list`,
  no secrets, a few hundred bytes.
- **One dialog per login session** at the first tick, plus one after any
  gap the tick could not cover — suspend, the app locking (autolock is 60
  minutes here; an `op` call against a locked app is **untested**, open
  question 4), or the app restarting.
- **Back off after a dismissed dialog.** A dialog nobody answers costs a
  60-second hang, and re-offering one every five minutes to an empty chair
  is exactly the annoyance the timer design was rejected for. After
  `authorization prompt dismissed`, the daemon waits for a trigger before
  trying again: the cce-secrets Sync button, a save in cce-secrets, or the
  seat coming back from idle (`loginctl show-session -p IdleHint`). Every
  `op` call runs under a 75-second timeout so a wedged app cannot hang a
  tick.
- **Spawn `op` as a direct child, always**, never via `setsid`,
  `systemd-run`, or a double fork: the authorization is the daemon's pid.
- **cce-secrets pokes the daemon** instead of running the binary: the Sync
  button sends `SIGUSR1` to the unit's main pid (or a line over the usual
  `cce_ui::ipc` socket, if the status line wants a reply). The state file
  and its "synced Nm ago" hint stay as they are. Running `cce-keyring-sync
  sync` by hand still works and prompts its own dialog; the flock keeps
  it from interleaving with the daemon.

The "open problem" section above is answered: the timer cadence question
does not arise, and the seat-idle check moves from "when to prompt" to
"when to retry after a dismissed prompt". The service-account fallback
stays on the shelf.

### Fallback, parked

`op` without the app integration signs in with the account password and
Secret Key, prints a 30-minute session token, and can take the password
on stdin — the same trust posture as the kdbx master password stored in
the keyring today, and no dialogs ever. It needs the integration toggle
off (a private `--config` dir does not escape it, measured) and a manual
`op account add`, which needs the Secret Key and password typed by the
person. Worth knowing if the resident design misbehaves; not preferred,
because it moves the account password into the keyring and gives up the
app's approval entirely.

### Open questions, continued

4. What does an `op` call do against a *locked* app — a system-auth
   (polkit → cce-authenticator) unlock prompt, the Authorize dialog, or a
   plain refusal? Decides what the daemon sees after autolock.
5. What does the app count as a "top level process"? If the daemon could
   present as one, the authorization might be remembered across restarts
   the way it is for a terminal window. Not needed for the design; nice
   if cheap.

## Phase 1 results (2026-09-21)

`cce-keyring-sync adopt --vault Personal` against the live keyring and the
freshly imported vault:

| | |
| --- | --- |
| keyring logins | 171 |
| 1Password logins after cleanup | 172 |
| paired and stamped | **168** |
| 1Password only | 4: 1Password's own account item, `secure.bankofamerica.com` (was in the kdbx Recycle Bin — the CSV export carries the bin), and two test entries |
| keyring only | 3: two `…@cce-mail:default` items cce-mail writes with a `UserName` attribute, and one test entry |
| field drift on a pair | 1 (notes) — base timestamp left unknown so the first sync takes 1Password's value |

The 168 all pair on exact (title, username); four needed the url tiebreaker
(two Microsoft tenants, two xferrecords accounts). The first dry run
refused on 23 import artefacts — Recycle Bin entries the CSV export had
resurrected, eight copies of one test login among them — which were
archived in 1Password by hand; the per-copy report (url, timestamp, id)
is what made that a five-minute job.

Things learned that phase 2 has to carry:

- **The Authorize dialog can be hidden.** It is a 400×370 floating window
  the app raises via xdg-activation at the same origin as its main window;
  when the main window was opened later it sat on top, and three dialogs
  in a row timed out unseen while the app log showed each one shown. Focus
  went to the dialog; the compositor did not raise it. Filed against
  cce-compositor. Until fixed: keep the main 1Password window closed or
  moved when a sync is expected to prompt.
- **`1Password Account (…)` must never be mirrored.** It is the item
  1Password creates for the account itself — Secret Key and account
  password inside. The sync's "1Password only → keyring" rule would copy
  it into gnome-keyring. Phase 2 skips it (title prefix `1Password
  Account`; better, its `category` if the list ever distinguishes it).
- **cce-mail's keyring items look like logins** (they carry `UserName`),
  so the sync will create them in 1Password at the first run, as the kdbx
  sync adopted them before (that is where the `…@cce-email:default`
  debris in the CSV came from). Either accept that — mail passwords in
  1Password are not wrong — or have phase 2 exclude items whose label
  matches `*@cce-mail:*`. Decide before the first real sync.
- **The old binary must never see the new state.** The version-2 base is
  keyed by item id; the kdbx `sync` reading it would treat every kdbx
  entry as never seen and re-create all of them in the keyring. Hence the
  install-before-adopt order, the `backend` guard in every kdbx path, and
  the backup `state.json.kdbx-<ts>` for a rollback (restore it and
  re-enable the timer; the stamps are harmless to the kdbx path).
- The cce-secrets Sync button now runs a `sync` that refuses; its status
  line shows the refusal text until the daemon lands.

## Phase 2 results (2026-09-21)

Shipped: `sync.rs` (the merge against the `Interchange` trait, keyed by
item id), `daemon.rs` (the resident loop), the `cce-keyring-sync.service`
unit replacing the timer, and cce-secrets' Sync button and saves poking
the daemon with `SIGUSR1` (falling back to the one-shot when no daemon
runs). The kdbx `sync` in main.rs is untouched and unreachable under the
1Password backend; it and the `keepass` dependency go in phase 3.

The first live pass mirrored the four 1Password-only entries into the
keyring (the account item excluded), created the three keyring-only ones
in 1Password (the cce-mail credentials, kept by decision), and took
1Password's notes on the one drifted pair. 174 entries in the base.

`scripts/e2e-1password.sh` runs the table end to end: mirror, idempotent
quiet pass (one `op item list`, zero fetches), edit each way, keyring-born
create with stamp, remote-born mirror, keyring delete → Archive, Archive →
keyring delete, both conflict directions, modification-beats-deletion
resurrecting as a new item with a restamp, a simulated mid-apply `op`
failure that leaves the rest for the next run, and a value-free state
file. 19 of 19.

What it found, and what was changed for it:

- **`op` prints two timestamp forms.** `item list` gives UTC to the
  second (`…T16:27:42Z`); `item get` and `item edit` give local time with
  an offset and nanoseconds (`…T12:27:42.39627885-04:00`). The parser
  takes both and the base stores the canonical UTC form, or a written
  entry would never match the list again and be fetched every tick. The
  base timestamp is also refreshed whenever an in-sync entry's list value
  differs — the server may stamp a write a second after the reply.
- **A remote edit needs a moment.** Listing right after `op item edit`
  can still show the previous `updated_at` (the app pushes
  asynchronously); in a conflict that flips the winner. Real edits arrive
  from other devices minutes old; the test waits two seconds.
- **Two keyring items with one stamp** (a tool that re-creates instead of
  editing — `secret-tool store` does exactly that, adding its own
  `xdg:schema` attribute so it never replaces) are resolved to the most
  recently modified one.
- **`op item get` resolves archived ids**, so "still live" is a question
  for the list, not `get`.

Open question 4 (a locked app) is still open; the daemon's back-off is
what happens in the meantime. Question 5 (the "top level process" the app
looks for) is unneeded now.

## Phase 3 results (2026-09-21)

`cce-keyring-sync` is now `adopt`, `sync`, `daemon`, `status` — 1,830
lines across main.rs, op.rs, sync.rs, adopt.rs, daemon.rs, with 19 unit
tests and `scripts/e2e-1password.sh` for the table. The kdbx file in
Dropbox is untouched and still serves other machines and phones; nothing
here reads or writes it any more. The `kdbx-uuid` / `kdbx-group`
attributes remain on the 168 adopted keyring items as inert history. The
kdbx-era base is at `state.json.kdbx-1790007276` beside the live state
file, should anyone want the old pairing back.

Rolling back to the kdbx design would mean checking out 0bac2e9^ and
re-importing the master password; the design above documents how that
worked. Nothing in cce-secrets or cce-browser changed shape in any phase:
both still front gnome-keyring over the Secret Service, which was the
point of choosing a mirror.

Still open: question 4, what an `op` call sees against a locked app. The
daemon's back-off covers the gap until it is measured.
