# Scoping: cce-keyring-sync — passwords synced across machines, cce-native UI here

Status: **phase 1 shipped** (2026-08-31) — `cce-keyring-sync import` with
`--dry-run`, `status`, the state file, quiescence + conflicted-copy detection.
Verified end to end in an isolated `dbus-run-session` keyring against a fixture
kdbx: create, idempotent re-run, update, secret round-trip, and a state file
holding only keyed hashes. Phases 2–3 (bidirectional sync, `doctor`, timer, UI)
remain scoping.

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
