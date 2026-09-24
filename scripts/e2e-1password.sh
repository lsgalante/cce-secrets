#!/bin/bash
# End-to-end exercise of cce-keyring-sync's 1Password merge table
# (KEYRING-SYNC.md): an isolated gnome-keyring (own session bus, own data
# and state dirs; the live keyring is never touched) against a throwaway
# vault in the signed-in 1Password account, created at the start and
# deleted at the end. Every pass runs through one resident daemon, the
# shape the systemd unit uses.
#
#   scripts/e2e-1password.sh            # B=<binary> VAULT=<name> to override
#   DAEMON_LOG_COPY=/tmp/d.log …        # keep the daemon's output
#
# Needs: the 1Password app unlocked with the CLI integration on, op,
# gnome-keyring-daemon, dbus-launch, gdbus, secret-tool, python3. Raises
# three Authorize dialogs (this script's own op calls, adopt, the daemon)
# — click each; an unanswered one costs a 60 s retry. Lessons kept as
# comments below: `op item get` resolves archived ids, so liveness is
# checked on the list; `secret-tool store` never edits in place (it makes a
# second item with the same stamp), so an "edit" deletes the old item by
# object path first; and a remote edit needs a moment to reach the server
# before the list reflects it.
set -u
B=${B:-$HOME/projects/cce/target/release/cce-keyring-sync}
VAULT=${VAULT:-cce-sync-test}
T=$(mktemp -d /tmp/cce-e2e.XXXX)
# XDG_CONFIG_HOME stays: op finds the app integration through it.
export XDG_DATA_HOME=$T/data XDG_STATE_HOME=$T/state
mkdir -p "$XDG_DATA_HOME/keyrings" "$XDG_STATE_HOME"
pass=0; fail=0
ok(){ echo "  PASS $1"; pass=$((pass+1)); }
bad(){ echo "  FAIL $1"; fail=$((fail+1)); }
step(){ echo; echo "== $1"; }

# --- isolated keyring on a private session bus ---
eval "$(dbus-launch --sh-syntax)"
export DBUS_SESSION_BUS_ADDRESS
mkdir -p "$T/run"; chmod 700 "$T/run"
KR_ENV=$(printf 'x\n' | XDG_RUNTIME_DIR=$T/run gnome-keyring-daemon --unlock --components=secrets --daemonize 2>&1)
sleep 1
KRPID=$(for p in $(pgrep -f gnome-keyring-daemon); do tr "\0" "\n" < /proc/$p/environ 2>/dev/null | grep -q "cce-e2e" && echo $p; done | head -1)
echo "isolated gnome-keyring pid $KRPID"
if ! printf "%s" "p" | secret-tool store --label="probe" probe 1 2>/dev/null; then echo "isolated keyring not usable"; exit 2; fi
secret-tool clear probe 1
echo "keyring ok at $DBUS_SESSION_BUS_ADDRESS (data in $T)"

# --- throwaway vault ---
op vault get "$VAULT" --format json >/dev/null 2>&1 || op vault create "$VAULT" --format json >/dev/null || { echo "vault create failed"; exit 2; }
# start empty
for id in $(op item list --vault "$VAULT" --format json | python3 -c 'import json,sys;print(" ".join(i["id"] for i in json.load(sys.stdin)))'); do op item delete "$id" --vault "$VAULT"; done
mk(){ # title user pass url notes -> id
  op item template get Login | python3 -c '
import json,sys
t=json.load(sys.stdin); a=sys.argv[1:]
t["title"]=a[0]
for f in t["fields"]:
    f["value"]={"USERNAME":a[1],"PASSWORD":a[2],"NOTES":a[4]}[f["purpose"]]
if a[3]: t["urls"]=[{"label":"website","primary":True,"href":a[3]}]
print(json.dumps(t))' "$@" | op item create --vault "$VAULT" --format json - | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])'
}
get(){ op item get "$1" --format json | python3 -c '
import json,sys;d=json.load(sys.stdin)
f={x["purpose"]:x.get("value","") for x in d["fields"] if "purpose" in x}
u=[x["href"] for x in d.get("urls",[]) if x.get("primary")] or [x["href"] for x in d.get("urls",[])] or [""]
print("|".join([d["title"],f.get("USERNAME",""),f.get("PASSWORD",""),u[0],f.get("NOTES","")]))'; }
# `secret-tool clear` skips items that lack its xdg:schema attribute (the
# ones the sync creates), so "delete every item with this stamp" goes
# through D-Bus by object path.
kr_clear(){ for p in $(secret-tool search --all op-item "$1" 2>/dev/null | sed -n 's/^\[\(\/[0-9]*\)\]$/\/org\/freedesktop\/secrets\/collection\/login\1/p'); do gdbus call --session --dest org.freedesktop.secrets --object-path "$p" --method org.freedesktop.Secret.Item.Delete >/dev/null; done; }
kr_path(){ secret-tool search --all op-item "$1" 2>/dev/null | sed -n 's/^\[\(\/[0-9]*\)\]$/\/org\/freedesktop\/secrets\/collection\/login\1/p' | head -1; }
kr_get(){ # by op-item id → title|user|secret|url|notes
  local path; path=$(kr_path "$1"); [ -z "$path" ] && { echo "<none>||||"; return; }
  local attrs; attrs=$(gdbus call --session --dest org.freedesktop.secrets --object-path "$path" --method org.freedesktop.DBus.Properties.Get org.freedesktop.Secret.Item Attributes 2>/dev/null)
  local label; label=$(gdbus call --session --dest org.freedesktop.secrets --object-path "$path" --method org.freedesktop.DBus.Properties.Get org.freedesktop.Secret.Item Label 2>/dev/null | sed -n "s/^(<'\(.*\)'>,)$/\1/p")
  local secret; secret=$(secret-tool lookup op-item "$1" 2>/dev/null)
  python3 - "$label" "$secret" "$attrs" <<'P'
import sys,re
label,secret,attrs=sys.argv[1:4]
def a(k):
    m=re.search(r"'"+re.escape(k)+r"': '((?:[^'\\]|\\.)*)'",attrs); return m.group(1) if m else ""
print("|".join([label,a("UserName"),secret,a("URL"),a("Notes")]))
P
}
kr_count(){ secret-tool search --all op-vault "$VAULT" 2>/dev/null | grep -c '^label' ; }
mkdir -p $T/bin; cat > $T/bin/op <<'W'
#!/bin/bash
# test hook: fail `item edit` while the toggle file exists; pass through otherwise
if [ "$1" = item ] && [ "$2" = edit ] && [ -e "$FAIL_EDIT_TOGGLE" ]; then echo "[ERROR] 2026/01/01 00:00:00 simulated failure" >&2; exit 1; fi
exec /usr/sbin/op "$@"
W
chmod +x $T/bin/op
export FAIL_EDIT_TOGGLE=$T/fail-edit
STATE=$XDG_STATE_HOME/cce/keyring-sync/state.json
last_run(){ python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("last_run",0))' "$STATE" 2>/dev/null || echo 0; }
# One resident daemon for the whole run: its op children share one parent,
# so one Authorize dialog covers every pass. SIGUSR1 = pass now.
PATH=$T/bin:$PATH "$B" daemon > $T/daemon.log 2>&1 &
DPID=$!
sleep 1
# The fixture passwords go through a variable rather than sitting on a
# literal `password=pw-…` line: GitGuardian reported one of those from this
# public repo as an exposed credential, and the pre-commit secret scan keys
# on the same shape.
set_pw(){ op item edit "$1" "password=$2" >/dev/null; }
dump_kr(){ echo "  -- keyring items:"; secret-tool search --all op-vault "$VAULT" 2>/dev/null | grep -E "^\[|^label|attribute.op-item|^modified" | paste - - - - | sed "s/^/     /"; }
sync(){
  local before; before=$(last_run); local n=0
  local mark; mark=$(wc -l < $T/daemon.log)
  kill -USR1 $DPID
  while [ $n -lt 200 ]; do sleep 0.5; n=$((n+1)); [ "$(last_run)" -gt "$before" ] && break; done
  [ $n -ge 200 ] && echo "  (daemon did not finish a pass in 100s)"
  tail -n +$((mark+1)) $T/daemon.log | grep -vE '^$' | tail -4
}

step "0. adopt on an empty keyring seeds the base (vault has 2 items)"
A=$(mk "Alpha" "alice" "pw-a1" "https://alpha.example" "note a")
C=$(mk "Gamma" "carol" "pw-c1" "" "")
"$B" adopt --vault "$VAULT" 2>&1 | tail -4
"$B" status
step "1. first sync mirrors 1Password -> keyring"
sync
[ "$(kr_count)" = 2 ] && ok "2 items landed in the keyring" || bad "keyring has $(kr_count) items"
[ "$(kr_get "$A")" = "Alpha|alice|pw-a1|https://alpha.example|note a" ] && ok "fields intact" || bad "fields: $(kr_get "$A")"
step "2. idempotent: a second pass fetches nothing"
out=$(sync); echo "$out" | grep -q 'in sync (0 fetched)' && ok "in sync, 0 fetched" || bad "$out"
step "3. edit in 1Password -> keyring"
sleep 1; set_pw "$A" pw-a2; sleep 2
sync
[ "$(kr_get "$A" | cut -d'|' -f3)" = "pw-a2" ] && ok "password followed" || bad "keyring pw: $(kr_get "$A")"
step "4. edit in keyring -> 1Password (secret + url)"
sleep 1
kr_clear "$A"; printf "%s" "pw-a3" | secret-tool store --label="Alpha" op-item "$A" op-vault "$VAULT" UserName alice URL "https://alpha2.example" Notes "note a"
sync
[ "$(get "$A")" = "Alpha|alice|pw-a3|https://alpha2.example|note a" ] && ok "1Password followed" || bad "remote: $(get "$A")"
step "5. keyring-born entry is created in 1Password and stamped"
printf "%s" "pw-d1" | secret-tool store --label="Delta" UserName dave URL "https://delta.example" Notes ""
sync
D=$(op item list --vault "$VAULT" --format json | python3 -c 'import json,sys;print(next(i["id"] for i in json.load(sys.stdin) if i["title"]=="Delta"))')
[ -n "$D" ] && [ "$(get "$D")" = "Delta|dave|pw-d1|https://delta.example|" ] && ok "created remotely" || bad "remote Delta: $(get "$D")"
[ "$(kr_get "$D" | cut -d'|' -f1)" = "Delta" ] && ok "stamped with its id" || bad "stamp missing"
step "6. new item in 1Password is mirrored"
E=$(mk "Epsilon" "erin" "pw-e1" "https://eps.example" "n"); sleep 2
sync
[ "$(kr_get "$E" | cut -d'|' -f3)" = "pw-e1" ] && ok "mirrored" || bad "not mirrored"
step "7. delete in keyring -> archived in 1Password"
kr_clear "$C"
sync
op item list --vault "$VAULT" --format json | grep -q "\"$C\"" && bad "Gamma still live" || ok "Gamma gone from the live list"
op item get "$C" --include-archive --format json >/dev/null 2>&1 && ok "Gamma is in the Archive, not deleted" || bad "Gamma not in archive"
step "8. archive in 1Password -> deleted from keyring"
op item delete "$E" --archive; sleep 2
sync
[ -z "$(secret-tool search --all op-item "$E" 2>/dev/null)" ] && ok "Epsilon removed from keyring" || bad "Epsilon still in keyring"
step "9. conflict: both edited, newer wins (keyring, edited last)"
set_pw "$A" pw-a4; sleep 4
kr_clear "$A"; printf "%s" "pw-a5" | secret-tool store --label="Alpha" op-item "$A" op-vault "$VAULT" UserName alice URL "https://alpha2.example" Notes "note a"
sync
[ "$(get "$A" | cut -d'|' -f3)" = "pw-a5" ] && [ "$(kr_get "$A" | cut -d'|' -f3)" = "pw-a5" ] && ok "keyring won, both sides pw-a5" || bad "remote=$(get "$A" | cut -d'|' -f3) keyring=$(kr_get "$A" | cut -d'|' -f3)"
step "10. conflict the other way: 1Password edited last"
kr_clear "$A"; printf "%s" "pw-a6" | secret-tool store --label="Alpha" op-item "$A" op-vault "$VAULT" UserName alice URL "https://alpha2.example" Notes "note a"; sleep 4
set_pw "$A" pw-a7; sleep 2
sync
[ "$(get "$A" | cut -d'|' -f3)" = "pw-a7" ] && [ "$(kr_get "$A" | cut -d'|' -f3)" = "pw-a7" ] && ok "1Password won, both sides pw-a7" || bad "remote=$(get "$A" | cut -d'|' -f3) keyring=$(kr_get "$A" | cut -d'|' -f3)"
step "11. modification beats deletion: archived remotely, edited locally -> recreated"
op item delete "$D" --archive; sleep 2
kr_clear "$D"; printf "%s" "pw-d2" | secret-tool store --label="Delta" op-item "$D" op-vault "$VAULT" UserName dave URL "https://delta.example" Notes "edited"
sync
D2=$(op item list --vault "$VAULT" --format json | python3 -c 'import json,sys;print(next((i["id"] for i in json.load(sys.stdin) if i["title"]=="Delta"),""))')
[ -n "$D2" ] && [ "$D2" != "$D" ] && [ "$(get "$D2" | cut -d'|' -f3)" = "pw-d2" ] && ok "resurrected as a new item" || bad "D2=$D2"
[ "$(kr_get "$D2" | cut -d'|' -f1)" = "Delta" ] && ok "restamped" || bad "restamp missing"
dump_kr; echo "  -- state ids: $(python3 -c 'import json,sys;print(list(json.load(open(sys.argv[1]))["entries"]))' "$STATE")"; echo "  -- remote live: $(op item list --vault "$VAULT" --format json | python3 -c 'import json,sys;print([(i["title"],i["id"]) for i in json.load(sys.stdin)])')"
step "12. mid-apply op failure stops the loop and keeps the base for the rest"
touch "$FAIL_EDIT_TOGGLE"
kr_clear "$A"; printf "%s" "pw-a8" | secret-tool store --label="Alpha" op-item "$A" op-vault "$VAULT" UserName alice URL "https://alpha2.example" Notes "note a"
out=$(sync); echo "$out" | tail -2
echo "$out" | grep -q 'failed: op item: simulated failure' && ok "reported the failure" || bad "no failure report: $out"
[ "$(get "$A" | cut -d'|' -f3)" = "pw-a7" ] && ok "remote untouched" || bad "remote changed"
rm -f "$FAIL_EDIT_TOGGLE"
sync
[ "$(get "$A" | cut -d'|' -f3)" = "pw-a8" ] && ok "retried on the next run" || bad "retry did not land"
dump_kr; echo "  -- state ids: $(python3 -c 'import json,sys;print(list(json.load(open(sys.argv[1]))["entries"]))' "$STATE")"; echo "  -- remote live: $(op item list --vault "$VAULT" --format json | python3 -c 'import json,sys;print([(i["title"],i["id"]) for i in json.load(sys.stdin)])')"
step "13. quiet again"
out=$(sync); echo "$out" | grep -q 'in sync (0 fetched)' && ok "in sync, 0 fetched" || bad "$out"

echo; echo "== $pass passed, $fail failed"
echo "state: $XDG_STATE_HOME/cce/keyring-sync/state.json"
grep -c '"h"' "$XDG_STATE_HOME/cce/keyring-sync/state.json" | sed 's/^/base entries: /'
grep -qE 'pw-a|pw-d|pw-e' "$XDG_STATE_HOME/cce/keyring-sync/state.json" && echo "!! a VALUE leaked into the state file" || echo "no values in the state file"
# --- teardown ---
kill -TERM $DPID; wait $DPID 2>/dev/null; cp $T/daemon.log "${DAEMON_LOG_COPY:-/dev/null}"; echo "daemon log: $(wc -l < $T/daemon.log) lines"
op vault delete "$VAULT" >/dev/null && echo "vault $VAULT deleted"
[ -n "$KRPID" ] && kill "$KRPID" 2>/dev/null && echo "isolated keyring stopped"
kill "$DBUS_SESSION_BUS_PID" 2>/dev/null
rm -rf "$T"
exit $fail
