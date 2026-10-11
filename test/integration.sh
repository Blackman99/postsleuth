#!/usr/bin/env bash
# Integration test against a real Postfix in Docker.
# Usage: test/integration.sh ./postsleuth   (a linux/amd64 build)
set -euo pipefail
BIN=$(realpath "${1:-./postsleuth}")
C=postsleuth-it
HERE=$(cd "$(dirname "$0")" && pwd)
pass() { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; docker exec "$C" cat /var/log/postfix.log || true; exit 1; }
cleanup() { docker rm -f "$C" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker build -q -t postsleuth-postfix "$HERE/postfix" >/dev/null
cleanup
docker run -d --name "$C" postsleuth-postfix >/dev/null
for i in $(seq 1 30); do docker exec "$C" postfix status >/dev/null 2>&1 && break; sleep 1; done
docker exec "$C" postfix status >/dev/null 2>&1 || fail "postfix did not start"

W=(--wrap "docker exec -i $C" --no-color)
PS() { "$BIN" "$@" "${W[@]}"; }
send() { # from to
  printf 'Subject: postsleuth test\n\nhello\n' | docker exec -i "$C" sendmail -f "$1" "$2"
}
send app@example.test alice@localhost
send app@example.test user1@retry.test
send app@example.test user2@retry.test
send app@example.test ghost@bounce.test
send app@example.test ceo@timeout.test
send app@example.test someone@nxdomain.invalid

# wait until the immediate attempts are done: 2 retry + timeout (+ maybe nxdomain) deferred, rest gone
for i in $(seq 1 40); do
  n=$(PS queue --json | jq '[.by_queue[] | select(.key=="deferred") | .count] | add // 0')
  b=$(docker exec "$C" sh -c 'grep -c "status=bounced" /var/log/postfix.log || true')
  if [ "${n:-0}" -ge 3 ] && [ "${b:-0}" -ge 1 ] && docker exec "$C" grep -q "timeout.test\|192.0.2.1" /var/log/postfix.log; then break; fi
  sleep 2
done
docker exec "$C" postqueue -p || true
echo "--- postfix.log ---"; docker exec "$C" cat /var/log/postfix.log; echo "---"

# --- queue (postqueue -j through --wrap) ---
Q=$(PS queue --json)
echo "$Q" | jq -e '[.by_queue[] | select(.key=="deferred") | .count] | add >= 3' >/dev/null || fail "queue: expected >=3 deferred: $Q"
echo "$Q" | jq -e '[.reasons[] | select(.category=="rate_limit")] | .[0].recipients == 2' >/dev/null || fail "queue: rate_limit reason for 2 recipients: $Q"
echo "$Q" | jq -e '[.reasons[] | select(.category=="timeout" or .category=="connect")] | length >= 1' >/dev/null || fail "queue: timeout/connect reason: $Q"
pass "queue summary classifies real deferrals"

S=$(PS shape)
echo "$S" | grep -q "retry.test" || fail "shape: $S"
pass "qshape matrix"

L=$(PS queue --list --domain retry.test --json)
[ "$(echo "$L" | jq length)" = 2 ] || fail "queue --list filter: $L"
ID=$(echo "$L" | jq -r '.[0].queue_id')
pass "queue --list filter (id $ID)"

# --- log (maillog_file discovered via postconf, read through --wrap) ---
G=$(PS log --since 1h --json)
echo "$G" | jq -e '.source | test("postfix.log")' >/dev/null || fail "log source: $(echo "$G" | jq .source)"
echo "$G" | jq -e '.stats.totals.sent >= 1 and .stats.totals.bounced >= 1 and .stats.totals.deferred_attempts >= 3' >/dev/null || fail "log totals: $(echo "$G" | jq .stats.totals)"
echo "$G" | jq -e '[.stats.bounce_causes[] | select(.category=="recipient_unknown")] | length == 1' >/dev/null || fail "bounce cause: $(echo "$G" | jq .stats.bounce_causes)"
echo "$G" | jq -e '[.stats.deferral_reasons[] | select(.category=="rate_limit")][0].count >= 2' >/dev/null || fail "deferral reasons: $(echo "$G" | jq .stats.deferral_reasons)"
echo "$G" | jq -e '[.stats.still_failing[].domain] | index("retry.test") != null' >/dev/null || fail "still failing"
pass "log stats from real maillog_file"

T=$(PS trace ghost@bounce.test --json)
echo "$T" | jq -e '.messages[0].final_status == "bounced" and (.messages | length) >= 2' >/dev/null || fail "trace: $T"
pass "trace follows message and its bounce notice"

# --- doctor exits 1 because mail is deferred ---
set +e; PS doctor --no-dns >/tmp/doctor.txt; ec=$?; set -e
cat /tmp/doctor.txt
[ $ec = 1 ] || fail "doctor exit code $ec"
grep -q "rate_limit" /tmp/doctor.txt || fail "doctor output"
pass "doctor report, exit 1"

# --- native run inside the container (no --wrap) ---
docker cp "$BIN" "$C:/usr/local/bin/postsleuth"
docker exec "$C" postsleuth queue --json | jq -e '.messages >= 3' >/dev/null || fail "native queue"
docker exec "$C" postsleuth log --json | jq -e '.stats.totals.bounced >= 1' >/dev/null || fail "native log"
pass "native run inside the container"

# --- mutations are refused without --allow-mutations ---
set +e; out=$(PS delete "$ID" 2>&1); ec=$?; set -e
[ $ec = 2 ] && echo "$out" | grep -q "allow-mutations" || fail "delete without flag: $ec $out"
PS queue --list --json | jq -e --arg id "$ID" 'map(.queue_id) | index($id) != null' >/dev/null || fail "message vanished"
set +e; PS delete ALL --allow-mutations >/dev/null 2>&1; ec=$?; set -e
[ $ec = 2 ] || fail "delete ALL accepted"
pass "mutations refused by default; ALL refused"

PS hold "$ID" --allow-mutations >/dev/null
PS queue --queue hold --list --json | jq -e --arg id "$ID" 'map(.queue_id) | index($id) != null' >/dev/null || fail "hold"
PS release "$ID" --allow-mutations >/dev/null
PS requeue "$ID" --allow-mutations >/dev/null
PS flush "$ID" --allow-mutations >/dev/null
PS delete "$ID" --allow-mutations >/dev/null
sleep 1
PS queue --list --json | jq -e --arg id "$ID" 'map(.queue_id) | index($id) == null' >/dev/null || fail "delete with flag"
pass "hold/release/requeue/flush/delete with --allow-mutations"

# --- MCP over stdio ---
mcp() {
  python3 - "$@" <<'PY'
import json, subprocess, sys
args = sys.argv[1:]
p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def rpc(i, method, params):
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params}) + "\n"); p.stdin.flush()
    while True:
        m = json.loads(p.stdout.readline())
        if m.get("id") == i:
            return m
rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "it", "version": "0"}})
p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"); p.stdin.flush()
tools = [t["name"] for t in rpc(2, "tools/list", {})["result"]["tools"]]
res = rpc(3, "tools/call", {"name": "postfix_queue_summary", "arguments": {"queue": "deferred"}})["result"]
print(json.dumps({"tools": tools, "summary": res.get("structuredContent")}))
p.stdin.close(); p.wait(timeout=10)
PY
}
M=$(mcp "$BIN" mcp --wrap "docker exec -i $C")
echo "$M" | jq -e '.tools | index("postfix_queue_summary") != null and index("postfix_queue_delete") == null' >/dev/null || fail "mcp tools: $M"
echo "$M" | jq -e '.summary.messages >= 2' >/dev/null || fail "mcp call: $M"
M=$(mcp "$BIN" mcp --allow-mutations --wrap "docker exec -i $C")
echo "$M" | jq -e '.tools | index("postfix_queue_delete") != null' >/dev/null || fail "mcp mutations: $M"
pass "MCP stdio: read-only by default, mutating tools only with --allow-mutations"

# --- DNS checks against the real internet ---
D=$("$BIN" dns google.com --json --selector 20230601 --no-color || true)
echo "$D" | jq -e '[.checks[] | select(.check=="mx" or .check=="spf" or .check=="dmarc") | .status] | all(. == "ok" or . == "warn")' >/dev/null || fail "dns google.com: $D"
pass "dns checks (google.com)"
echo "all integration tests passed"
