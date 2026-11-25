#!/bin/bash
# H1 replay against the OFFICIAL RELEASE instance (CrowdSec v1.7.8 release binaries).
# Mirrors poc/h1.sh S1-S4 exactly: same values, durations, origins, allowlist.
set -u
cd "$(dirname "$0")/../../poc"
BASE=http://127.0.0.1:18080
BKEY='xw20tUFOu3EZ0w0RYM5Orteoytg1emnJ5+Y/IN0oy0U'
UA='crowdsec/v1.7.8-63227459-linux'
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUT=../supplement-release/h1-release-results.txt
: > "$OUT"

alert_nodsc() {
cat <<JSON
[{"message":"h1-rel nodsc","events_count":1,"start_at":"$NOW","stop_at":"$NOW","capacity":10,"leakspeed":"10s","scenario":"test/manual","scenario_version":"1.0","scenario_hash":"x","remediation":true,"simulated":false,"source":{"scope":"Ip","value":"$1"},"events":[{"timestamp":"$NOW","meta":[{"key":"source_ip","value":"$1"}]}]}]
JSON
}
alert_embed() { # ip duration origin scope value
cat <<JSON
[{"message":"h1-rel embed","events_count":1,"start_at":"$NOW","stop_at":"$NOW","capacity":10,"leakspeed":"10s","scenario":"test/manual","scenario_version":"1.0","scenario_hash":"x","remediation":true,"simulated":false,"source":{"scope":"Ip","value":"$1"},"events":[{"timestamp":"$NOW","meta":[{"key":"source_ip","value":"$1"}]}],"decisions":[{"duration":"$2","origin":"$3","scenario":"test/manual","scope":"$4","type":"ban","value":"$5"}]}]
JSON
}
post_alert() { curl -s --noproxy '*' -m 15 -X POST "$BASE/v1/alerts" -H "Authorization: Bearer $1" -H 'Content-Type: application/json' -H "User-Agent: $UA" -d "$2" -w '\nHTTP %{http_code}'; }
get_dec() { curl -s --noproxy '*' -m 15 "$BASE/v1/decisions?$1" -H "X-Api-Key: $BKEY"; }
log() { echo "$@" | tee -a "$OUT"; }

log "===== H1 REPLAY on official release binaries ====="
log "-- server binary version:"
./bin-rel/crowdsec --version 2>&1 | head -2 | tee -a "$OUT"
log "-- login agentA (validated log-processor machine):"
TOK=$(curl -s --noproxy '*' -X POST "$BASE/v1/watchers/login" -H 'Content-Type: application/json' -H "User-Agent: $UA" -d '{"machine_id":"agentA","password":"AgentA-pass-123!"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
log "   JWT acquired: ${TOK:0:25}..."
log "-- control: agent JWT on GET /v1/decisions (machines are not decision readers, expect 403):"
curl -s --noproxy '*' "$BASE/v1/decisions" -H "Authorization: Bearer $TOK" -H "User-Agent: $UA" -w '\nHTTP %{http_code}' | tee -a "$OUT"; echo | tee -a "$OUT"
log "-- allowlist check 203.0.113.99 (expect allowlisted:true from audit_allowlist):"
curl -s --noproxy '*' "$BASE/v1/allowlists/check/203.0.113.99" -H "Authorization: Bearer $TOK" -H "User-Agent: $UA" | tee -a "$OUT"; echo | tee -a "$OUT"

log "== S1 control: profile path, normal IP 198.51.100.23 =="
post_alert "$TOK" "$(alert_nodsc 198.51.100.23)" | tee -a "$OUT"; echo | tee -a "$OUT"
log "-- bouncer view of 198.51.100.23:"
get_dec "value=198.51.100.23" | tee -a "$OUT"; echo | tee -a "$OUT"

log "== S2 control: profile path, ALLOWLISTED IP 203.0.113.99 =="
post_alert "$TOK" "$(alert_nodsc 203.0.113.99)" | tee -a "$OUT"; echo | tee -a "$OUT"
log "-- bouncer view of 203.0.113.99 (expect no decision):"
get_dec "value=203.0.113.99" | tee -a "$OUT"; echo | tee -a "$OUT"

log "== S3 ATTACK: embedded decision, ALLOWLISTED IP 203.0.113.99, duration 87600h, origin spoofed as capi =="
post_alert "$TOK" "$(alert_embed 203.0.113.99 87600h capi Ip 203.0.113.99)" | tee -a "$OUT"; echo | tee -a "$OUT"
log "-- bouncer view of 203.0.113.99 (attack success = decision present):"
get_dec "value=203.0.113.99" | tee -a "$OUT"; echo | tee -a "$OUT"

log "== S4 ATTACK: embedded decision scope=Range value=0.0.0.0/0 duration 87600h origin cscli =="
post_alert "$TOK" "$(alert_embed 192.0.2.55 87600h cscli Range 0.0.0.0/0)" | tee -a "$OUT"; echo | tee -a "$OUT"
log "-- bouncer containment check ip=198.51.100.23 after /0 decision:"
get_dec "ip=198.51.100.23" | tee -a "$OUT"; echo | tee -a "$OUT"
log "-- all decisions (bouncer, unfiltered, first 600 chars):"
get_dec "" | head -c 600 | tee -a "$OUT"; echo | tee -a "$OUT"
log "===== END H1 release replay ====="
