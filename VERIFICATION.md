# VERIFICATION NOTE — CrowdSec H1/H2/H7 re-verification on the official stable release

Purpose: the E.25 audit found one shared defect in SOR-SD1MPH (H1), SOR-76S9HG (H2) and
SOR-SE09A2 (H7): all PoCs ran on a locally built master HEAD (8f653d0c, 2026-11-19) with no
comparison against a tagged release — the same framing weakness that closed the Chainlink
reports. This package closes that gap. Nothing here was posted to Sorona; the main agent
posts after review.

## Release obtained

- Latest published v1.7.x stable: **v1.7.8** (GitHub release, published 2026-05-11T07:53:36Z,
  target branch `releases/1.7.x`). (v1.8.x exists but is outside the reports' 1.7 line and
  outside this task's scope.)
- Binaries: official release asset `crowdsec-release.tgz`
  (https://github.com/crowdsecurity/crowdsec/releases/download/v1.7.8/crowdsec-release.tgz),
  sha256 `647bd928b8413fe932fd781be1edef01ba6211797e837f3a731c39a3ce66f94c`, run as downloaded —
  `version: v1.7.8-63227459`, Codename alphaga, BuildDate 2026-05-11_07:56:07, GoVersion 1.26.1.
  Extracted under `~/workspace/tmp/crowdsec-rel/crowdsec-v1.7.8/`; working copies in `poc/bin-rel/`.
- Source for diffing: official tag archive
  (https://github.com/crowdsecurity/crowdsec/archive/refs/tags/v1.7.8.tar.gz),
  sha256 `f7fdaa851f8578d763a573f77974871071583b9913ba284600e9277d2688e101`,
  extracted under `~/workspace/tmp/crowdsec-rel/relsrc/crowdsec-1.7.8/`.

## Code identity (release v1.7.8 vs audited master HEAD 8f653d0c in `src/`)

Full-file diffs: `diffs/alerts.go.release-vs-master.diff`,
`diffs/decisions.go.release-vs-master.diff`, `diffs/jwt.go.release-vs-master.diff`.
Region-by-region extraction: `diffs/vulnerable-snippets-side-by-side.txt`.

| Region | Release | Master HEAD | Result |
|---|---|---|---|
| alerts.go isAllowListed early return (H1) | lines 128–131 | lines 129–132 | **byte-identical** |
| alerts.go CreateAlert embedded-decision branch (H1) | lines 189–220 | lines 190–221 | **byte-identical** |
| decisions.go DeleteDecisionById + DeleteDecisions (H2) | lines 101–157 (handlers at 101 / 134) | lines 101–157 (handlers at 101 / 134) | **byte-identical, same line numbers** |
| jwt.go Authorizator (H7) | lines 240–242 | lines 240–242 | **byte-identical, same line numbers** |

Unrelated differences (none touches the vulnerable logic):
- alerts.go: 3 hunks — a nil-slice initialisation at :102 (causes the 1-line numbering shift in
  this file), and the flush-pause mechanism at :272–278 in the import path.
- decisions.go: hunks only from line 158 on — a refactor of the bouncer decision-streaming
  helpers (writeStartupDecisions/writeDeltaDecisions → writeDecisions/streamDecisions plus a
  stream concurrency limiter). The DELETE handlers are untouched.
- jwt.go: 1 line at :305 — the release's TokenLookup additionally accepts `query: token`.

## Release instance and replay

- Fresh instance in `poc/instance-rel/` (own sqlite DB, own config tree copied from the
  original instance): LAPI `0.0.0.0:18080`, CAPI disabled (`-no-cs`), default profiles
  (ban 4h, Ip + Range), machines `agentA`/`agentB` created and validated with the release
  cscli, one bouncer (`bouncer1`), allowlist `audit_allowlist` ∋ `203.0.113.99`
  (verified live: `{"allowlisted":true,...}`). Same topology as the original demos.
- Replay scripts (adapted copies of the originals): `run/h1-release.sh`,
  `run/h2-release.sh`, `run/h7-release.sh`. Raw outputs: `h1-release-results.txt`,
  `h2-release-results.txt`, `h7-release-results.txt`.
- Note: the first H1 run's log file was lost to a script path bug (results were visible in
  the terminal and matched); the instance DB was then reset (decisions/alerts wiped,
  topology kept) and all three scripts re-run cleanly in order H1 → H2 → H7. The files
  above are from that clean run.

Results (unchanged from the master-HEAD demos):
- **H1**: S1 profile decision `4h0m0s` origin `crowdsec`; S2 allowlisted IP → `[]` / bouncer
  `null`; S3 embedded decision bans allowlisted 203.0.113.99 for `87600h0m0s` with origin
  `capi`; S4 embedded `0.0.0.0/0` Range ban, origin `cscli`, `87600h0m0s`, containment check
  for an arbitrary IP returns it. Tier control: machine JWT on GET /v1/decisions → 403.
- **H2**: agentB from source 127.0.0.2 deletes agentA's decision by ID (200,
  `{"nbDeleted":"1"}`, view → `null`) and by filter (200, `{"nbDeleted":"1"}`, view → `null`);
  alerts-delete from the same peer → 403 `access forbidden from this IP (127.0.0.2)`, XFF
  spoof → 403, loopback control → 200; empty-filter DELETE → 200 `{"nbDeleted":"3"}` (every
  active decision at that point: the H1 re-run's 4h profile ban + both 87600h attack
  decisions), bouncer view afterwards → `null`. (Original nuclear count was 4 because the
  original instance held one extra test decision; the invariant — all active decisions
  expired by one unfiltered call — is identical.)
- **H7**: agentC created/logged in with release cscli, deleted (0 rows left), fresh login →
  401 `ent: machine not found`; orphaned JWT → GET /v1/alerts 200, POST /v1/alerts 201
  (alert id 10; its decision for 192.0.2.203 live in the bouncer view), GET /v1/refresh_token
  200 issuing a fresh token.

## H2 non-loopback source (task point 3)

Attempted and **not feasible in this sandbox**: `curl http://198.19.0.2:18080/health`
(hairpin to the VM's LAN address) and `curl --interface 198.19.0.2 http://127.0.0.1:18080/health`
both fail to connect (HTTP 000) — the sandbox's external interface does not hairpin to the
process, exactly as recorded in the original AUDIT.md. The replays therefore keep the
original disclosure's method (source-bound 127.0.0.2, a peer the LAPI's literal-IP gate
treats as remote; the server's own 403 message confirms the peer it saw). The original
disclosure stands unchanged on this point.

## State after the run

Release LAPI left running from `poc/bin-rel/` with config `poc/instance-rel/config.yaml`
(sqlite DB at `poc/instance-rel/data/crowdsec.db`): machines agentA/agentB validated,
agentC deleted, one active decision (id 10, 192.0.2.203, from the H7 replay). All local,
our own instance only; nothing external was touched and nothing was posted to Sorona.
