SUPPLEMENT — SOR-SE09A2 (H7) — Re-verified end-to-end on the official stable release (CrowdSec v1.7.8 release binaries)

This supplement answers the one gap in the original submission: the original PoC ran on a locally built master HEAD (8f653d0c). The full demonstration has now been re-executed, unchanged, against the official published stable release, and the vulnerable code is byte-identical between the two.

1) Target now: official release binaries, not a self-build
- Release: CrowdSec v1.7.8 — the latest published v1.7.x stable release (GitHub release page, published 2026-05-11).
- Artifact: official `crowdsec-release.tgz` from that release, sha256 647bd928b8413fe932fd781be1edef01ba6211797e837f3a731c39a3ce66f94c.
- The binaries run as downloaded (no recompilation): `crowdsec --version` and `cscli version` both report "version: v1.7.8-63227459, Codename: alphaga, BuildDate: 2026-05-11, GoVersion: 1.26.1". Machine administration in this re-run (add/delete) was done with the release cscli itself.
- Same topology as the original demo: fresh local instance (sqlite), LAPI on 0.0.0.0:18080, validated machines agentA/agentB, one bouncer API key, default 4h profiles.

2) The vulnerable code is identical in the release
Diffed the official v1.7.8 tag source against the audited master commit 8f653d0c (full diff preserved with this supplement package):
- pkg/apiserver/middlewares/v1/jwt.go — the per-request Authorizator (line 240 in both trees) is byte-identical:
    func Authorizator(data any, c *gin.Context) bool {
        return true
    }
  Token validation checks the HS256 signature and expiry only; machine existence / is_validated is never re-checked against the database after login. The single other difference in the file (line 305: the release's TokenLookup additionally accepts "query: token") does not affect this behaviour.

3) Re-run results on v1.7.8 — unchanged (raw log: h7-release-results.txt)
- Setup: release cscli creates machine agentC; agentC logs in (HTTP 200, JWT captured). Control: GET /v1/heartbeat with the token -> 200.
- Revocation: release cscli deletes agentC ("machine 'agentC' deleted successfully"); the machines table then holds 0 rows for agentC. Control: a fresh login as agentC is refused -> 401 {"message":"ent: machine not found"}.
- The pre-deletion JWT, after deletion:
  - GET /v1/alerts -> 200 (full alert read).
  - POST /v1/alerts for 192.0.2.203 -> 201 (alert id 10 created); the resulting profile decision for 192.0.2.203 is live in the bouncer view ({"duration":"3h59m59s","origin":"crowdsec","value":"192.0.2.203"}) — the deleted machine is still writing enforcement state.
  - GET /v1/refresh_token -> 200, issuing a brand-new token (new expire ~ +1h) for the nonexistent machine.
- Bound unchanged: each token lives <= 1h and refresh is allowed up to 1h from original issuance (gin-jwt MaxRefresh), so worst-case post-revocation access remains just under 2h from the last pre-deletion login.

Conclusion: every step of the original report reproduces exactly on the published v1.7.8 stable release — deleting a machine does not revoke its already-issued JWT, which keeps reading alerts, writing alerts whose decisions go live, and refreshing into a fresh token. The finding is not an artifact of an unreleased master commit.
