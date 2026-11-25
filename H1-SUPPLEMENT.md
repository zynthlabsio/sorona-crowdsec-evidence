SUPPLEMENT — SOR-SD1MPH (H1) — Re-verified end-to-end on the official stable release (CrowdSec v1.7.8 release binaries)

This supplement answers the one gap in the original submission: the original PoC ran on a locally built master HEAD (8f653d0c). The full demonstration has now been re-executed, unchanged, against the official published stable release, and the vulnerable code is byte-identical between the two.

1) Target now: official release binaries, not a self-build
- Release: CrowdSec v1.7.8 — the latest published v1.7.x stable release (GitHub release page, published 2026-05-11).
- Artifact: official `crowdsec-release.tgz` from that release, sha256 647bd928b8413fe932fd781be1edef01ba6211797e837f3a731c39a3ce66f94c.
- The binaries run as downloaded (no recompilation): `crowdsec --version` reports "version: v1.7.8-63227459, Codename: alphaga, BuildDate: 2026-05-11_07:56:07, GoVersion: 1.26.1".
- Same topology as the original demo: fresh local instance (sqlite), LAPI on 0.0.0.0:18080, two validated machines (agentA, agentB), one bouncer API key, the default profiles (ban 4h for Ip and Range), and operator allowlist `audit_allowlist` containing 203.0.113.99 (verified live before the run: GET /v1/allowlists/check/203.0.113.99 -> {"allowlisted":true,"reason":"203.0.113.99 from audit_allowlist"}).

2) The vulnerable code is identical in the release
Diffed the official v1.7.8 tag source against the audited master commit 8f653d0c (full diffs preserved with this supplement package):
- pkg/apiserver/controllers/v1/alerts.go — the isAllowListed early return ("If we have decisions, it comes from cscli that already checked the allowlist", release lines 128-131 = master 129-132) and the CreateAlert embedded-decision branch ("if coming from cscli, alert already has decisions", release lines 189-220 = master 190-221) are byte-identical. The only other differences in the file are a nil-slice initialisation in the CreateAlert prologue and the flush-pause mechanism in the import path — neither touches this logic.
- So the release handler still infers the privileged cscli sender from payload shape alone and never checks the caller's identity.

3) Re-run results on v1.7.8 — unchanged (raw log: h1-release-results.txt)
- Tier control: agentA's JWT on GET /v1/decisions -> 403 {"message":"access forbidden"} (machines are not decision readers; the write path below is the anomaly).
- S1 control (profile path): alert for 198.51.100.23, no decisions -> 201; bouncer view: one decision {origin:"crowdsec", duration:"4h0m0s"} — the profile's decision.
- S2 control (allowlist): alert for allowlisted 203.0.113.99, no decisions -> 201 []; bouncer view: null. The allowlist holds on the profile path.
- S3 attack: same caller, alert for 203.0.113.99 WITH embedded decision {duration:"87600h", origin:"capi", scope:"Ip", type:"ban", value:"203.0.113.99"} -> 201; bouncer view: {"duration":"87600h0m0s","origin":"capi","value":"203.0.113.99"} — the allowlisted IP is banned for ~10 years, attributed to the Central API.
- S4 attack: alert with source 192.0.2.55 and embedded decision {duration:"87600h", origin:"cscli", scope:"Range", value:"0.0.0.0/0"} -> 201; bouncer containment check GET /v1/decisions?ip=198.51.100.23 returns the /0 ban — every IPv4 address is covered.

Conclusion: every step of the original report reproduces exactly on the published v1.7.8 stable release — allowlist bypass, uncapped 87600h duration vs the 4h profile, arbitrary scope/value up to 0.0.0.0/0, and origin spoofing (capi / cscli), all from an ordinary validated log-processor machine credential, with the resulting decisions served to every bouncer. The finding is not an artifact of an unreleased master commit.
