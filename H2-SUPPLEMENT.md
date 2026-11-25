SUPPLEMENT — SOR-76S9HG (H2) — Re-verified end-to-end on the official stable release (CrowdSec v1.7.8 release binaries)

This supplement answers the one gap in the original submission: the original PoC ran on a locally built master HEAD (8f653d0c). The full demonstration has now been re-executed, unchanged, against the official published stable release, and the vulnerable handlers are byte-identical between the two.

1) Target now: official release binaries, not a self-build
- Release: CrowdSec v1.7.8 — the latest published v1.7.x stable release (GitHub release page, published 2026-05-11).
- Artifact: official `crowdsec-release.tgz` from that release, sha256 647bd928b8413fe932fd781be1edef01ba6211797e837f3a731c39a3ce66f94c.
- The binaries run as downloaded (no recompilation): `crowdsec --version` reports "version: v1.7.8-63227459, Codename: alphaga, BuildDate: 2026-05-11_07:56:07, GoVersion: 1.26.1".
- Same topology as the original demo: fresh local instance (sqlite), LAPI on 0.0.0.0:18080, two validated machines (agentA = decision owner, agentB = attacker), one bouncer API key, default 4h profiles, operator allowlist present. "Remote" peer = TCP source 127.0.0.2 bound via `curl --interface`, exactly as in the original disclosure (the gate trusts only the literal 127.0.0.1/::1/unix socket and trusted_ips is empty, so this executes the remote code path; the server's own error below confirms the peer it saw). Binding from the VM's real LAN address (198.19.0.2) was attempted for this re-run and is not feasible inside this sandbox — the external interface does not hairpin to the process (both the direct and source-bound attempts fail to connect) — so the original disclosure's peer method stands unchanged.

2) The vulnerable code is identical in the release
Diffed the official v1.7.8 tag source against the audited master commit 8f653d0c (full diffs preserved with this supplement package):
- pkg/apiserver/controllers/v1/decisions.go — DeleteDecisionById (line 101) and DeleteDecisions (line 134) sit at the same line numbers in both trees and the whole handler region (lines 101-157) is byte-identical: no ownership scoping, no source-IP check. Every difference elsewhere in the file is a refactor of the bouncer decision-streaming helpers (from line 158 on) and does not touch the DELETE handlers.
- The sibling gate it lacks is also unchanged: DELETE /v1/alerts remains IP-gated by authIP in alerts.go (demonstrated live again below).

3) Re-run results on v1.7.8 — unchanged (raw log: h2-release-results.txt)
- Setup: agentA creates two decisions via the profile path — id 7 (192.0.2.200) and id 8 (192.0.2.201); bouncer view confirms both active.
- By ID, remote: agentB's JWT, source 127.0.0.2: DELETE /v1/decisions/7 -> 200 {"nbDeleted":"1"}; bouncer view of 192.0.2.200 -> null.
- By filter, remote: agentB, source 127.0.0.2: DELETE /v1/decisions?value=192.0.2.201 -> 200 {"nbDeleted":"1"}; bouncer view -> null.
- Asymmetry control: same caller class, same remote peer: DELETE /v1/alerts/9 -> 403 {"message":"access forbidden from this IP (127.0.0.2)"}; with a spoofed X-Forwarded-For: 127.0.0.1 header -> still 403 (gate uses the real peer); from loopback -> 200. The protection exists on the sibling endpoint and is simply absent on decisions.
- Nuclear variant: with 3 active decisions in the bouncer view (a 4h profile ban plus the two 87600h attack decisions from the H1 re-verification), agentB from source 127.0.0.2: DELETE /v1/decisions with NO filter -> 200 {"nbDeleted":"3"}; bouncer view afterwards -> null. One request from the lowest authenticated tier expired every active decision the deployment was enforcing.

Conclusion: every step of the original report reproduces exactly on the published v1.7.8 stable release — cross-agent decision deletion by ID and by filter from a non-loopback peer, and a one-call empty-filter wipe of the entire active decision set, with no IP gate and no ownership check. The finding is not an artifact of an unreleased master commit.
