# CrowdSec LAPI — Sorona supplement evidence (H1 / H2 / H7)

Supplement evidence package for three reports filed on [Sorona](https://sorona.xyz)
against the CrowdSec Local API (LAPI):

| Report | Finding |
|---|---|
| **SOR-SD1MPH** (H1) | Embedded-decision injection in alert creation — a validated log-processor machine can attach arbitrary decisions (any scope/value, up to `0.0.0.0/0`, uncapped 87600h duration, spoofed origin) to an alert, bypassing the operator allowlist |
| **SOR-76S9HG** (H2) | Decision deletion without ownership scoping or source-IP gating — any validated machine can delete other machines' decisions by ID or by filter from a non-loopback peer, and one unfiltered `DELETE /v1/decisions` call wipes the entire active decision set |
| **SOR-SE09A2** (H7) | Orphaned JWT — deleting a machine does not revoke its already-issued JWT; the token keeps reading alerts, writing alerts whose decisions go live, and refreshing into a fresh token |

## Why this package exists

The original proofs for all three reports ran on a locally built master HEAD
(`8f653d0c`, 2026-11-19). These supplements close that framing gap: **all three
demonstrations were re-executed end-to-end, unchanged, on the official CrowdSec
v1.7.8 release binaries** (official `crowdsec-release.tgz`, sha256
`647bd928b8413fe932fd781be1edef01ba6211797e837f3a731c39a3ce66f94c`, run as
downloaded — `version: v1.7.8-63227459`), and **every result is unchanged**.

The vulnerable code is **byte-identical** between the v1.7.8 release tag source
and the audited master HEAD (see `VERIFICATION.md` and `diffs/`):

| Region | Release v1.7.8 | Master HEAD `8f653d0c` | Result |
|---|---|---|---|
| `pkg/apiserver/controllers/v1/alerts.go` — `isAllowListed` early return (H1) | lines 128–131 | lines 129–132 | byte-identical |
| `pkg/apiserver/controllers/v1/alerts.go` — `CreateAlert` embedded-decision branch (H1) | lines 189–220 | lines 190–221 | byte-identical |
| `pkg/apiserver/controllers/v1/decisions.go` — `DeleteDecisionById` + `DeleteDecisions` (H2) | lines 101–157 (handlers at 101 / 134) | lines 101–157 (handlers at 101 / 134) | byte-identical, same line numbers |
| `pkg/apiserver/middlewares/v1/jwt.go` — `Authorizator` (H7) | lines 240–242 | lines 240–242 | byte-identical, same line numbers |

The findings are not artifacts of an unreleased master commit.

This repository exists because Sorona caps report attachments at 8 files per
report, which is not enough room for the full supplement package (supplement
texts, raw replay logs, replay scripts, and source diffs).

## Contents

- `H1-SUPPLEMENT.md`, `H2-SUPPLEMENT.md`, `H7-SUPPLEMENT.md` — per-report supplement texts
- `VERIFICATION.md` — release provenance (hashes, version strings), code-identity table, replay notes
- `h1-release-results.txt`, `h2-release-results.txt`, `h7-release-results.txt` — raw output of the re-runs on v1.7.8
- `run/h1-release.sh`, `run/h2-release.sh`, `run/h7-release.sh` — replay scripts
- `diffs/` — full-file diffs (release tag vs audited master) for `alerts.go`, `decisions.go`, `jwt.go`, plus a side-by-side extraction of the vulnerable regions

## Lab note

All demonstrations ran against a throwaway local lab instance (own sqlite DB,
CAPI disabled) created solely for this audit. The machine accounts
(`agentA`/`agentB`/`agentC`), their passwords, the bouncer API key, and the JWTs
appearing in the scripts and logs are disposable credentials of that local
instance only — they protect nothing else and the instance is not reachable
from anywhere.
