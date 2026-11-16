# Threshold-Signature Validator Key Custody

How a validator key can be custodied so that one compromised share
cannot authorize amendment votes or checkpoint signatures — with a
runnable drill that proves each property instead of asserting it.

Two custody paths are built and measured:

- **Path A — FROST threshold signing (RFC 9591, Ed25519).** Genuine
  threshold signing: the group secret is never reconstructed. The
  pure-Python implementation in this pack reproduces all 20 RFC 9591
  Appendix E.1 test vectors exactly.
- **Path B — ML-DSA-65 under Shamir-shared custody.** Shared custody
  WITH reconstruction: a quorum reconstructs the ML-DSA secret key at
  signing time. This is **not** threshold signing — there is no
  standardized threshold ML-DSA as of November 2026 — and the pack
  labels it as such throughout.

## Contents

- [`framework.md`](framework.md) — custody decision framework:
  scheme selection (FROST vs Shamir-shared custody vs threshold
  ML-DSA research), share generation and distribution, quorum rules,
  rotation and revocation, compromise response, and voting /
  checkpoint compatibility limits.
- [`cost-table.md`](cost-table.md) — measured cost table: share
  sizes, signing latency across quorum sizes, verification times,
  and signature bytes per checkpoint.
- [`citations.md`](citations.md) — primary sources (RFC 9591,
  RFC 8032, FIPS 204, NIST IR 8214C, ePrint 2026/013 and 2025/1163,
  Shamir 1979, XRPL amendment documentation) with URLs and access
  dates.
- [`claims.md`](claims.md) — claim-to-evidence index: every
  substantive claim in the framework and cost table linked to a
  drill-log file and line, or to a primary source.
- [`scripts/custody_drill.py`](scripts/custody_drill.py) — the
  one-command drill (see below). Proves quorum signing,
  below-quorum rejection, group-key verification, and
  compromised-share rotation for both paths, with unedited logs.
- [`scripts/frost_ed25519.py`](scripts/frost_ed25519.py) — pure-Python
  FROST(Ed25519, SHA-512) implementation (RFC 9591 §4–§6.1,
  Appendix C). Validated against the RFC test vectors by
  [`scripts/check_frost_vectors.py`](scripts/check_frost_vectors.py).
- [`scripts/oqs_ctypes.py`](scripts/oqs_ctypes.py) — minimal ctypes
  binding to liboqs 0.16.0 (needed because liboqs-python exposes no
  secret-key import; the reconstructed key must be passed to the
  signer explicitly).
- [`scripts/measure_costs.py`](scripts/measure_costs.py) — size and
  latency measurement for the cost table.
- [`scripts/compare_runs.py`](scripts/compare_runs.py) — verifies the
  5 drill runs agree on every invariant.
- [`scripts/run_drill.sh`](scripts/run_drill.sh) — one-command
  runner for the whole drill (5 runs + costs + comparison).

## Drill logs (unedited)

- [`logs/run-1.log`](logs/run-1.log)
- [`logs/run-2.log`](logs/run-2.log)
- [`logs/run-3.log`](logs/run-3.log)
- [`logs/run-4.log`](logs/run-4.log)
- [`logs/run-5.log`](logs/run-5.log)
- [`logs/costs.log`](logs/costs.log) — cost measurement
- [`logs/compare-runs.log`](logs/compare-runs.log) — determinism comparison
- [`logs/fresh-copy-rerun.log`](logs/fresh-copy-rerun.log) — fresh-copy rerun (see below)

## Simulated chain state

- [`ledger/final-state-run1.json`](ledger/final-state-run1.json) …
  [`ledger/final-state-run5.json`](ledger/final-state-run5.json) —
  final simulated checkpoint state per run.
- [`ledger/invariants-run1.json`](ledger/invariants-run1.json) …
  [`ledger/invariants-run5.json`](ledger/invariants-run5.json) —
  per-run invariants (identical across runs).

## How to run

```sh
# Requirements: python3 with liboqs-python installed, and liboqs
# 0.16.0 discoverable (see scripts/oqs_ctypes.py).
# Set PY to choose the interpreter, e.g.:
#   PY=/path/to/venv/bin/python bash scripts/run_drill.sh

# 1. One-command full drill: 5 runs + costs + determinism check
bash scripts/run_drill.sh

# 2. A single drill run (writes ledger/final-state-runN.json)
python3 scripts/custody_drill.py 1 ledger

# 3. RFC 9591 test-vector validation only
python3 scripts/check_frost_vectors.py

# 4. Cost measurement only
python3 scripts/measure_costs.py
```

## Measured results (summary)

- Drill: 5 consecutive runs, 45 checks each, 45 passed, 0 failed.
  20 of the 45 are the RFC 9591 Appendix E.1 test-vector checks,
  reproduced exactly. 6 simulated checkpoints signed and verified
  per run (3 FROST, 3 ML-DSA).
- FROST: share 32 B, group public key 32 B, signature 64 B (any
  quorum size). Full signing round (pure Python): 2-of-3 0.0691 s,
  3-of-5 0.1207 s, 4-of-7 0.1885 s, 5-of-7 0.2750 s (medians);
  verification ~0.0137 s flat.
- ML-DSA-65: pk 1952 B, sk 4032 B, sig 3309 B (FIPS 204 Table 2,
  asserted); sign 0.000260 s, verify 0.000099 s (medians, liboqs
  0.16.0). Shamir share of a 4032-byte key: 4032 B + 1 id byte per
  share; 3-of-5 share 0.0833 s, reconstruct 0.0054 s (medians).
- Signature bytes per quorum-signed checkpoint: FROST 64 B,
  ML-DSA quorum 3309 B, naive per-validator ML-DSA quorum-4
  13236 B. At 1,000,000 checkpoints: 64 MB / 3309 MB / 13236 MB.
- Rotation, both paths: refresh/resharing keeps the group public
  key unchanged (SHA-256 verified) and mixed old+new quorums fail —
  but refresh does NOT revoke old shares. The drill proves that
  limitation for both paths: a pre-refresh quorum still signs.
  Only a full rekey (new group key) revokes a compromised share.

## Fresh-clone rerun

Fresh-clone rerun performed 2026-11-16 (finished 23:48 WIB) from a
fresh `git clone` of this repository at commit
`6e659287f6045789de140771d9040fde446f076f`:

```sh
git clone https://github.com/araupooo/pftl-threshold-signature-validator-key-custody.git
cd pftl-threshold-signature-validator-key-custody
LIBOQS_PATH=<path-to-liboqs-0.16.0.so> PY=<python-with-oqs-0.16.0> bash scripts/run_drill.sh
```

(`PY` selects the interpreter with `oqs` 0.16.0 installed;
`LIBOQS_PATH` points at the liboqs 0.16.0 shared library. Both are
environment-specific; the drill itself needs only python3 with
liboqs-python and a discoverable liboqs 0.16.0 — see
[`scripts/oqs_ctypes.py`](scripts/oqs_ctypes.py).)

Results: **RUN_DRILL: ALL GREEN** (exit 0). 5 drill runs, 45 checks
each, **45 passed, 0 failed in every run**; cost measurement: all
size assertions passed; determinism comparison: **ALL 5 RUNS
AGREE**, failures 0. Each rerun log carries 29 full 64-hex SHA-256
values. The rerun regenerated the clone's `logs/` and `ledger/`
from the cloned files alone — no staged files were used.

Equivalent proof performed during the build (not a public clone):
the staged `scripts/` directory was copied to a fresh directory
in `/tmp`, and the drill was run from that copy alone — see
[`logs/fresh-copy-rerun.log`](logs/fresh-copy-rerun.log)
(45 checks, 45 passed, 0 failed).

## Verification

```sh
sha256sum -c SHA256SUMS
```

## Honesty notes

- FROST is Schnorr-only (RFC 9591). It cannot threshold-sign
  ML-DSA. The ML-DSA path in this pack is shared custody with
  reconstruction, not threshold signing.
- There is no standardized threshold ML-DSA as of November 2026.
  Mithril, Quorus, Efficient Threshold ML-DSA (ePrint 2026/013),
  TALUS, and Pebble are research submissions to NIST's first
  Multi-Party Threshold Cryptography call (NIST IR 8214C); their
  properties are reported as the authors' claims, never as
  standardized or production-ready.
- No public specification of the PFTL validator key lifecycle,
  amendment-vote signature format, or checkpoint signature format
  was located during this build; the framework's compatibility
  limits (§6) are built on the public XRPL-derived amendment model
  and marked as interpretation.
- All keys in the drill are freshly generated random test keys. No
  secret share or secret key is printed in full in any log — only
  sizes and full 64-hex SHA-256 hashes.
- The FROST implementation is pure Python with no constant-time
  guarantees and no side-channel mitigations (RFC 9591 §7.1). It is
  evidence code, not a production implementation.
