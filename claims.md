# Claim-to-Evidence Index

Every substantive claim in `framework.md` and `cost-table.md` is
listed here with the evidence that backs it: an unedited drill-log
file and line, or a primary source in `citations.md`. Claims are
labelled [FAKTA] (verified fact), [ESTIMASI] (modelled/reported
number), or [ANALISIS] (interpretation). Nothing in this index is
backed by assertion alone.

Log line numbers refer to `logs/run-1.log` unless another log is
named. All five runs carry the same checks; see
`logs/compare-runs.log` ("ALL 5 RUNS AGREE").

## A. FROST threshold signing (Path A)

| # | Claim | Label | Evidence |
| --- | --- | --- | --- |
| A1 | FROST is specified in RFC 9591 (June 2024, CFRG/IRTF, informational, not Standards Track); two rounds; Schnorr ciphersuites Ed25519, Ed448, ristretto255, P-256, secp256k1; signatures verify as standard Schnorr/EdDSA | [FAKTA] | citations.md §1 (RFC 9591 Abstract, §1, §6); RFC text read 2026-11-16 |
| A2 | FROST key generation is out of scope of RFC 9591; Appendix C specifies trusted-dealer key generation only | [FAKTA] | citations.md §1 (RFC 9591 §1, App. C) |
| A3 | FROST assumes an adversary corrupts strictly fewer than the threshold number of participants | [FAKTA] | citations.md §1 (RFC 9591 §1) |
| A4 | The FROST implementation in this pack reproduces the RFC 9591 Appendix E.1 test vectors exactly (group key, shares, nonces, commitments, binding factors, signature shares, aggregate signature) | [FAKTA] | logs/run-1.log lines 8–26 (20 vector checks, all PASS); line 28 ("test vectors reproduced (20 checks)") |
| A5 | A quorum of 3-of-5 FROST shares signs simulated checkpoints and the aggregate verifies under the group public key | [FAKTA] | logs/run-1.log lines 39–40, 42–43, 45–46 (heights 1000–1002) |
| A6 | A FROST signature for one checkpoint is rejected for another checkpoint (message binding) | [FAKTA] | logs/run-1.log lines 41, 44, 47 |
| A7 | Below-quorum sets (2 shares, 1 share) cannot produce a valid FROST signature | [FAKTA] | logs/run-1.log lines 48–49 |
| A8 | A quorum containing one foreign share produces an invalid aggregate signature | [FAKTA] | logs/run-1.log line 50 |
| A9 | FROST share refresh keeps the group public key unchanged | [FAKTA] | logs/run-1.log line 52 (group pk SHA-256 identical before/after) |
| A10 | A refreshed FROST quorum signs and verifies; a mixed old+new quorum fails | [FAKTA] | logs/run-1.log lines 53–54 |
| A11 | LIMITATION: a pre-refresh FROST quorum still signs after refresh — refresh does not revoke old shares | [FAKTA] | logs/run-1.log line 55 |
| A12 | FROST full rekey changes the group public key; the new quorum signs under it; old shares cannot sign under it | [FAKTA] | logs/run-1.log lines 57–59 |
| A13 | Nonces must not be reused; deterministic nonce derivation allows complete key recovery in multi-party Schnorr signing | [FAKTA] | citations.md §1 (RFC 9591 §1, §4.1, §7.3) |
| A14 | FROST cannot threshold-sign ML-DSA (Schnorr-only mathematics) | [FAKTA] | citations.md §1 (RFC 9591 §1, §6); citations.md §11 (Pebble paper §1) |
| A15 | A coordinator that misbehaves can only cause an invalid signature, not a forgery | [FAKTA] | citations.md §1 (RFC 9591 §5, §7.5) |

## B. ML-DSA Shamir-shared custody (Path B)

| # | Claim | Label | Evidence |
| --- | --- | --- | --- |
| B1 | ML-DSA-65 sizes: pk 1952 B, sk 4032 B, sig 3309 B (FIPS 204 Table 2) | [FAKTA] | citations.md §4; logs/run-1.log line 64; logs/costs.log line "size ML-DSA-65" |
| B2 | A 3-of-5 Shamir quorum reconstructs the ML-DSA-65 secret key exactly (SHA-256 match) | [FAKTA] | logs/run-1.log line 68 |
| B3 | The quorum-reconstructed key signs simulated checkpoints and the signatures verify under the group public key | [FAKTA] | logs/run-1.log lines 69–74 (heights 6000–6002) |
| B4 | A below-quorum (2-share) reconstruction differs from the secret key, and signatures made with it are invalid | [FAKTA] | logs/run-1.log lines 75–76 |
| B5 | A single share used directly as a key produces an invalid signature | [FAKTA] | logs/run-1.log line 77 |
| B6 | Resharing keeps the group public key unchanged; a new quorum reconstructs the same key and signs | [FAKTA] | logs/run-1.log lines 79–81 |
| B7 | A mixed old+new share quorum reconstructs a wrong key and its signature is invalid | [FAKTA] | logs/run-1.log lines 82–83 |
| B8 | LIMITATION: a pre-rotation quorum still reconstructs the key after resharing — resharing does not revoke old shares | [FAKTA] | logs/run-1.log line 84 |
| B9 | ML-DSA full rekey changes the group public key; the new key signs under it; the old key cannot sign under it | [FAKTA] | logs/run-1.log lines 86–88 |
| B10 | Shamir sharing is information-theoretic: any t shares reconstruct, any t−1 reveal nothing | [FAKTA] | citations.md §3 (Shamir 1979) |
| B11 | Shared custody with reconstruction is NOT threshold signing: the reconstructed key is a single point of failure at signing time | [ANALISIS] | Follows from B2–B3 (reconstruction is required to sign) plus citations.md §5–§6 (no standardized threshold ML-DSA) |
| B12 | Path B is suitable only where the signing ceremony is trusted and short-lived (reconstruct, sign, erase) | [ANALISIS] | Follows from B11; no separate log evidence — stated as interpretation |

## C. Threshold ML-DSA research (Path C)

| # | Claim | Label | Evidence |
| --- | --- | --- | --- |
| C1 | No standardized threshold ML-DSA exists as of November 2026; threshold ML-DSA is under NIST's first MPTC call (IR 8214C, final January 2026) | [FAKTA] | citations.md §5 (NIST IR 8214C, DOI 10.6028/NIST.IR.8214C) |
| C2 | Mithril: replicated secret sharing, short shares, DKG + sharing of an existing key preserving the public key; authors report <20 ms local / <1 s WAN signing, up to 8 parties | [FAKTA] | citations.md §9 (preview v1.0, 2026-01-19); figures are the authors' reported numbers |
| C3 | Quorus: MPC-based, ~150 KB/party/round, honest-majority, signatures verify under unmodified ML-DSA verifiers | [FAKTA] | citations.md §7 (ePrint 2025/1163, USENIX Security 2025); figures are the authors' reported numbers |
| C4 | Efficient Threshold ML-DSA: first practical ML-DSA-compatible scheme per the authors; up to 6 parties, ≤1 MB/party average, Go implementation | [FAKTA] | citations.md §6 (ePrint 2026/013, USENIX Security 2026); figures are the authors' reported numbers; verified live 2026-11-16 |
| C5 | TALUS: Boundary Clearance Condition, FIPS-204-exact signatures, two-round online phase, mandatory key rotation | [FAKTA] | citations.md §10 (preview v0.22, 2026-08-11); authors' claims |
| C6 | Pebble: discrete-Gaussian partial nonces, Pebble-ADA quorum identity | [FAKTA] | citations.md §11 (Silence Labs, 2026-07-28); authors' claims |
| C7 | ML-DSA threshold signing is hard because responses are short integer vectors from rejection sampling | [FAKTA] | citations.md §11 (Pebble paper §1) |
| C8 | Path C schemes are not standardized, have not completed NIST evaluation, and are not recommended for production custody | [ANALISIS] | Follows from C1; no evaluated submission exists under the call as of this build |

## D. Measured costs

| # | Claim | Label | Evidence |
| --- | --- | --- | --- |
| D1 | ML-DSA-44/65/87 sizes match FIPS 204 Table 2 (all size assertions passed) | [FAKTA] | logs/costs.log ("ALL SIZE ASSERTIONS PASSED", failures 0); cost-table.md §1 |
| D2 | ML-DSA-65 sign median 0.000260 s, verify median 0.000099 s (n=50, liboqs 0.16.0) | [FAKTA] | logs/costs.log (timing ML-DSA-65); cost-table.md §2.1 |
| D3 | FROST full signing round medians: 2-of-3 0.0691 s, 3-of-5 0.1207 s, 4-of-7 0.1885 s, 5-of-7 0.2750 s (pure Python, n=20); verify ~0.0137 s flat | [FAKTA] | logs/costs.log (timing FROST); cost-table.md §2.2 |
| D4 | Shamir share/reconstruct medians for a 4032-byte key: 3-of-5 share 0.0833 s / reconstruct 0.0054 s (n=10) | [FAKTA] | logs/costs.log (timing Shamir); cost-table.md §2.3 |
| D5 | Signature bytes per checkpoint: FROST 64 B, ML-DSA quorum 3309 B, naive quorum-4 13236 B; 1M checkpoints: 64 MB / 3309 MB / 13236 MB | [FAKTA] | logs/costs.log (LEDGER MODEL); cost-table.md §3 |
| D6 | FROST verification time is flat across quorum sizes because the aggregate is one ordinary Ed25519 signature | [ANALISIS] | Follows from D3 + A1 (RFC 9591 §6.1: aggregates verify as standard EdDSA) |
| D7 | The pure-Python FROST timings show scaling shape, not production latency; a compiled implementation would be far faster | [ANALISIS] | Follows from D3; the implementation notes its non-optimized status in scripts/frost_ed25519.py |

## E. Voting and checkpoint compatibility

| # | Claim | Label | Evidence |
| --- | --- | --- | --- |
| E1 | No public specification of the PFTL validator key lifecycle, amendment-vote signature format, or checkpoint signature format was located during this build | [FAKTA] | Searched 2026-11-16; no PFTL validator key document found (see framework.md §6.1) |
| E2 | In the XRPL amendment model, an amendment needs >80% of trusted validators voting yes, support held 14 consecutive days, votes counted at flag ledgers (every 256th) | [FAKTA] | citations.md §12–§13 (xrpl.org; xrpldashboard.com), accessed 2026-11-16 |
| E3 | A custody quorum inside one validator is not the same as a quorum of validators on the network; the 80% rule counts validators, not shares | [ANALISIS] | Follows from E2; no separate log evidence |
| E4 | A FROST aggregate verifies as an ordinary Ed25519 signature, so a ledger accepting Ed25519 validator signatures accepts it with no protocol change — only if the registered key is the FROST group key | [ANALISIS] | Follows from A1 (RFC 9591 §6.1) + A5 (drill verification) |
| E5 | An emergency rekey during an amendment vote can reset that validator's contribution to the vote | [ANALISIS] | Follows from E2 (votes are cast under a registered key) + A12 (rekey changes the key) |

## F. Drill integrity (determinism)

| # | Claim | Label | Evidence |
| --- | --- | --- | --- |
| F1 | 5 consecutive drill runs: 45 checks each, 45 passed, 0 failed | [FAKTA] | logs/compare-runs.log ("run-1.log: 45 passed, 0 failed" … "run-5.log: 45 passed, 0 failed"); logs/run-1.log line 91 through logs/run-5.log |
| F2 | All 5 runs agree on every invariant (deterministic in invariants; fresh keys per run, so hashes differ legitimately) | [FAKTA] | logs/compare-runs.log ("ALL 5 RUNS AGREE", failures 0) |
| F3 | A fresh-copy rerun (scripts copied to /tmp, run 99) passes 45/45 | [FAKTA] | logs/fresh-copy-rerun.log ("checks: 45 passed, 0 failed", "ALL CHECKS PASSED") |
| F4 | Drill logs print full 64-hex SHA-256 values, never truncated prefixes | [FAKTA] | logs/compare-runs.log ("full 64-hex SHA-256 values present: 29" per run) |
| F5 | No secret share or secret key is printed in full in any log (sizes and hashes only) | [FAKTA] | Verified by inspection of logs/run-1.log … run-5.log: only SHA-256 hashes and sizes of secrets appear |
