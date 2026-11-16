# Measured Custody Cost Table

All figures below are measured on this machine (liboqs 0.16.0;
FROST via the pure-Python RFC 9591 implementation in
`scripts/frost_ed25519.py`). Sizes are specification values confirmed
by measurement; timings are medians on this environment, not
specification values. Full unedited output: `logs/costs.log`.

Every substantive claim in this document carries exactly one label:
[FAKTA] (verified fact with source and date), [ESTIMASI] (a modelled
or reported number), or [ANALISIS] (interpretation).

## 1. Sizes (asserted against the specifications)

| Item | Bytes | Source |
| --- | --- | --- |
| ML-DSA-44 public key | 1312 | [FAKTA] FIPS 204 Table 2, measured `logs/costs.log` |
| ML-DSA-44 secret key | 2560 | [FAKTA] FIPS 204 Table 2, measured |
| ML-DSA-44 signature | 2420 | [FAKTA] FIPS 204 Table 2, measured |
| ML-DSA-65 public key | 1952 | [FAKTA] FIPS 204 Table 2, measured |
| ML-DSA-65 secret key | 4032 | [FAKTA] FIPS 204 Table 2, measured |
| ML-DSA-65 signature | 3309 | [FAKTA] FIPS 204 Table 2, measured |
| ML-DSA-87 public key | 2592 | [FAKTA] FIPS 204 Table 2, measured |
| ML-DSA-87 secret key | 4896 | [FAKTA] FIPS 204 Table 2, measured |
| ML-DSA-87 signature | 4627 | [FAKTA] FIPS 204 Table 2, measured |
| FROST share (Ed25519 scalar) | 32 | [FAKTA] RFC 9591 §6.1 (Ns = 32) |
| FROST group public key | 32 | [FAKTA] RFC 9591 §6.1 (Ne = 32) |
| FROST signature (R \|\| z) | 64 | [FAKTA] RFC 9591 Appendix A |
| FROST commitment pair per signer | 64 | [FAKTA] RFC 9591 §5.1 (two 32-byte points) |
| ML-DSA-65 Shamir share | 4032 + 1 id byte | [FAKTA] measured `logs/costs.log` |

[FAKTA] All size assertions passed in the cost measurement
(`logs/costs.log`: "ALL SIZE ASSERTIONS PASSED", failures 0).

## 2. Signing and verification latency (medians)

### 2.1 ML-DSA (liboqs 0.16.0, n = 50 repetitions)

| Scheme | Sign median (s) | Verify median (s) |
| --- | --- | --- |
| ML-DSA-44 | 0.000170 | 0.000064 |
| ML-DSA-65 | 0.000260 | 0.000099 |
| ML-DSA-87 | 0.000290 | 0.000139 |

[FAKTA] Measured values are the medians in `logs/costs.log`
(`RESULTS_JSON`). ML-DSA-65 signing takes about 0.26 ms and
verification about 0.10 ms on this machine.

### 2.2 FROST full signing round (commit + sign + aggregate, pure Python, n = 20)

| Quorum | Sign round median (s) | Verify median (s) |
| --- | --- | --- |
| 2-of-3 | 0.0691 | 0.0138 |
| 3-of-5 | 0.1207 | 0.0139 |
| 4-of-7 | 0.1885 | 0.0137 |
| 5-of-7 | 0.2750 | 0.0136 |

[FAKTA] Measured values are the medians in `logs/costs.log`.
[ANALISIS] The pure-Python FROST implementation is not optimized
(no constant-time guarantees, no multi-exponentiation); the figures
show the scaling shape (roughly linear in quorum size, dominated by
scalar multiplications), not production latency. A compiled FROST
implementation would be orders of magnitude faster. Verification
time is flat across quorum sizes because a FROST aggregate is one
ordinary Ed25519 signature regardless of quorum size.

### 2.3 Shamir sharing of a 4032-byte ML-DSA-65 secret key (n = 10)

| Quorum | Share median (s) | Reconstruct median (s) |
| --- | --- | --- |
| 2-of-3 | 0.0322 | 0.0038 |
| 3-of-5 | 0.0833 | 0.0054 |
| 4-of-7 | 0.1029 | 0.0080 |
| 5-of-7 | 0.1274 | 0.0100 |

[FAKTA] Measured values are the medians in `logs/costs.log`.
[ANALISIS] Sharing is the expensive step (one polynomial evaluation
per byte per share); reconstruction is cheap (one Lagrange
interpolation per byte). Both are milliseconds-to-tenths-of-a-second
for a 4032-byte key in pure Python and negligible next to the
ceremony's human and network costs.

## 3. Ledger model: signature bytes per quorum-signed checkpoint

[FAKTA] Measured/derived from the sizes in §1 (see
`logs/costs.log`, LEDGER MODEL section):

| Path | Bytes per checkpoint |
| --- | --- |
| FROST (any quorum size) | 64 |
| ML-DSA Shamir quorum (one reconstructed-key signature) | 3309 |
| Naive per-validator ML-DSA-65 signatures, quorum 4 | 13236 |

| Checkpoints | FROST | ML-DSA quorum | Naive quorum 4 |
| --- | --- | --- | --- |
| 10,000 | 0.64 MB | 33.09 MB | 132.36 MB |
| 100,000 | 6.40 MB | 330.90 MB | 1323.60 MB |
| 1,000,000 | 64.00 MB | 3309.00 MB | 13236.00 MB |

[ANALISIS] The ledger-growth difference between the paths is
dominated by signature size, not by quorum size: FROST's aggregate
is one 64-byte signature for any quorum, while the ML-DSA path
carries one 3309-byte signature per checkpoint. A naive design that
stores one ML-DSA signature per validator in the quorum costs 4x
the ML-DSA quorum figure at quorum 4. These are signature-bytes
only; full checkpoint records carry additional fields.

## 4. Custody storage per validator key

[FAKTA] FROST share: 32 bytes per holder. ML-DSA-65 Shamir share:
4032 bytes + 1 identifier byte per holder. Full ML-DSA-65 secret
key: 4032 bytes; public key: 1952 bytes (FIPS 204 Table 2,
measured).

[ANALISIS] Storage is not the binding constraint for either path: a
4032-byte share is trivial to store. The binding constraints are
the reconstruction risk (Path B), the scheme change (Path A), and
the ceremony and network costs — not bytes.
