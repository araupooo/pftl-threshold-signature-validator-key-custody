# Primary Sources

All sources below were accessed 2026-11-16 unless noted. Only
primary sources are cited for specification-derived claims: the RFC
text, the FIPS documents, the NIST call, the ePrint papers, and the
XRPL documentation. Community and vendor material is not used for
specification claims.

## Threshold signing and Schnorr

1. RFC 9591 — D. Connolly, C. Komlo, I. Goldberg, C. A. Wood,
   "Two-Round Threshold Schnorr Signatures with FROST", June 2024,
   CFRG/IRTF, Informational (not Internet Standards Track).
   https://www.rfc-editor.org/rfc/rfc9591.txt
   https://www.rfc-editor.org/info/rfc9591
   Used for: FROST protocol (§4–§5), Ed25519 ciphersuite (§6.1),
   trusted-dealer key generation (Appendix C), test vectors
   (Appendix E.1). Key facts verified against the text during this
   build: Schnorr-only ciphersuites; key generation out of scope;
   two-round signing; nonce rules (§4.1, §7.3); binding factors
   (§4.4); below-quorum aggregates do not verify (§5.3).

2. RFC 8032 — S. Josefsson, I. Liusvaara, "Edwards-Curve Digital
   Signature Algorithm (EdDSA)", January 2017.
   https://www.rfc-editor.org/rfc/rfc8032.txt
   Used for: Ed25519 point encoding/decoding (§5.1.2–§5.1.3) and
   signature verification (§5.1.7), as referenced by RFC 9591 §6.1.

3. Shamir, A., "How to share a secret", Communications of the ACM
   22(11), 1979, pp. 612–613. https://doi.org/10.1145/359168.359176
   Used for: Shamir secret sharing (threshold reconstruction,
   information-theoretic security of below-threshold sets).

## Post-quantum signatures and threshold cryptography

4. FIPS 204 — NIST, "Module-Lattice-Based Digital Signature
   Standard (ML-DSA)", final, 2024-08-13.
   https://doi.org/10.6028/NIST.FIPS.204
   Used for: ML-DSA-44/65/87 sizes (Table 2: pk/sk/sig), asserted
   and re-measured in this pack (see `logs/costs.log`).

5. NIST IR 8214C — L. T. A. N. Brandão, R. Peralta, "NIST First Call
   for Multi-Party Threshold Schemes", final version, January 2026.
   https://doi.org/10.6028/NIST.IR.8214C
   https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8214C.pdf
   Used for: the scope of the NIST threshold call (Class N
   NIST-specified primitives, Class S special primitives; submission
   package = technical specification + reference implementation +
   experimental evaluation). No standardized threshold ML-DSA exists
   under this call as of November 2026.

6. Celi, S., del Pino, R., Espitau, T., Niot, G., Prest, T.,
   "Efficient Threshold ML-DSA", Cryptology ePrint Archive,
   Paper 2026/013; to appear at USENIX Security 2026.
   https://eprint.iacr.org/2026/013
   https://eprint.iacr.org/2026/013.pdf
   Used for: authors' claim of the first practical ML-DSA-compatible
   threshold scheme (up to 6 parties, ≤1 MB communication per party
   on average, Go implementation). Research claim, not a standard.

7. Bienstock, A., et al., "Quorus", Cryptology ePrint Archive,
   Paper 2025/1163; USENIX Security 2025.
   https://eprint.iacr.org/2025/1163
   Used for: authors' reported properties (MPC-based threshold
   ML-DSA, ~150 KB per party per round, honest-majority, signatures
   verify under unmodified ML-DSA verifiers). Research claim.

8. Borin, G., Celi, S., del Pino, R., Espitau, T., Niot, G., Prest, T.,
   "Threshold Signatures Reloaded: ML-DSA and Enhanced Raccoon with
   Identifiable Aborts", Cryptology ePrint Archive, Paper 2025/1166.
   https://eprint.iacr.org/2025/1166
   Used for: the design space of Fiat-Shamir lattice threshold
   signatures; the ML-DSA-compatible construction behind paper 6.

9. Mithril — Celi et al., NIST MPTC preview v1.0, 2026-01-19
   (submission preview to the NIST IR 8214C call).
   Used for: authors' reported properties (replicated secret
   sharing, short shares, DKG + sharing of an existing key
   preserving the public key, signing <20 ms local / <1 s WAN,
   up to 8 parties). Research claim; the preview is listed on the
   NIST MPTC project pages (https://csrc.nist.gov/Projects/pec/threshold).

10. TALUS — NIST MPTC preview v0.22, 2026-08-11 (submission preview
    to the NIST IR 8214C call).
    Used for: authors' reported properties (Boundary Clearance
    Condition, FIPS-204-exact signatures, two-round online phase,
    mandatory key rotation). Research claim.

11. Pebble — Silence Labs, "Pebble: Threshold ML-DSA",
    2026-07-28.
    https://silencelaboratories.com/papers/pebble-normal-threshold-ml-dsa.pdf
    Used for: the technical reason threshold ML-DSA is hard (ML-DSA
    responses are short integer vectors from rejection sampling;
    partial signatures must pass standard verification when
    aggregated) and the authors' reported design (discrete-Gaussian
    partial nonces, Pebble-ADA quorum identity). Research claim.

## Ledger and voting model

12. XRPL documentation — "Configure Amendment Voting", xrpl.org.
    https://xrpl.org/docs/infrastructure/configuration/configure-amendment-voting
    Used for: amendment voting mechanics in the XRPL-derived model
    (validators vote on amendments; >80% of trusted validators
    required). Accessed 2026-11-16.

13. XRPL Dashboard — "How the vote works",
    https://xrpldashboard.com/amendments/how-it-works
    Used for: the 14-day support rule and flag-ledger counting
    (every 256th ledger) in the XRPL amendment model.
    Accessed 2026-11-16.

## Implementations used for measurement

14. liboqs 0.16.0 (Open Quantum Safe), C library + liboqs-python
    0.16.0. https://github.com/open-quantum-safe/liboqs
    Used for: ML-DSA-44/65/87 key generation, signing, verification
    (`scripts/measure_costs.py` via liboqs-python;
    `scripts/custody_drill.py` via the ctypes binding in
    `scripts/oqs_ctypes.py`, because liboqs-python exposes no
    secret-key import).

15. FROST implementation in this pack: `scripts/frost_ed25519.py`,
    pure-Python implementation of RFC 9591 FROST(Ed25519, SHA-512),
    validated against the RFC 9591 Appendix E.1 test vectors
    (`scripts/check_frost_vectors.py`: 20 checks, all pass).
    Not a production implementation: no constant-time guarantees,
    no side-channel mitigations (see RFC 9591 §7.1).
