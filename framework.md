# Threshold-Signature Validator Key Custody: Decision Framework

How a validator key can be custodied so that one compromised share
cannot authorize amendment votes or checkpoint signatures. Two
custody paths are assessed: genuine threshold signing (FROST, Schnorr
only) and Shamir-shared custody of an ML-DSA key (shared custody with
reconstruction — not threshold signing). The framework states, for
each path, what it proves, what it does not prove, and where the
group key must change.

Every substantive claim in this document carries exactly one label:
[FAKTA] (verified fact with source and date), [ESTIMASI] (a modelled
or reported number, never stated as a measured fact), or [ANALISIS]
(interpretation, never presented as fact). The drill evidence for
each claim is indexed in `claims.md`.

## 0. The one distinction the whole framework turns on

[FAKTA] FROST (RFC 9591, June 2024) is a threshold signing protocol
for Schnorr signatures only: its ciphersuites are Ed25519, Ed448,
ristretto255, P-256, and secp256k1, and its signatures verify as
standard Schnorr/EdDSA signatures. Key generation is out of scope of
the RFC. Source: RFC 9591 §1, §6 (accessed 2026-11-16).

[FAKTA] There is no standardized threshold ML-DSA scheme as of
November 2026. Threshold ML-DSA is active research under NIST's First
Call for Multi-Party Threshold Schemes (NIST IR 8214C, final version
January 2026), which solicits public submission packages (technical
specification, reference implementation, experimental evaluation).
Source: NIST IR 8214C (DOI 10.6028/NIST.IR.8214C), accessed
2026-11-16.

[FAKTA] FROST cannot threshold-sign ML-DSA. The two schemes rest on
different mathematics: FROST aggregates linear Schnorr responses over
a prime-order group; ML-DSA responses are short integer vectors
produced by rejection sampling, and partial signatures must pass
standard ML-DSA verification when aggregated. Source: RFC 9591 §1;
Pebble paper (Silence Labs, 2026-07-28), §1.

[ANALISIS] Any custody design that claims "threshold ML-DSA" today is
either (a) Shamir-shared custody with reconstruction, which
re-exposes a single key at signing time, or (b) one of the research
schemes in §2, which are not standardized. The honest vocabulary is:
"threshold signing" only for the FROST path; "shared custody" for
the ML-DSA path. Conflating the two is the single most dangerous
error in this area, because it makes a reconstruction-risk design
look like it has the security property it lacks.

## 1. Scheme selection

### 1.1 Path A — FROST threshold signing (deployable now, Schnorr only)

[FAKTA] FROST is specified in RFC 9591 (June 2024, CFRG/IRTF,
informational — not Internet Standards Track). It needs two rounds to
produce a signature; single-round variants are out of scope. FROST
signatures verify with a standard EdDSA verifier (RFC 8032). Source:
RFC 9591 Abstract, §1, §5, §6.1 (accessed 2026-11-16).

[FAKTA] FROST assumes an adversary corrupts strictly fewer than the
threshold number of signer participants (RFC 9591 §1). A quorum of
`t` signers produces a signature that verifies under the group
public key; fewer than `t` shares cannot. Source: RFC 9591 §1, §5.3.

[FAKTA] FROST key generation is out of scope of RFC 9591; Appendix C
specifies trusted-dealer key generation (Shamir sharing of the group
secret over the scalar field) for completeness only. Distributed key
generation is not specified. Source: RFC 9591 §1, Appendix C.

[FAKTA] Nonces in FROST are generated with `nonce_generate` (RFC 9591
§4.1): fresh 32-byte randomness combined with the secret share under
a domain-separated hash (H3). Nonces MUST NOT be reused across
signing operations; deterministic nonce derivation allows a complete
key-recovery attack in multi-party Schnorr signing. Source: RFC 9591
§1, §4.1, §5.1, §7.3.

[ANALISIS] Path A is the only path in this framework that genuinely
removes the single-key point of failure at signing time. Its cost is
a scheme change: validator keys must be Schnorr (Ed25519) keys, not
ML-DSA keys. Where the validator signing scheme is fixed to ML-DSA,
Path A cannot be used for the validator key itself — it can only
protect adjacent Schnorr keys (e.g. a separate amendment-vote
signing key, if the ledger accepts Ed25519 votes).

### 1.2 Path B — ML-DSA key under Shamir-shared custody (deployable now, with reconstruction risk)

[FAKTA] ML-DSA is standardized in FIPS 204 (final, 2024-08-13).
ML-DSA-65 (security category 3) has public key 1952 bytes, secret
key 4032 bytes, signature 3309 bytes (FIPS 204 Table 2). The sizes
were re-measured in this pack with liboqs 0.16.0: see
`cost-table.md` §1 and `logs/costs.log`.

[FAKTA] Shamir secret sharing (Shamir, 1979, "How to share a
secret", Communications of the ACM 22(11)) splits a secret into `n`
shares such that any `t` reconstruct it and any `t-1` reveal no
information about it (information-theoretic). The drill shares the
4032-byte ML-DSA secret key byte-wise over GF(256).

[ANALISIS] Path B protects the key AT REST: one compromised share
reveals nothing about the ML-DSA secret key, and one compromised
share cannot sign anything on its own. It does NOT protect the key
AT SIGNING TIME: a quorum must reconstruct the full secret key to
produce an ML-DSA signature, and at that moment the reconstructed
key is a single point of failure — whoever holds the reconstructed
key (the signing ceremony host, or any quorum of colluding holders)
can sign anything. The drill proves both halves: quorum
reconstruction signs and verifies (logs/run-1.log, Phase 2), and
below-quorum reconstruction produces a wrong key whose signatures
fail verification.

[ANALISIS] Path B is therefore suitable only where the signing
ceremony itself is trusted and short-lived (reconstruct, sign,
erase), or where the threat model is share theft at rest rather than
signing-time compromise. It must never be described as "threshold
signing".

### 1.3 Path C — threshold ML-DSA research (not deployable; track it)

[FAKTA] The following schemes are submissions or previews to NIST's
first Multi-Party Threshold Cryptography call (NIST IR 8214C). None
is standardized, none has completed NIST evaluation, and none is
recommended for production custody. Reported properties below are
the authors' claims, not this pack's measurements.

- [FAKTA] Mithril (Celi et al., preview v1.0, 2026-01-19): replicated
  secret sharing with short shares; distributed key generation and
  sharing of an existing key while preserving the public key;
  authors report signing under 20 ms locally and under 1 s over a
  wide-area network, for up to 8 parties.
- [FAKTA] Quorus (Bienstock et al., ePrint 2025/1163, USENIX Security
  2025): MPC-based threshold ML-DSA; authors report about 150 KB per
  party per round under an honest-majority assumption; signatures
  verify under unmodified ML-DSA verifiers.
- [FAKTA] Efficient Threshold ML-DSA (Celi, del Pino, Espitau, Niot,
  Prest, ePrint 2026/013; to appear at USENIX Security 2026): the
  authors present it as the first threshold signature scheme fully
  compatible with ML-DSA, supporting up to 6 parties with at most
  1 MB of communication per party on average; Go implementation;
  communication reported from 10.5 kB to 525 kB depending on
  threshold.
- [FAKTA] TALUS (preview v0.22, 2026-08-11): authors describe a
  "Boundary Clearance Condition", FIPS-204-exact signatures verified
  under an independent dilithium implementation, a two-round online
  phase, and mandatory key rotation.
- [FAKTA] Pebble (Silence Labs, 2026-07-28): discrete-Gaussian
  partial nonces; authors describe a "Pebble-ADA" quorum identity
  for identifiable abort.

[FAKTA] ML-DSA threshold signing is hard because ML-DSA responses
are short integer vectors from rejection sampling: partial
signatures must pass standard verification when aggregated (Pebble
paper, §1).

[ANALISIS] Path C is the correct long-term direction for ML-DSA
validator keys, but adopting any of these schemes before NIST
evaluation completes would trade a standardized primitive for an
unreviewed protocol. The framework's recommendation is: deploy Path
A where Schnorr keys are acceptable, Path B where ML-DSA keys are
mandatory and the ceremony is trusted, and re-evaluate Path C after
the NIST MPTC call produces evaluated submissions.

## 2. Share generation and distribution

### 2.1 Generation

[FAKTA] RFC 9591 specifies trusted-dealer key generation only as an
appendix (Appendix C): a random group secret, a random polynomial of
degree `t-1` with the secret as constant term, share `f(i)` for
participant `i`. The dealer learns the secret and must be trusted
and then erased. Source: RFC 9591 Appendix C.

[ANALISIS] A trusted dealer is the weakest link of both Path A and
Path B at setup time. For Path A, distributed key generation (DKG)
removes the dealer but is not specified in RFC 9591; any DKG used
must be a separately audited protocol. For Path B, the dealer holds
the full ML-DSA key during sharing and must be an air-gapped,
single-use ceremony host. In both paths, the drill uses a fresh
dealer per run (test keys only) and prints only hashes of secrets.

[FAKTA] FROST shares are 32-byte scalars (mod the group order L);
ML-DSA-65 Shamir shares are 4032 bytes each (one byte per secret-key
byte) plus a 1-byte identifier. Measured: see `cost-table.md` §1.

### 2.2 Distribution

[ANALISIS] Shares must travel over authenticated channels (RFC 9591
§5 assumes authenticated channels; an attacker masquerading as a
participant yields only an invalid signature, §5, §7). In practice:
each share encrypted to its holder's long-term key, delivered
out-of-band from the other shares, with a public commitment to the
share (e.g. the holder's share public key `PK_i = share_i * B` for
FROST) published so the coordinator can detect a wrong share before
signing. The drill demonstrates the detection property: a quorum
containing one foreign share produces an invalid aggregate
signature (logs/run-1.log, Phase 1).

[ANALISIS] Share identifiers must be distinct non-zero scalars in
`[1, MAX_PARTICIPANTS]` (RFC 9591 §5). Identifier reuse across
quorums, or two holders sharing one identifier, breaks the Lagrange
interpolation the protocol depends on.

## 3. Quorums

[FAKTA] FROST requires `MIN_PARTICIPANTS <= NUM_PARTICIPANTS <=
MAX_PARTICIPANTS` (RFC 9591 §5). The drill uses `n=5, t=3` for the
live quorum proofs and measures `2-of-3, 3-of-5, 4-of-7, 5-of-7` in
`cost-table.md`.

[ANALISIS] Quorum choice is a three-way trade: a low threshold
(`t=2`) keeps signing available when holders are offline but lets
any 2 colluding holders sign; a high threshold (`t=4-of-5`) needs 4
honest holders for liveness and tolerates only 1 faulty holder. For
amendment votes — which are infrequent, high-stakes, and have long
voting windows — a high threshold is affordable. For checkpoint
signing — frequent and liveness-sensitive — a lower threshold with
fast rotation is the better trade. The framework recommends deciding
the two quorums separately rather than sharing one threshold for
both operations.

[ANALISIS] The quorum must be bound to the message: FROST binding
factors are computed from the group public key, the commitment list,
and the message hash (RFC 9591 §4.4), so a signature share made for
one checkpoint cannot be replayed for another. The drill proves
this: a signature for one checkpoint height is rejected for another
height (logs/run-1.log, Phase 1).

## 4. Rotation and revocation

### 4.1 Refresh without changing the group key (both paths)

[FAKTA] Proactive share refresh replaces each share with a new share
of the SAME secret: a new random polynomial with constant term 0 is
added to the old shares (FROST) or the secret is re-shared under a
new random polynomial with the same constant term (ML-DSA). The
group public key is unchanged, so no ledger update is needed. The
drill proves the group key is unchanged (full SHA-256 comparison
before and after refresh) for both paths.

[FAKTA] Refresh does NOT revoke old shares. The drill PROVES this
limitation for both paths: after refresh, a quorum of pre-refresh
shares still signs (FROST) and still reconstructs the key (ML-DSA).
Old shares remain valid until a rekey. Any rotation plan that claims
refresh alone revokes a compromised share is wrong.

[ANALISIS] Refresh still has value: it bounds the window in which a
slowly-accumulating attacker can collect shares (an attacker who
steals one share per epoch never reaches quorum if shares refresh
faster than they are stolen), and it makes mixed old/new quorums
fail — the drill proves a mixed old+new quorum produces an invalid
signature in both paths, so a rotation can be enforced by
version-binding shares to an epoch and rejecting stale epochs at the
coordinator.

### 4.2 Full rekey (group key changes)

[FAKTA] Full rekey generates a fresh keypair (new dealer run for
FROST, new ML-DSA keypair for Path B) and distributes fresh shares.
The group public key changes. The drill proves: the new group key
differs (full SHA-256 comparison), the new quorum signs under the
new key, and old shares cannot produce a valid signature under the
new key.

[ANALISIS] Rekey is the only revocation mechanism that actually
kills a compromised share. Its cost is a ledger update: the new
group public key must be registered as the validator's key, which
for amendment voting means an on-ledger key change that itself must
be authorized. A compromised-share response plan must therefore
pre-authorize an emergency rekey path (e.g. a pre-registered
standby key) or the response will be blocked by the same key it is
trying to replace.

## 5. Compromise response

[ANALISIS] Response depends on what was compromised, and the
framework distinguishes four cases:

1. One share compromised, no quorum reached: rotate by refresh
   (cheap, group key kept) AND schedule a rekey, because refresh
   alone does not revoke the stolen share. Treat the holder as
   untrusted until rekeyed; exclude them from quorums in the
   meantime by version-binding.
2. A quorum of shares compromised: the key is compromised. Rekey
   immediately (new group key, new shares, old key revoked on the
   ledger). Any signatures produced after the compromise time and
   before rekey must be treated as suspect and re-validated against
   an independent record.
3. The signing ceremony host compromised (Path B only): the
   reconstructed key may have been copied. This is equivalent to
   case 2 — rekey. Path B's ceremony host is a single point of
   failure by design; the response plan must assume it.
4. A nonce reused or leaked (Path A): RFC 9591 §7.3 — nonce reuse
   in multi-party Schnorr signing allows complete key recovery.
   Treat as case 2 (rekey) even if only one nonce leaked.

[ANALISIS] Detection is the hard part: a stolen share is silent.
The framework recommends share-use auditing (each signing ceremony
logs which share identifiers participated, and the log is itself
hash-chained), plus liveness probes (a quorum member that stops
responding to signing requests is investigated, not just routed
around).

## 6. Voting and checkpoint compatibility limits

### 6.1 What was verified, and what was not

[FAKTA] No public specification of the PFTL validator key lifecycle,
amendment-vote signature format, or checkpoint signature format was
located during this build (searched 2026-11-16). The compatibility
limits in this section are therefore [ANALISIS] built on the public
XRPL-derived amendment model, not on verified PFTL documentation.
If PFTL publishes validator key documentation, this section must be
revised against it.

[FAKTA] In the XRPL amendment model (the ledger family PFTL derives
from), an amendment activates only when more than 80% of trusted
validators vote for it, with support held for 14 consecutive days
and votes counted at flag ledgers (every 256th ledger). Source:
XRPL documentation, "Configure Amendment Voting" and amendment
process pages (xrpl.org; xrpldashboard.com/amendments/how-it-works),
accessed 2026-11-16.

### 6.2 Limits

[ANALISIS] Amendment votes are single-validator, single-key
operations in the XRPL model: each validator votes with its own
validator key. Threshold custody of ONE validator's key changes how
that validator authorizes its own vote; it does not change the
80%-of-validators rule, which counts validators, not shares. A
custody quorum of 3-of-5 INSIDE one validator is not the same as 3
of 5 validators on the network, and the two thresholds must never be
confused in a vote-counting argument.

[ANALISIS] Checkpoint signatures face the same limit: a checkpoint
signature is attributed to one validator identity (one group public
key). FROST's aggregate signature verifies as an ordinary Ed25519
signature under the group key, so a ledger that accepts Ed25519
validator signatures accepts a FROST aggregate with no protocol
change — but only if the validator's registered key is the FROST
group key and the ledger's signature scheme is Ed25519. If the
ledger mandates ML-DSA validator signatures, Path A cannot sign
checkpoints at all, and Path B's reconstructed-key signature is an
ordinary ML-DSA signature (verifiable under the group key with no
protocol change), at the cost of the reconstruction risk in §1.2.

[ANALISIS] Rekey interacts with the 80%/14-day amendment rule: if a
validator's key changes mid-vote, its earlier votes were cast under
the old key and the new key's votes start fresh. An emergency rekey
during an amendment vote can therefore reset that validator's
contribution to the vote. Rekeys should be scheduled outside active
amendment votes where possible, and the response plan must account
for the lost vote if it cannot wait.

[ANALISIS] FROST is a two-round protocol with a coordinator (RFC 9591
§5). The coordinator is trusted to choose the signing set and
aggregate shares, but a malicious coordinator can only cause an
invalid signature, not a forgery (RFC 9591 §5, §7.5). For validator
operations, the coordinator role should sit with the validator
operator's own infrastructure, not with a third party, and signing
rounds must complete inside the checkpoint interval — the measured
full-round latencies (0.07–0.28 s for quorums 2–5 in pure Python;
see `cost-table.md`) leave ample margin inside any realistic
checkpoint interval, but these are local-computation figures only:
network round-trips between share holders are not measured here and
dominate in deployment.

## 7. Recommendation

[ANALISIS] For a validator key that must be ML-DSA: use Path B
(Shamir-shared custody, `n=5, t=3`) with a trusted, short-lived,
audited signing ceremony; refresh shares on a fixed schedule;
pre-register a standby key so a quorum compromise can be answered
by immediate rekey; and track the NIST MPTC call for a future
migration to a standardized threshold ML-DSA scheme. For any
adjacent signing key the ledger accepts as Ed25519: use Path A
(FROST, `n=5, t=3`), which is the only path here that removes the
single-key point of failure at signing time. Never present Path B as
threshold signing, and never treat refresh as revocation.
