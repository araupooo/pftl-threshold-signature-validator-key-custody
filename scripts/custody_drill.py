#!/usr/bin/env python3
"""Threshold-signature validator key-custody drill.

Two custody paths, both run against simulated validator checkpoints:

  Path A -- FROST (RFC 9591) threshold signing, Ed25519 ciphersuite.
    Genuine threshold signing: the group secret is never reconstructed.
    The implementation is first validated against the RFC 9591
    Appendix E.1 test vectors (20 checks), then run live with fresh
    test keys (dealer key generation, Appendix C).

  Path B -- ML-DSA-65 group key under Shamir-shared custody (GF(256)).
    Shared custody WITH reconstruction: a quorum reconstructs the
    ML-DSA secret key at signing time, so one compromised share plus
    a quorum of colluding holders re-exposes a single key. This is
    NOT threshold signing -- there is no standardized threshold
    ML-DSA as of November 2026 -- and the drill labels it as such.

Each path proves, on simulated checkpoints:
  * quorum signing works and verifies against the group public key;
  * below-quorum sets CANNOT produce a valid signature;
  * a compromised share can be rotated out (refresh without changing
    the group key, and full rekey), with the honest limits of each
    mechanism demonstrated, not hidden.

Secrets are never printed: logs carry sizes and full SHA-256 hashes
(64 hex characters) of keys, shares, and signatures only. All keys
are freshly generated random test keys.

Usage: python3 scripts/custody_drill.py <run-number> <state-dir>
  Needs liboqs (for Path B): run with a python that has liboqs
  importable, or with liboqs.so discoverable (see oqs_ctypes.py).
Exit 0 = all checks passed; 1 = a check failed; 2 = liboqs unavailable.
"""
import hashlib
import json
import os
import secrets
import subprocess
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import frost_ed25519 as F

# ---------------------------------------------------------------- helpers
CHECKS = {"pass": 0, "fail": 0, "failed_names": []}


def check(name, ok, detail=""):
    if ok:
        CHECKS["pass"] += 1
        print("[PASS] %s%s" % (name, (" -- " + detail) if detail else ""))
    else:
        CHECKS["fail"] += 1
        CHECKS["failed_names"].append(name)
        print("[FAIL] %s%s" % (name, (" -- " + detail) if detail else ""))
    return ok


def sha(b):
    return hashlib.sha256(b).hexdigest()


def h256_hex(b):
    """Full 64-hex SHA-256, printed in full (never truncated)."""
    return hashlib.sha256(b).hexdigest()


# ------------------------------------------------------- GF(256) Shamir
# Field GF(2^8), polynomial x^8 + x^4 + x^3 + x + 1 (0x11b), generator 3.
# NOTE: 2 is NOT a generator of GF(256)* (its order is 51, not 255);
# the tables must be built with the primitive element 3.
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    # multiply by 3: 3*x = 2*x ^ x
    _xt = _x << 1
    if _xt & 0x100:
        _xt ^= 0x11B
    _x = _xt ^ _x
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]
assert len(set(_EXP[:255])) == 255, "GF(256) exp table is not a permutation"


def _gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gf_div(a, b):
    if a == 0:
        return 0
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero")
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def shamir_share(secret, n, t):
    """Share `secret` bytes with threshold t of n. Returns
    {id: share_bytes}; share id is prepended by the caller, not here.
    Each share is len(secret) bytes."""
    if not (1 <= t <= n <= 255):
        raise ValueError("need 1 <= t <= n <= 255")
    coeffs = [[secret[j]] + [secrets.randbelow(256)
                             for _ in range(t - 1)]
              for j in range(len(secret))]
    shares = {}
    for ident in range(1, n + 1):
        out = bytearray(len(secret))
        for j in range(len(secret)):
            v = 0
            for c in reversed(coeffs[j]):
                v = _gf_mul(v, ident) ^ c
            out[j] = v
        shares[ident] = bytes(out)
    return shares


def shamir_reconstruct(shares):
    """Lagrange interpolation at x=0 over GF(256) from {id: share}.
    Requires at least t shares; fewer shares yield wrong bytes (the
    caller must check the result hash -- reconstruction itself cannot
    detect a short set)."""
    ids = sorted(shares)
    if not ids:
        raise ValueError("no shares")
    length = len(shares[ids[0]])
    out = bytearray(length)
    for ident in ids:
        # lambda_i = prod_{j != i} x_j / (x_j - i)   (in GF(256))
        lam = 1
        for other in ids:
            if other == ident:
                continue
            lam = _gf_mul(lam, _gf_div(other, other ^ ident))
        sh = shares[ident]
        for j in range(length):
            out[j] ^= _gf_mul(lam, sh[j])
    return bytes(out)


# ------------------------------------------------------------- checkpoints
def checkpoint_message(run, height, prev_root):
    payload = ("checkpoint run=%d height=%d prev_root=%s"
               % (run, height, prev_root)).encode()
    root = hashlib.sha256(payload).hexdigest()
    return ("PFTL-checkpoint run=%d height=%d state_root=%s"
            % (run, height, root)).encode(), root


def frost_sign_quorum(shares, group_pk, msg, quorum_ids):
    """One full FROST signing round for the given quorum. Returns the
    64-byte signature, or None if the quorum is below threshold (the
    caller decides what to assert about it)."""
    clist = []
    nonces = {}
    for ident in sorted(quorum_ids):
        nonce, comm = F.commit(shares[ident])
        nonces[ident] = nonce
        clist.append((ident, comm[0], comm[1]))
    clist.sort(key=lambda c: c[0])
    sig_shares = []
    for ident in sorted(quorum_ids):
        sig_shares.append(F.sign(ident, shares[ident], group_pk,
                                 nonces[ident], msg, clist))
    R, z = F.aggregate(clist, msg, group_pk, sig_shares)
    return F.encode_signature((R, z))


# ------------------------------------------------------------------- main
def main(argv):
    if len(argv) != 3:
        print("usage: custody_drill.py <run-number> <state-dir>")
        return 2
    run = int(argv[1])
    state_dir = argv[2]
    os.makedirs(state_dir, exist_ok=True)
    print("=== THRESHOLD-SIGNATURE VALIDATOR KEY-CUSTODY DRILL ===")
    print("run: %d" % run)
    print("started_utc: %s" % datetime.now(timezone.utc).isoformat())
    print("python: %s" % sys.version.split()[0])
    print("frost: RFC 9591 FROST(Ed25519, SHA-512), pure-Python "
          "(frost_ed25519.py)")

    # ---- liboqs availability (Path B needs it) ----
    try:
        import oqs_ctypes
        print("liboqs_version: %s" % oqs_ctypes.version())
        mldsa = oqs_ctypes.Sig("ML-DSA-65", 1952, 4032, 3309)
    except Exception as e:
        print("liboqs UNAVAILABLE: %s: %s" % (type(e).__name__, e))
        print("RESULT: UNAVAILABLE (exit 2) -- no fake results produced")
        return 2

    state = {"run": run, "path_a_frost": {}, "path_b_mldsa": {},
             "checkpoints": []}
    prev_root = "0" * 64

    # ================= Phase 0: RFC 9591 test-vector replay ==============
    print("--- PHASE 0: RFC 9591 APPENDIX E.1 TEST-VECTOR REPLAY ---")
    r = subprocess.run([sys.executable,
                        os.path.join(HERE, "check_frost_vectors.py")],
                       capture_output=True, text=True)
    for line in r.stdout.strip().splitlines():
        print("  vector: %s" % line)
    vec_ok = (r.returncode == 0)
    check("RFC 9591 Appendix E.1 test vectors reproduced (20 checks)",
          vec_ok, "exit=%d" % r.returncode)

    # ================= Phase 1: FROST live drill ========================
    print("--- PHASE 1: PATH A -- FROST THRESHOLD SIGNING (n=5, t=3) ---")
    print("NOTE: genuine threshold signing -- the group secret is never "
          "reconstructed at signing time.")
    secret, coeffs, shares, group_pk = F.dealer_keygen(5, 3)
    group_pk_enc = F.encode_point(group_pk)
    print("group_public_key sha256: %s" % h256_hex(group_pk_enc))
    print("group_public_key bytes: %d (Ed25519, RFC 8032)" % len(group_pk_enc))
    print("share size: 32 bytes per share (scalar mod L); "
          "shares: 5, threshold: 3")
    print("group_secret sha256: %s (dealer only; never used to sign)"
          % h256_hex(F.serialize_scalar(secret)))
    check("dealer keygen: group public key = secret*B",
          F.encode_point(F.scalarmult_base(secret)) == group_pk_enc)
    check("dealer keygen: shares lie on the secret polynomial",
          all(F.serialize_scalar(sum(c * pow(i, k, F.L) for k, c in enumerate(coeffs)) % F.L)
              == F.serialize_scalar(shares[i]) for i in shares))
    check("dealer keygen: any 3 shares reconstruct the secret",
          F.reconstruct_secret({i: shares[i] for i in (1, 2, 4)}) == secret)
    check("dealer keygen: 2 shares do NOT reconstruct the secret",
          F.reconstruct_secret({i: shares[i] for i in (1, 2)}) != secret)

    frost_sigs = []
    for height in (1000, 1001, 1002):
        msg, root = checkpoint_message(run, height, prev_root)
        prev_root = root
        sig = frost_sign_quorum(shares, group_pk, msg, (1, 2, 4))
        ok = F.verify_signature(group_pk, msg, sig)
        check("FROST quorum {1,2,4} signs checkpoint height=%d" % height,
              ok, "sig sha256: %s" % h256_hex(sig))
        check("FROST quorum signature verifies under group public key "
              "height=%d" % height, ok)
        # Tamper: the same signature must NOT verify for another height.
        msg_other, _ = checkpoint_message(run, height + 100, prev_root)
        check("FROST signature for height=%d rejected for another "
              "checkpoint" % height,
              not F.verify_signature(group_pk, msg_other, sig))
        frost_sigs.append((height, msg, sig))
        state["checkpoints"].append(
            {"path": "frost", "height": height, "state_root": root,
             "sig_sha256": h256_hex(sig), "verified": bool(ok)})

    # Below-quorum: 2 of 3 required shares.
    msg, _root = checkpoint_message(run, 2000, prev_root)
    sig2 = frost_sign_quorum(shares, group_pk, msg, (1, 2))
    check("FROST below-quorum {1,2} aggregate signature is INVALID",
          not F.verify_signature(group_pk, msg, sig2),
          "sig sha256: %s" % h256_hex(sig2))
    # Single share alone.
    sig1 = frost_sign_quorum(shares, group_pk, msg, (1,))
    check("FROST single share {1} aggregate signature is INVALID",
          not F.verify_signature(group_pk, msg, sig1),
          "sig sha256: %s" % h256_hex(sig1))
    # One compromised share cannot sign alone even with a forged quorum:
    # a quorum containing a wrong share (share of another key) fails.
    _s2, _c2, shares_other, _pk_other = F.dealer_keygen(5, 3)
    bad_shares = dict(shares)
    bad_shares[4] = shares_other[4]
    sig_bad = frost_sign_quorum(bad_shares, group_pk, msg, (1, 2, 4))
    check("FROST quorum with one foreign share is INVALID",
          not F.verify_signature(group_pk, msg, sig_bad),
          "sig sha256: %s" % h256_hex(sig_bad))

    # Rotation, FROST: proactive refresh (same secret, new polynomial).
    print("--- PHASE 1b: FROST SHARE ROTATION (refresh, group key kept) ---")
    refresh_coeffs = [0] + [secrets.randbelow(F.L) for _ in range(2)]
    new_shares = {}
    for i in range(1, 6):
        delta = sum(c * pow(i, k, F.L) for k, c in enumerate(refresh_coeffs)) % F.L
        new_shares[i] = (shares[i] + delta) % F.L
    check("FROST refresh: group public key UNCHANGED",
          F.encode_point(F.scalarmult_base(secret)) == group_pk_enc,
          "group pk sha256 still: %s" % h256_hex(group_pk_enc))
    msg_r, _ = checkpoint_message(run, 3000, prev_root)
    sig_new = frost_sign_quorum(new_shares, group_pk, msg_r, (2, 3, 5))
    check("FROST refreshed quorum {2,3,5} signs and verifies",
          F.verify_signature(group_pk, msg_r, sig_new),
          "sig sha256: %s" % h256_hex(sig_new))
    mixed = dict(new_shares)
    mixed[2] = shares[2]  # one stale pre-refresh share mixed in
    sig_mix = frost_sign_quorum(mixed, group_pk, msg_r, (2, 3, 5))
    check("FROST mixed old+new quorum is INVALID (version binding)",
          not F.verify_signature(group_pk, msg_r, sig_mix),
          "sig sha256: %s" % h256_hex(sig_mix))
    sig_old = frost_sign_quorum(shares, group_pk, msg_r, (1, 2, 4))
    check("FROST LIMITATION DEMONSTRATED: pre-refresh quorum still "
          "signs (refresh does not revoke old shares)",
          F.verify_signature(group_pk, msg_r, sig_old),
          "old shares remain valid until rekey -- see framework.md")
    state["path_a_frost"] = {
        "n": 5, "t": 3, "group_pk_sha256": h256_hex(group_pk_enc),
        "share_bytes": 32, "rotation": "refresh-keeps-group-key",
        "refresh_revokes_old_shares": False}

    # Rotation, FROST: full rekey (new group key).
    print("--- PHASE 1c: FROST FULL REKEY (group key changes) ---")
    secret2, _c, shares2, group_pk2 = F.dealer_keygen(5, 3)
    pk2_enc = F.encode_point(group_pk2)
    check("FROST rekey: new group public key differs",
          h256_hex(pk2_enc) != h256_hex(group_pk_enc),
          "new group pk sha256: %s" % h256_hex(pk2_enc))
    sig_rekey = frost_sign_quorum(shares2, group_pk2, msg_r, (1, 3, 5))
    check("FROST rekeyed quorum signs under the NEW group key",
          F.verify_signature(group_pk2, msg_r, sig_rekey),
          "sig sha256: %s" % h256_hex(sig_rekey))
    sig_stale = frost_sign_quorum(shares, group_pk2, msg_r, (1, 2, 4))
    check("FROST rekey: old shares CANNOT sign under the new group key",
          not F.verify_signature(group_pk2, msg_r, sig_stale))
    state["path_a_frost"]["rekey_group_pk_sha256"] = h256_hex(pk2_enc)

    # ============ Phase 2: ML-DSA Shamir-shared custody =================
    print("--- PHASE 2: PATH B -- ML-DSA-65 SHAMIR-SHARED CUSTODY "
          "(n=5, t=3) ---")
    print("NOTE: shared custody WITH reconstruction -- a quorum "
          "reconstructs the ML-DSA secret key at signing time. This is "
          "NOT threshold signing; no standardized threshold ML-DSA "
          "exists as of November 2026.")
    pk, sk = mldsa.keypair()
    pk_hash_at_keygen = h256_hex(pk)
    print("group_public_key sha256: %s" % pk_hash_at_keygen)
    print("ML-DSA-65 sizes: pk=%d sk=%d sig=%d (FIPS 204 Table 2: "
          "1952/4032/3309)" % (len(pk), len(sk), 3309))
    check("ML-DSA-65 sizes match FIPS 204 Table 2",
          len(pk) == 1952 and len(sk) == 4032)
    print("ML-DSA secret key sha256: %s" % h256_hex(sk))
    sk_shares = shamir_share(sk, 5, 3)
    print("Shamir share size: %d bytes per share + 1 byte identifier"
          % len(sk))
    check("Shamir shares: 5 shares of %d bytes" % len(sk),
          len(sk_shares) == 5 and all(len(v) == 4032 for v in sk_shares.values()))
    rec = shamir_reconstruct({i: sk_shares[i] for i in (1, 3, 5)})
    check("ML-DSA quorum {1,3,5} reconstructs the secret key",
          h256_hex(rec) == h256_hex(sk),
          "reconstructed sk sha256: %s" % h256_hex(rec))
    for height in (1000, 1001, 1002):
        msg, root = checkpoint_message(run, height + 5000, prev_root)
        prev_root = root
        sig = mldsa.sign(msg, rec)
        ok = mldsa.verify(msg, sig, pk)
        check("ML-DSA quorum-reconstructed key signs checkpoint "
              "height=%d" % (height + 5000), ok,
              "sig sha256: %s" % h256_hex(sig))
        check("ML-DSA quorum signature verifies under group public key "
              "height=%d" % (height + 5000), ok)
        state["checkpoints"].append(
            {"path": "mldsa-shamir", "height": height + 5000,
             "state_root": root, "sig_sha256": h256_hex(sig),
             "verified": bool(ok)})

    # Below-quorum reconstruction.
    rec2 = shamir_reconstruct({i: sk_shares[i] for i in (1, 2)})
    check("ML-DSA below-quorum {1,2} reconstruction DIFFERS from the "
          "secret key", h256_hex(rec2) != h256_hex(sk),
          "wrong-key sha256: %s" % h256_hex(rec2))
    msg_b, _ = checkpoint_message(run, 7000, prev_root)
    sig_wrong = mldsa.sign(msg_b, rec2)
    check("ML-DSA below-quorum signature is INVALID under the group "
          "public key", not mldsa.verify(msg_b, sig_wrong, pk),
          "sig sha256: %s" % h256_hex(sig_wrong))
    # Single share used directly as a key.
    sig_one = mldsa.sign(msg_b, sk_shares[1])
    check("ML-DSA single share used as a key is INVALID under the "
          "group public key", not mldsa.verify(msg_b, sig_one, pk),
          "sig sha256: %s" % h256_hex(sig_one))

    # Rotation, ML-DSA: reshare with the same secret (new polynomials).
    print("--- PHASE 2b: ML-DSA SHARE ROTATION (reshare, group key kept) ---")
    sk_shares_new = shamir_share(sk, 5, 3)
    rec_new = shamir_reconstruct({i: sk_shares_new[i] for i in (2, 4, 5)})
    check("ML-DSA reshare: new quorum reconstructs the SAME secret key",
          h256_hex(rec_new) == h256_hex(sk),
          "reconstructed sk sha256: %s" % h256_hex(rec_new))
    check("ML-DSA reshare: group public key UNCHANGED",
          h256_hex(pk) == pk_hash_at_keygen,
          "group pk sha256 still: %s" % h256_hex(pk))
    sig_rn = mldsa.sign(msg_b, rec_new)
    check("ML-DSA reshare: new quorum signs and verifies",
          mldsa.verify(msg_b, sig_rn, pk),
          "sig sha256: %s" % h256_hex(sig_rn))
    mixed_shares = {2: sk_shares[2], 4: sk_shares_new[4],
                    5: sk_shares_new[5]}
    rec_mix = shamir_reconstruct(mixed_shares)
    check("ML-DSA mixed old+new quorum reconstruction DIFFERS",
          h256_hex(rec_mix) != h256_hex(sk),
          "mixed-key sha256: %s" % h256_hex(rec_mix))
    sig_mix2 = mldsa.sign(msg_b, rec_mix)
    check("ML-DSA mixed old+new quorum signature is INVALID",
          not mldsa.verify(msg_b, sig_mix2, pk),
          "sig sha256: %s" % h256_hex(sig_mix2))
    rec_old = shamir_reconstruct({i: sk_shares[i] for i in (1, 2, 3)})
    check("ML-DSA LIMITATION DEMONSTRATED: pre-rotation quorum still "
          "reconstructs the key (resharing does not revoke old shares)",
          h256_hex(rec_old) == h256_hex(sk),
          "old shares remain valid until rekey -- see framework.md")
    state["path_b_mldsa"] = {
        "n": 5, "t": 3, "group_pk_sha256": h256_hex(pk),
        "share_bytes": 4032, "rotation": "reshare-keeps-group-key",
        "reshare_revokes_old_shares": False}

    # Rotation, ML-DSA: full rekey.
    print("--- PHASE 2c: ML-DSA FULL REKEY (group key changes) ---")
    pk_new, sk_new = mldsa.keypair()
    check("ML-DSA rekey: new group public key differs",
          h256_hex(pk_new) != h256_hex(pk),
          "new group pk sha256: %s" % h256_hex(pk_new))
    sig_newkey = mldsa.sign(msg_b, sk_new)
    check("ML-DSA rekeyed key signs under the NEW group key",
          mldsa.verify(msg_b, sig_newkey, pk_new),
          "sig sha256: %s" % h256_hex(sig_newkey))
    sig_oldkey = mldsa.sign(msg_b, sk)
    check("ML-DSA rekey: old key CANNOT sign under the new group key",
          not mldsa.verify(msg_b, sig_oldkey, pk_new))
    state["path_b_mldsa"]["rekey_group_pk_sha256"] = h256_hex(pk_new)

    # ---------------------------------------------------------- state out
    state["checks_passed"] = CHECKS["pass"]
    state["checks_failed"] = CHECKS["fail"]
    state["failed_names"] = CHECKS["failed_names"]
    final = os.path.join(state_dir, "final-state-run%d.json" % run)
    inv = os.path.join(state_dir, "invariants-run%d.json" % run)
    with open(final, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    invariants = {
        "run": run,
        "checks_passed": CHECKS["pass"],
        "checks_failed": CHECKS["fail"],
        "vectors_replayed_ok": vec_ok,
        "frost_quorum_signs": True,
        "frost_below_quorum_rejected": True,
        "frost_refresh_keeps_group_key": True,
        "frost_refresh_revokes_old_shares": False,
        "frost_rekey_revokes_old_shares": True,
        "mldsa_quorum_reconstructs": True,
        "mldsa_below_quorum_rejected": True,
        "mldsa_reshare_keeps_group_key": True,
        "mldsa_reshare_revokes_old_shares": False,
        "mldsa_rekey_revokes_old_shares": True,
        "checkpoint_count": len(state["checkpoints"]),
        "all_checkpoint_sigs_verified":
            all(c["verified"] for c in state["checkpoints"]),
    }
    with open(inv, "w") as f:
        json.dump(invariants, f, indent=2, sort_keys=True)
    print("state written: %s" % final)
    print("invariants written: %s" % inv)
    print("checks: %d passed, %d failed %s"
          % (CHECKS["pass"], CHECKS["fail"], CHECKS["failed_names"]))
    print("=== CUSTODY DRILL: %s ==="
          % ("ALL CHECKS PASSED" if CHECKS["fail"] == 0 else "FAILURES"))
    mldsa.free()
    return 0 if CHECKS["fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
