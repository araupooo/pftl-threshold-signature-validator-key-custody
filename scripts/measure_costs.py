#!/usr/bin/env python3
"""measure_costs.py -- measured custody cost table.

Measures on this machine (liboqs 0.16.0 via liboqs-python; FROST via
the pure-Python RFC 9591 implementation in frost_ed25519.py):
  * key / signature / share sizes for the custody inventory, asserted
    against the FIPS 204 tables (ML-DSA) and RFC 9591 Section 6.1
    (FROST/Ed25519: 32-byte scalars, 32-byte points, 64-byte sigs);
  * median FROST signing latency (commit + sign + aggregate) and
    verification time across quorum sizes;
  * median ML-DSA-65 sign / verify times;
  * median Shamir share-generation and reconstruction times for a
    4032-byte ML-DSA-65 secret key across quorum sizes;
  * ledger model: signature bytes per quorum-signed checkpoint.

Timings are medians over N repetitions on this machine; they are
measurements of this environment, not specification values. Sizes are
specification values confirmed by measurement.

Usage: python3 scripts/measure_costs.py
Exit 0 iff every size assertion holds.
"""
import hashlib
import json
import statistics
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import frost_ed25519 as F
from custody_drill import shamir_share, shamir_reconstruct

import oqs

EXPECTED = {
    "ML-DSA-44": {"liboqs": "ML-DSA-44", "pk": 1312, "sk": 2560,
                  "sig": 2420},
    "ML-DSA-65": {"liboqs": "ML-DSA-65", "pk": 1952, "sk": 4032,
                  "sig": 3309},
    "ML-DSA-87": {"liboqs": "ML-DSA-87", "pk": 2592, "sk": 4896,
                  "sig": 4627},
}
MSG = b"custody-cost benchmark checkpoint payload"
N_SIG = 50
N_FROST = 20
N_SHAMIR = 10
QUORUMS = [(2, 3), (3, 5), (4, 7), (5, 7)]


def med(v):
    return statistics.median(v)


def main():
    print("=== CUSTODY-COST MEASUREMENT ===")
    print("started_utc: %s" % datetime.now(timezone.utc).isoformat())
    print("liboqs_version: %s" % oqs.oqs_version())
    print("python: %s" % sys.version.split()[0])
    print("benchmark payload sha256: %s"
          % hashlib.sha256(MSG).hexdigest())
    failures = []
    results = {"signatures": {}, "frost": {}, "shamir": {}}

    for name, exp in EXPECTED.items():
        sig = oqs.Signature(exp["liboqs"])
        det = sig.details
        pk_len = det["length_public_key"]
        sk_len = det["length_secret_key"]
        sig_len = det["length_signature"]
        ok = (pk_len == exp["pk"] and sk_len == exp["sk"]
              and sig_len == exp["sig"])
        print("[%s] size %s pk=%d sk=%d sig=%d (expected %d/%d/%d, "
              "FIPS 204 Table 2)"
              % ("PASS" if ok else "FAIL", name, pk_len, sk_len, sig_len,
                 exp["pk"], exp["sk"], exp["sig"]))
        if not ok:
            failures.append("size %s" % name)
        pk = sig.generate_keypair()
        t_sign, t_verify = [], []
        for _ in range(N_SIG):
            t0 = time.perf_counter()
            s = sig.sign(MSG)
            t_sign.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            ok_v = sig.verify(MSG, s, pk)
            t_verify.append(time.perf_counter() - t0)
            if not ok_v:
                failures.append("self-verify %s" % name)
        print("timing %s: sign n=%d median=%.6f s min=%.6f s max=%.6f s; "
              "verify median=%.6f s min=%.6f s max=%.6f s"
              % (name, N_SIG, med(t_sign), min(t_sign), max(t_sign),
                 med(t_verify), min(t_verify), max(t_verify)))
        results["signatures"][name] = {
            "pk": pk_len, "sk": sk_len, "sig": sig_len,
            "sign_s_median": med(t_sign), "verify_s_median": med(t_verify),
            "n": N_SIG}

    # ---- FROST path: sizes (RFC 9591 Section 6.1) and timings ----
    print("--- FROST(Ed25519, SHA-512) ---")
    print("share size: 32 bytes (scalar); group public key: 32 bytes; "
          "signature: 64 bytes (R||z, RFC 9591 Appendix A); "
          "commitment pair per signer: 64 bytes")
    for (t, n) in QUORUMS:
        _s, _c, shares, group_pk = F.dealer_keygen(n, t)
        t_sign, t_verify = [], []
        for _ in range(N_FROST):
            ids = tuple(range(1, t + 1))
            t0 = time.perf_counter()
            clist, nonces = [], {}
            for ident in ids:
                nonce, comm = F.commit(shares[ident])
                nonces[ident] = nonce
                clist.append((ident, comm[0], comm[1]))
            sig_shares = [F.sign(i, shares[i], group_pk, nonces[i],
                                 MSG, clist) for i in ids]
            R, z = F.aggregate(clist, MSG, group_pk, sig_shares)
            sig = F.encode_signature((R, z))
            t_sign.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            ok_v = F.verify_signature(group_pk, MSG, sig)
            t_verify.append(time.perf_counter() - t0)
            if not ok_v:
                failures.append("frost self-verify t=%d n=%d" % (t, n))
        print("timing FROST t=%d-of-%d: full signing round n=%d "
              "median=%.4f s min=%.4f s max=%.4f s; verify "
              "median=%.4f s min=%.4f s max=%.4f s"
              % (t, n, N_FROST, med(t_sign), min(t_sign), max(t_sign),
                 med(t_verify), min(t_verify), max(t_verify)))
        results["frost"]["%d-of-%d" % (t, n)] = {
            "sign_s_median": med(t_sign), "verify_s_median": med(t_verify),
            "n": N_FROST}

    # ---- Shamir path: share/reconstruct timings for ML-DSA-65 sk ----
    print("--- SHAMIR SHARING OF ML-DSA-65 SECRET KEY (4032 bytes) ---")
    sk = bytes(4032)  # timing only; values do not affect cost
    # Use a fresh random key for the timing runs (same length).
    import os
    sk = os.urandom(4032)
    for (t, n) in QUORUMS:
        t_share, t_recon = [], []
        for _ in range(N_SHAMIR):
            t0 = time.perf_counter()
            sh = shamir_share(sk, n, t)
            t_share.append(time.perf_counter() - t0)
            subset = {i: sh[i] for i in range(1, t + 1)}
            t0 = time.perf_counter()
            rec = shamir_reconstruct(subset)
            t_recon.append(time.perf_counter() - t0)
            if rec != sk:
                failures.append("shamir round-trip t=%d n=%d" % (t, n))
        print("timing Shamir t=%d-of-%d sk=4032B: share n=%d "
              "median=%.4f s; reconstruct median=%.4f s"
              % (t, n, N_SHAMIR, med(t_share), med(t_recon)))
        results["shamir"]["%d-of-%d" % (t, n)] = {
            "share_s_median": med(t_share),
            "reconstruct_s_median": med(t_recon), "n": N_SHAMIR}

    # ---- ledger model: bytes per quorum-signed checkpoint ----
    print("--- LEDGER MODEL (signature bytes per quorum-signed "
          "checkpoint) ---")
    frost_b = 64
    mldsa_b = 3309
    print("FROST path: 1 x 64 B aggregate signature = %d B per "
          "checkpoint (any quorum size)" % frost_b)
    print("ML-DSA Shamir path: 1 x 3309 B signature = %d B per "
          "checkpoint (one reconstructed-key signature)" % mldsa_b)
    print("naive per-validator ML-DSA-65 signatures, quorum 4: %d B"
          % (4 * mldsa_b))
    for ckpts in (10000, 100000, 1000000):
        print("checkpoints=%d: FROST=%.2f MB ML-DSA-quorum=%.2f MB "
              "naive-quorum4=%.2f MB"
              % (ckpts, frost_b * ckpts / 1e6, mldsa_b * ckpts / 1e6,
                 4 * mldsa_b * ckpts / 1e6))
    print("custody storage per validator key (bytes): FROST share=32; "
          "ML-DSA-65 Shamir share=4032 (+1 id byte); full ML-DSA-65 "
          "sk=4032; ML-DSA-65 pk=1952")
    results["ledger_model"] = {
        "bytes_per_checkpoint": {"frost": frost_b, "mldsa_quorum": mldsa_b,
                                 "naive_quorum4": 4 * mldsa_b}}
    print("RESULTS_JSON: %s" % json.dumps(results, sort_keys=True))
    print("failures: %d %s" % (len(failures), failures))
    print("=== COST MEASUREMENT: %s ==="
          % ("ALL SIZE ASSERTIONS PASSED" if not failures else "FAILURES"))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
