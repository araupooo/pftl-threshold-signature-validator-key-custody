#!/usr/bin/env python3
"""Validate frost_ed25519.py against RFC 9591 Appendix E.1 test vectors.
Exit 0 iff every published intermediate value is reproduced exactly.
Run: python3 scripts/check_frost_vectors.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import frost_ed25519 as F

# RFC 9591 Appendix E.1, FROST(Ed25519, SHA-512). All values below are
# PUBLISHED test data from the RFC (not secrets).
V = {
    "group_secret_key": "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304",
    "group_public_key": "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673",
    "message": "74657374",
    "coeff1": "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204",
    "p1_share": "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509",
    "p3_share": "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02",
    "p1_hiding_rand": "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec",
    "p1_binding_rand": "69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501",
    "p1_hiding_nonce": "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407",
    "p1_binding_nonce": "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301",
    "p1_hiding_comm": "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3",
    "p1_binding_comm": "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932",
    "p1_binding_factor": "f2cb9d7dd9beff688da6fcc83fa89046b3479417f47f55600b106760eb3b5603",
    "p3_hiding_rand": "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f",
    "p3_binding_rand": "13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775",
    "p3_hiding_nonce": "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e",
    "p3_binding_nonce": "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d",
    "p3_hiding_comm": "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91",
    "p3_binding_comm": "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552",
    "p3_binding_factor": "b087686bf35a13f3dc78e780a34b0fe8a77fef1b9938c563f5573d71d8d7890f",
    "p1_sig_share": "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603",
    "p3_sig_share": "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007",
    "sig": "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe"
           "bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b",
}


def hx(s):
    return bytes.fromhex(s)


def main():
    fails = []

    def check(name, got, want_hex):
        ok = got == bytes.fromhex(want_hex)
        print("[%s] %s" % ("PASS" if ok else "FAIL", name))
        if not ok:
            print("  got : %s" % got.hex())
            print("  want: %s" % want_hex)
            fails.append(name)
        return ok

    s = F.deserialize_scalar(hx(V["group_secret_key"]))
    a1 = F.deserialize_scalar(hx(V["coeff1"]))
    pk = F.scalarmult_base(s)
    check("group_public_key = s*B", F.encode_point(pk), V["group_public_key"])

    p1 = F.deserialize_scalar(hx(V["p1_share"]))
    p3 = F.deserialize_scalar(hx(V["p3_share"]))
    check("share P1 = s + a1*1", F.serialize_scalar((s + a1) % F.L), V["p1_share"])
    check("share P3 = s + a1*3", F.serialize_scalar((s + 3 * a1) % F.L), V["p3_share"])

    msg = hx(V["message"])
    # Nonces from the published randomness inputs.
    n1h = F.nonce_generate(p1, hx(V["p1_hiding_rand"]))
    n1b = F.nonce_generate(p1, hx(V["p1_binding_rand"]))
    n3h = F.nonce_generate(p3, hx(V["p3_hiding_rand"]))
    n3b = F.nonce_generate(p3, hx(V["p3_binding_rand"]))
    check("P1 hiding_nonce", F.serialize_scalar(n1h), V["p1_hiding_nonce"])
    check("P1 binding_nonce", F.serialize_scalar(n1b), V["p1_binding_nonce"])
    check("P3 hiding_nonce", F.serialize_scalar(n3h), V["p3_hiding_nonce"])
    check("P3 binding_nonce", F.serialize_scalar(n3b), V["p3_binding_nonce"])

    c1h = F.scalarmult_base(n1h)
    c1b = F.scalarmult_base(n1b)
    c3h = F.scalarmult_base(n3h)
    c3b = F.scalarmult_base(n3b)
    check("P1 hiding_nonce_commitment", F.encode_point(c1h), V["p1_hiding_comm"])
    check("P1 binding_nonce_commitment", F.encode_point(c1b), V["p1_binding_comm"])
    check("P3 hiding_nonce_commitment", F.encode_point(c3h), V["p3_hiding_comm"])
    check("P3 binding_nonce_commitment", F.encode_point(c3b), V["p3_binding_comm"])

    clist = [(1, c1h, c1b), (3, c3h, c3b)]
    bfs = F.compute_binding_factors(pk, clist, msg)
    check("P1 binding_factor", F.serialize_scalar(dict(bfs)[1]), V["p1_binding_factor"])
    check("P3 binding_factor", F.serialize_scalar(dict(bfs)[3]), V["p3_binding_factor"])

    z1 = F.sign(1, p1, pk, (n1h, n1b), msg, clist)
    z3 = F.sign(3, p3, pk, (n3h, n3b), msg, clist)
    check("P1 sig_share", F.serialize_scalar(z1), V["p1_sig_share"])
    check("P3 sig_share", F.serialize_scalar(z3), V["p3_sig_share"])

    sig = F.aggregate(clist, msg, pk, [z1, z3])
    check("aggregate signature R||z", F.encode_signature(sig), V["sig"])
    ok = F.verify_signature(pk, msg, F.encode_signature(sig))
    print("[%s] aggregate signature verifies under group public key" % ("PASS" if ok else "FAIL"))
    if not ok:
        fails.append("verify")

    # Share verification (RFC 9591 Section 5.3).
    pk1 = F.scalarmult_base(p1)
    pk3 = F.scalarmult_base(p3)
    ok1 = F.verify_signature_share(1, pk1, (c1h, c1b), z1, pk, clist, msg)
    ok3 = F.verify_signature_share(3, pk3, (c3h, c3b), z3, pk, clist, msg)
    print("[%s] P1 signature share verifies" % ("PASS" if ok1 else "FAIL"))
    print("[%s] P3 signature share verifies" % ("PASS" if ok3 else "FAIL"))
    if not ok1:
        fails.append("share-verify-1")
    if not ok3:
        fails.append("share-verify-3")

    print("failures: %d %s" % (len(fails), fails))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
