#!/usr/bin/env python3
"""FROST(Ed25519, SHA-512) -- RFC 9591, Sections 4-6.1, Appendix C/E.1.

Pure-Python implementation (standard library only) of the two-round
FROST threshold Schnorr signing protocol for the Ed25519 ciphersuite,
plus the Appendix C trusted-dealer key generation (Shamir sharing of
the group secret over the scalar field).

Ed25519 arithmetic uses extended twisted-Edwards coordinates; the
implementation is validated against the RFC 9591 Appendix E.1 test
vectors in custody_drill.py (every intermediate value is recomputed
and compared to the published vector).

Context string: "FROST-ED25519-SHA512-v1" (RFC 9591 Section 6.1).
  H1(m) = SHA-512(ctx || "rho"   || m), LE integer mod L
  H2(m) = SHA-512(m),                   LE integer mod L (no domain
          separator, for RFC 8032 compatibility)
  H3(m) = SHA-512(ctx || "nonce" || m), LE integer mod L
  H4(m) = SHA-512(ctx || "msg"   || m)
  H5(m) = SHA-512(ctx || "com"   || m)

SerializeScalar: 32-byte little-endian. SerializeElement: RFC 8032
compressed Edwards encoding. Signature encoding (Appendix A): R || z.
Verification: RFC 8032 Section 5.1.7 with the cofactor equation
[8]z*B = [8]R + [8]c*PK (RFC 9591 Section 6.1).

This module is NOT a production implementation: it has no
constant-time guarantees and no side-channel mitigations (see RFC 9591
Section 7.1). It exists to produce verifiable evidence about the
protocol's properties (quorum signing, below-quorum rejection,
group-key verification, share rotation) against the published test
vectors.
"""
import hashlib
import secrets

# ---------------------------------------------------------------- ed25519
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)  # sqrt(-1) mod p
# Base point, compressed form from RFC 8032.
_B_Y = (4 * pow(5, P - 2, P)) % P


def _xrecover(y):
    """Recover x from y on edwards25519 (RFC 8032 Section 5.1.3)."""
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if (x * x - xx) % P != 0:
        raise ValueError("not on curve")
    if x & 1:
        x = P - x
    return x


def decode_point(s):
    """RFC 8032 Section 5.1.3 compressed-point decoding -> (x, y)."""
    if len(s) != 32:
        raise ValueError("bad point length")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = (s[31] >> 7) & 1
    if y >= P:
        raise ValueError("y out of range")
    x = _xrecover(y)
    if (x & 1) != sign:
        x = P - x
    if (y * y - x * x - 1 - D * x * x * y * y) % P != 0:
        raise ValueError("not on curve")
    return (x, y)


def encode_point(pt):
    """RFC 8032 Section 5.1.2 compressed-point encoding."""
    x, y = pt
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _to_ext(pt):
    x, y = pt
    return (x, y, 1, (x * y) % P)


def _from_ext(e):
    X, Y, Z, _T = e
    zi = pow(Z, P - 2, P)
    return ((X * zi) % P, (Y * zi) % P)


def _edwards_add(e1, e2):
    X1, Y1, Z1, T1 = e1
    X2, Y2, Z2, T2 = e2
    A = (X1 * X2) % P
    B = (Y1 * Y2) % P
    C = (T1 * D % P * T2) % P
    Dd = (Z1 * Z2) % P
    E = ((X1 + Y1) * (X2 + Y2) - A - B) % P
    F = (Dd - C) % P
    G = (Dd + C) % P
    H = (B + A) % P  # a = -1, so H = B - a*A = B + A
    return ((E * F) % P, (G * H) % P, (F * G) % P, (E * H) % P)


_IDENTITY_EXT = (0, 1, 1, 0)


def _scalarmult(pt, e):
    """Scalar multiplication by double-and-add (e mod L)."""
    e %= L
    q = _IDENTITY_EXT
    p_ext = _to_ext(pt)
    # Double-and-add over the bits, most significant first.
    bits = bin(e)[2:]
    for bit in bits:
        q = _edwards_add(q, q)
        if bit == "1":
            q = _edwards_add(q, p_ext)
    return _from_ext(q)


_BASE = None


def base_point():
    global _BASE
    if _BASE is None:
        x = _xrecover(_B_Y)
        _BASE = (x, _B_Y)
    return _BASE


def scalarmult_base(e):
    return _scalarmult(base_point(), e)


def point_add(a, b):
    return _from_ext(_edwards_add(_to_ext(a), _to_ext(b)))


def scalarmult(pt, e):
    return _scalarmult(pt, e)


def point_mul_small(pt, n):
    """Multiply a point by a small integer (for cofactor checks)."""
    return _scalarmult(pt, n)


# ---------------------------------------------------------------- scalars
def serialize_scalar(s):
    return (s % L).to_bytes(32, "little")


def deserialize_scalar(buf):
    if len(buf) != 32:
        raise ValueError("bad scalar length")
    v = int.from_bytes(buf, "little")
    if v >= L:
        raise ValueError("scalar out of range")
    return v


# ---------------------------------------------------------------- hashes
CTX = b"FROST-ED25519-SHA512-v1"


def _h1(m):
    return int.from_bytes(
        hashlib.sha512(CTX + b"rho" + m).digest(), "little") % L


def _h2(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little") % L


def _h3(m):
    return int.from_bytes(
        hashlib.sha512(CTX + b"nonce" + m).digest(), "little") % L


def _h4(m):
    return hashlib.sha512(CTX + b"msg" + m).digest()


def _h5(m):
    return hashlib.sha512(CTX + b"com" + m).digest()


# ---------------------------------------------------------------- FROST
def nonce_generate(secret, randomness=None):
    """RFC 9591 Section 4.1. `randomness` is 32 fresh bytes; when given
    (test-vector replay) it is used verbatim instead of sampled."""
    if randomness is None:
        randomness = secrets.token_bytes(32)
    return _h3(randomness + serialize_scalar(secret))


def derive_interpolating_value(participant_ids, identifier):
    """RFC 9591 Section 4.2: Lagrange coefficient lambda_i at x=0."""
    if identifier not in participant_ids:
        raise ValueError("invalid parameters: identifier not in list")
    if len(set(participant_ids)) != len(participant_ids):
        raise ValueError("invalid parameters: duplicate identifier")
    num = 1
    den = 1
    for xj in participant_ids:
        if xj == identifier:
            continue
        num = num * xj % L
        den = den * (xj - identifier) % L
    return num * pow(den, L - 2, L) % L


def encode_group_commitment_list(commitment_list):
    """RFC 9591 Section 4.3. commitment_list sorted by identifier:
    [(id, hiding_comm, binding_comm), ...] with points as (x, y)."""
    out = b""
    for (ident, hiding, binding) in commitment_list:
        out += (serialize_scalar(ident) + encode_point(hiding)
                + encode_point(binding))
    return out


def compute_binding_factors(group_public_key, commitment_list, msg):
    """RFC 9591 Section 4.4 -> [(identifier, binding_factor), ...]."""
    pk_enc = encode_point(group_public_key)
    msg_hash = _h4(msg)
    comm_hash = _h5(encode_group_commitment_list(commitment_list))
    prefix = pk_enc + msg_hash + comm_hash
    out = []
    for (ident, _h, _b) in commitment_list:
        rho = prefix + serialize_scalar(ident)
        out.append((ident, _h1(rho)))
    return out


def binding_factor_for(bf_list, identifier):
    for (i, bf) in bf_list:
        if i == identifier:
            return bf
    raise ValueError("invalid participant")


def compute_group_commitment(commitment_list, bf_list):
    """RFC 9591 Section 4.5 -> group commitment point (x, y)."""
    acc = None  # identity
    for (ident, hiding, binding) in commitment_list:
        bf = binding_factor_for(bf_list, ident)
        term = point_add(hiding, scalarmult(binding, bf))
        acc = term if acc is None else point_add(acc, term)
    if acc is None:
        raise ValueError("empty commitment list")
    return acc


def compute_challenge(group_commitment, group_public_key, msg):
    """RFC 9591 Section 4.6."""
    return _h2(encode_point(group_commitment)
               + encode_point(group_public_key) + msg)


def commit(sk_i, randomness_pair=None):
    """RFC 9591 Section 5.1. Returns ((hiding, binding) nonces,
    (hiding_comm, binding_comm) points). `randomness_pair` optionally
    supplies the two 32-byte randomness inputs (test-vector replay)."""
    if randomness_pair is None:
        hiding = nonce_generate(sk_i)
        binding = nonce_generate(sk_i)
    else:
        hiding = nonce_generate(sk_i, randomness_pair[0])
        binding = nonce_generate(sk_i, randomness_pair[1])
    return ((hiding, binding),
            (scalarmult_base(hiding), scalarmult_base(binding)))


def sign(identifier, sk_i, group_public_key, nonce_i, msg,
         commitment_list):
    """RFC 9591 Section 5.2 -> signature share (Scalar)."""
    bf_list = compute_binding_factors(group_public_key, commitment_list,
                                      msg)
    bf = binding_factor_for(bf_list, identifier)
    group_commitment = compute_group_commitment(commitment_list, bf_list)
    ids = [i for (i, _h, _b) in commitment_list]
    lam = derive_interpolating_value(ids, identifier)
    challenge = compute_challenge(group_commitment, group_public_key, msg)
    hiding, binding = nonce_i
    return (hiding + binding * bf + lam * sk_i * challenge) % L


def aggregate(commitment_list, msg, group_public_key, sig_shares):
    """RFC 9591 Section 5.3 -> (R, z); encoded as R || z (Appendix A)."""
    bf_list = compute_binding_factors(group_public_key, commitment_list,
                                      msg)
    group_commitment = compute_group_commitment(commitment_list, bf_list)
    z = sum(sig_shares) % L
    return (group_commitment, z)


def encode_signature(sig):
    R, z = sig
    return encode_point(R) + serialize_scalar(z)


def verify_signature(group_public_key, msg, sig_bytes):
    """RFC 8032 Section 5.1.7 with the RFC 9591 Section 6.1 cofactor
    equation [8]z*B = [8]R + [8]c*PK. Returns True/False."""
    if len(sig_bytes) != 64:
        return False
    R_enc, z_enc = sig_bytes[:32], sig_bytes[32:]
    try:
        z = deserialize_scalar(z_enc)
        R = decode_point(R_enc)
    except ValueError:
        return False
    c = _h2(R_enc + encode_point(group_public_key) + msg)
    # [8]z*B == [8]R + [8]c*PK
    lhs = scalarmult(base_point(), (8 * z) % L)
    rhs = point_add(scalarmult(R, 8), scalarmult(group_public_key,
                                                 (8 * c) % L))
    return lhs == rhs


def verify_signature_share(identifier, pk_i, comm_i, sig_share,
                           group_public_key, commitment_list, msg):
    """RFC 9591 Section 5.3 share verification: [z_i]B =
    [lambda_i]PK_i * challenge ... precisely: z_i*B =
    R_i + lambda_i * c * PK_i where R_i = hiding_i + rho_i*binding_i."""
    bf_list = compute_binding_factors(group_public_key, commitment_list,
                                      msg)
    bf = binding_factor_for(bf_list, identifier)
    group_commitment = compute_group_commitment(commitment_list, bf_list)
    ids = [i for (i, _h, _b) in commitment_list]
    lam = derive_interpolating_value(ids, identifier)
    challenge = compute_challenge(group_commitment, group_public_key, msg)
    hiding_comm, binding_comm = comm_i
    r_i = point_add(hiding_comm, scalarmult(binding_comm, bf))
    lhs = scalarmult_base(sig_share)
    rhs = point_add(r_i, scalarmult(pk_i, (lam * challenge) % L))
    return lhs == rhs


# ------------------------------------------------- dealer key generation
def dealer_keygen(max_participants, min_participants, secret=None):
    """RFC 9591 Appendix C trusted-dealer key generation: a random group
    secret s and a degree-(min-1) polynomial f with f(0) = s; share for
    participant i is f(i); group public key is s*B. Returns
    (secret, coefficients, {id: share}, group_public_key)."""
    if secret is None:
        secret = secrets.randbelow(L - 1) + 1
    coeffs = [secret] + [secrets.randbelow(L) for _ in range(min_participants - 1)]
    shares = {}
    for i in range(1, max_participants + 1):
        v = 0
        for c in reversed(coeffs):
            v = (v * i + c) % L
        shares[i] = v
    return secret, coeffs, shares, scalarmult_base(secret)


def reconstruct_secret(shares):
    """Lagrange interpolation at x=0 from {id: share} (Shamir, RFC 9591
    Appendix C.1). Returns the reconstructed scalar."""
    ids = sorted(shares)
    total = 0
    for i in ids:
        lam = derive_interpolating_value(ids, i)
        total = (total + lam * shares[i]) % L
    return total
