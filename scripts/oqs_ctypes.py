#!/usr/bin/env python3
"""Minimal ctypes binding to the liboqs C API (liboqs 0.16.0).

Needed because liboqs-python exposes no import_secret_key: signing
with a *reconstructed* secret key (the Shamir-custody path) requires
passing arbitrary secret-key bytes to OQS_SIG_sign. All sizes and
timings measured here are cross-checked against liboqs-python in
measure_costs.py.

If liboqs cannot be loaded, this module raises RuntimeError and the
drill exits 2 (UNAVAILABLE) instead of producing fake results.
"""
import ctypes
import ctypes.util
import os

_CANDIDATES = [
    os.environ.get("LIBOQS_PATH", ""),
    ctypes.util.find_library("oqs") or "",
    "liboqs.so",
]


def _load():
    last = None
    for path in _CANDIDATES:
        if not path:
            continue
        try:
            return ctypes.CDLL(path)
        except OSError as e:
            last = e
    raise RuntimeError("liboqs unavailable: %s" % last)


_LIB = _load()
_LIB.OQS_version.restype = ctypes.c_char_p
_LIB.OQS_SIG_new.argtypes = [ctypes.c_char_p]
_LIB.OQS_SIG_new.restype = ctypes.c_void_p
_LIB.OQS_SIG_free.argtypes = [ctypes.c_void_p]
_LIB.OQS_SIG_keypair.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                 ctypes.c_char_p]
_LIB.OQS_SIG_keypair.restype = ctypes.c_int
_LIB.OQS_SIG_sign.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                              ctypes.POINTER(ctypes.c_size_t),
                              ctypes.c_char_p, ctypes.c_size_t,
                              ctypes.c_char_p]
_LIB.OQS_SIG_sign.restype = ctypes.c_int
_LIB.OQS_SIG_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                ctypes.c_size_t, ctypes.c_char_p,
                                ctypes.c_size_t, ctypes.c_char_p]
_LIB.OQS_SIG_verify.restype = ctypes.c_int


def version():
    return _LIB.OQS_version().decode()


class Sig:
    """One liboqs signature algorithm instance (ML-DSA-65 here)."""

    def __init__(self, name, pk_len, sk_len, sig_len):
        self.name = name
        self.pk_len, self.sk_len, self.sig_len = pk_len, sk_len, sig_len
        self._sig = _LIB.OQS_SIG_new(name.encode())
        if not self._sig:
            raise RuntimeError("OQS_SIG_new failed for %s" % name)

    def keypair(self):
        pk = ctypes.create_string_buffer(self.pk_len)
        sk = ctypes.create_string_buffer(self.sk_len)
        if _LIB.OQS_SIG_keypair(self._sig, pk, sk) != 0:
            raise RuntimeError("OQS_SIG_keypair failed")
        return pk.raw, sk.raw

    def sign(self, msg, sk):
        if len(sk) != self.sk_len:
            raise ValueError("secret key length %d != %d"
                             % (len(sk), self.sk_len))
        out = ctypes.create_string_buffer(self.sig_len)
        out_len = ctypes.c_size_t(self.sig_len)
        rc = _LIB.OQS_SIG_sign(self._sig, out, ctypes.byref(out_len),
                               msg, len(msg), sk)
        if rc != 0:
            raise RuntimeError("OQS_SIG_sign failed")
        return out.raw[:out_len.value]

    def verify(self, msg, sig, pk):
        if len(pk) != self.pk_len or len(sig) != self.sig_len:
            return False
        return _LIB.OQS_SIG_verify(self._sig, msg, len(msg), sig,
                                   len(sig), pk) == 0

    def free(self):
        if self._sig:
            _LIB.OQS_SIG_free(self._sig)
            self._sig = None
