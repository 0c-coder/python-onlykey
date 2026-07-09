"""Hardware-free proof of the derived (label-based) X-Wing split custody path.

A standard X-Wing sender encapsulates to the recipient; decapsulation is split
between the "device" (X25519 half; sk_X never leaves) and the host (ML-KEM half,
kyber-py) and must reproduce the same shared secret. Interoperable with the web
app (@noble) — verified separately that the two ML-KEM impls agree byte-for-byte.
"""
import os
import sys
import types

import pytest

pytest.importorskip("kyber_py")
pytest.importorskip("cryptography")

# Stub hid so importing the onlykey package doesn't need USB libs.
for _n in ("hid", "hidraw"):
    if _n not in sys.modules:
        try:
            __import__(_n)
        except ImportError:
            _m = types.ModuleType(_n)
            _m.device = object
            sys.modules[_n] = _m

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from onlykey.age_plugin import derived_xwing as dx
from onlykey.age_plugin import xwing  # existing: xwing_encaps_host, x25519 helpers


def _device_derive():
    """Stand-in for the OnlyKey web-derivation: returns sk_X, pk_X, mlkem_seed."""
    sk = X25519PrivateKey.generate()
    return sk.private_bytes_raw(), sk.public_key().public_bytes_raw(), os.urandom(32)


def test_recipient_is_1216_bytes():
    _, pk_x, seed = _device_derive()
    assert len(dx.build_recipient(pk_x, seed)) == 1216


def test_split_decaps_matches_standard_encaps():
    sk_x, pk_x, seed = _device_derive()
    recipient = dx.build_recipient(pk_x, seed)

    ss_enc, ct = xwing.xwing_encaps_host(recipient)   # standard X-Wing sender
    assert len(ct) == 1120

    ss_x = xwing.x25519_scalarmult(sk_x, dx.ct_x_of(ct))   # device: X25519(sk_X, ct_X)
    ss_dec = dx.split_decapsulate(ss_x, ct, pk_x, seed)    # host: ML-KEM half + combiner
    assert ss_dec == ss_enc


def test_wrong_device_share_fails():
    sk_x, pk_x, seed = _device_derive()
    recipient = dx.build_recipient(pk_x, seed)
    ss_enc, ct = xwing.xwing_encaps_host(recipient)
    bad = dx.split_decapsulate(bytes(32), ct, pk_x, seed)   # no device ss_X
    assert bad != ss_enc


def test_deterministic_recipient_per_seed():
    _, pk_x, seed = _device_derive()
    assert dx.build_recipient(pk_x, seed) == dx.build_recipient(pk_x, seed)


def test_derived_identity_roundtrip():
    for label in ("age:personal", "alice@example.com", "work"):
        ident = dx.encode_identity(label)
        assert ident.startswith("AGE-PLUGIN-ONLYKEY-DERIVED-")
        assert dx.decode_identity(ident) == {"derived": True, "label": label}
    # a slot-style identity is not a derived identity
    assert dx.decode_identity("AGE-PLUGIN-ONLYKEY-1QQQ") is None
