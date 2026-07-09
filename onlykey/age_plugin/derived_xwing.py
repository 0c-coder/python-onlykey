"""Derived (label-based) X-Wing split-custody crypto for age-plugin-onlykey.

The OnlyKey derives sk_X (X25519) and a 32-byte ML-KEM seed from
(web-derivation key, label, RPID="onlyagent.app") and keeps sk_X. The host does
the ML-KEM half locally: expand the seed, decapsulate ct_M, and run the X-Wing
combiner. Same derivation + same seed => the SAME X-Wing key on the CLI and the
web app, so a file encrypted in one decrypts in the other on the same OnlyKey.

kyber-py's ML-KEM-768 is byte-compatible with the web app's @noble/post-quantum
(verified: same pk from same seed, cross-decapsulation matches).

Wire contract with the firmware HID derive branch (RESERVED_KEY_WEB_DERIVATION,
keytype X-Wing), matching the FIDO2 branch:
  DERIVE_PUBLIC_KEY -> [ pk_X(32) | mlkem_seed(32) ]
  DERIVE_SHAREDSEC  -> [ ss_X(32) | mlkem_seed(32) ]
"""

import base64
import hashlib

from kyber_py.ml_kem import ML_KEM_768

# draft-connolly-cfrg-xwing-kem-09 combiner label "\.//^\"
XWING_LABEL = bytes([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c])

MLKEM_PK = 1184
MLKEM_CT = 1088
XWING_PK = 1216
XWING_CT = 1120
SEED = 32
RPID = "onlyagent.app"   # fixed derivation origin shared with the web app


def mlkem_keypair_from_seed(mlkem_seed):
    """Expand the 32-byte seed (SHAKE256 -> 64-byte d||z) into an ML-KEM keypair.

    Matches the firmware (xwing_shake256/keypair_derand) and the web app
    (shake256 -> noble keygen). Returns (pk_M 1184, sk_M 2400).
    """
    if len(mlkem_seed) != SEED:
        raise ValueError("mlkem_seed must be 32 bytes, got %d" % len(mlkem_seed))
    seed64 = hashlib.shake_256(bytes(mlkem_seed)).digest(64)
    ek, dk = ML_KEM_768._keygen_internal(seed64[:32], seed64[32:])
    return ek, dk


def build_recipient(pk_x, mlkem_seed):
    """Build the 1216-byte X-Wing recipient public key (pk_M || pk_X)."""
    if len(pk_x) != 32:
        raise ValueError("pk_X must be 32 bytes, got %d" % len(pk_x))
    pk_m, _ = mlkem_keypair_from_seed(mlkem_seed)
    return bytes(pk_m) + bytes(pk_x)


def split_decapsulate(ss_x, ciphertext, pk_x, mlkem_seed):
    """Finish X-Wing decapsulation given the device's ss_X and the seed.

    ss_x        : 32-byte X25519 shared secret from the device (sk_X stays there)
    ciphertext  : 1120-byte X-Wing ct (ct_M || ct_X) from the age stanza
    pk_x        : recipient X25519 public
    mlkem_seed  : 32-byte ML-KEM seed from the device
    Returns the 32-byte X-Wing shared secret. ct_M never leaves the host.
    """
    if len(ss_x) != 32:
        raise ValueError("ss_X must be 32 bytes")
    if len(ciphertext) != XWING_CT:
        raise ValueError("X-Wing ct must be 1120 bytes, got %d" % len(ciphertext))
    ct_m = bytes(ciphertext[:MLKEM_CT])
    ct_x = bytes(ciphertext[MLKEM_CT:XWING_CT])
    _, sk_m = mlkem_keypair_from_seed(mlkem_seed)
    ss_m = ML_KEM_768.decaps(sk_m, ct_m)
    return hashlib.sha3_256(bytes(ss_m) + bytes(ss_x) + ct_x + bytes(pk_x) + XWING_LABEL).digest()


def ct_x_of(ciphertext):
    """Return ct_X (the 32 bytes the device needs) from a stanza ciphertext."""
    return bytes(ciphertext[MLKEM_CT:XWING_CT])


# ---- derived age identity encoding (label-based, no slot) ----------------
# Distinguishes a derived identity from a slot identity so age-plugin-onlykey
# can support BOTH models (like SSH/GPG). A derived identity carries the label;
# the key is reproduced on demand from (OnlyKey web-derivation key, label, RPID).
_DERIVED_PREFIX = "AGE-PLUGIN-ONLYKEY-DERIVED-"


def encode_identity(label):
    """Encode a derived identity string for a label (used with `age -i`)."""
    if not isinstance(label, str) or not label:
        raise ValueError("derived identity needs a non-empty label")
    b32 = base64.b32encode(label.encode("utf-8")).decode("ascii").rstrip("=")
    return _DERIVED_PREFIX + b32.upper()


def decode_identity(s):
    """Decode a derived identity string -> {'derived': True, 'label': str},
    or None if `s` is not a derived identity (caller falls back to slot decode)."""
    s = str(s).strip().upper()
    if not s.startswith(_DERIVED_PREFIX):
        return None
    b32 = s[len(_DERIVED_PREFIX):]
    b32 += "=" * (-len(b32) % 8)
    label = base64.b32decode(b32).decode("utf-8")
    return {"derived": True, "label": label}
