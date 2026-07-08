"""
onlykey/pqc.py — composite post-quantum PGP keys over the USB-HID transport.

Matches the firmware in trustcrypto/libraries PR #31 (KEYTYPE_PQC_PGP = 7):
one RSA slot (1-4) holds one composite key as a 160-byte seed blob, and the
device does ML-KEM-768 decapsulation + ML-DSA-65 signing on-device.

This is the CLI/agent path (loaded keys, HID transport). It is NOT the
age/X-Wing *derive* path (that is firmware + web app over FIDO2).

Wire protocol (as implemented by okpqc.cpp):
  * Load  : OKSETPRIV, slot, key_type = 0x67 (KEYTYPE_PQC_PGP | decrypt bit5 | sign bit6),
            payload = 160-byte blob.
  * Decrypt (OKDECRYPT, slot): the device picks the half by INPUT SIZE:
            32-byte X25519 ephemeral point -> X25519 shared secret (32 B)
            1088-byte ML-KEM ciphertext    -> ML-KEM shared secret (32 B)
  * Sign  (OKSIGN, slot): payload = [selector_byte] + digest, selector:
            0 = Ed25519 (-> 64-byte sig),  1 = ML-DSA-65 (-> 3309-byte sig)

Composite blob layout (160 bytes):
  [0:32]  Ed25519 secret       (sign, ecc half)
  [32:64] ML-DSA-65 seed       (sign, pqc half)     FIPS 204 32-byte seed
  [64:96] X25519 secret        (decrypt, ecc half)
  [96:160] ML-KEM-768 seed     (decrypt, pqc half)  FIPS 203 64-byte seed (d||z)

UNTESTED against hardware — by inspection. Validate the framing on a device.
"""
from .client import Message

# --- key type + layout (mirror okpqc.h) ---------------------------------------
KEYTYPE_PQC_PGP   = 7
FEATURE_DECRYPT   = 0x20   # bit 5
FEATURE_SIGN      = 0x40   # bit 6
PQC_KEY_TYPE_BYTE = KEYTYPE_PQC_PGP | FEATURE_DECRYPT | FEATURE_SIGN   # 0x67

PQC_PGP_BLOB_LEN  = 160
OFF_ED25519       = 0
OFF_MLDSA_SEED    = 32
OFF_X25519        = 64
OFF_MLKEM_SEED    = 96

ED25519_SK_LEN    = 32
MLDSA_SEED_LEN    = 32
X25519_SK_LEN     = 32
MLKEM_SEED_LEN    = 64

# component selector (sign only; decrypt infers from size)
HALF_ECC = 0
HALF_PQC = 1

# transport sizes
MLKEM_CT_LEN  = 1088
X25519_PT_LEN = 32
SS_LEN        = 32
ED25519_SIG_LEN = 64
MLDSA_SIG_LEN   = 3309


def build_composite_blob(ed25519_sk, mldsa_seed, x25519_sk, mlkem_seed):
    """Pack the four private seeds into the 160-byte composite blob."""
    for name, val, ln in (
        ("ed25519_sk", ed25519_sk, ED25519_SK_LEN),
        ("mldsa_seed", mldsa_seed, MLDSA_SEED_LEN),
        ("x25519_sk",  x25519_sk,  X25519_SK_LEN),
        ("mlkem_seed", mlkem_seed, MLKEM_SEED_LEN),
    ):
        if len(val) != ln:
            raise ValueError("%s must be %d bytes, got %d" % (name, ln, len(val)))
    blob = bytes(ed25519_sk) + bytes(mldsa_seed) + bytes(x25519_sk) + bytes(mlkem_seed)
    assert len(blob) == PQC_PGP_BLOB_LEN
    return blob


def load_composite_key(ok, slot, blob):
    """Load a composite PQC PGP key (160-byte seed blob) into RSA slot 1-4.

    Uses OKSETPRIV with key_type = 0x67 (PQC composite; decrypt+sign capable),
    the same op RSA keys use. Only allowed in config mode / first use.
    """
    if not 1 <= slot <= 4:
        raise ValueError("PQC composite keys use RSA slots 1-4")
    if len(blob) != PQC_PGP_BLOB_LEN:
        raise ValueError("blob must be %d bytes" % PQC_PGP_BLOB_LEN)
    # The firmware OKSETPRIV reads buffer[5]=slot, buffer[6]=key_type, buffer[7:]=57-byte chunk,
    # accumulating across messages. send_message frames [hdr][msg][slot_id][payload], so each
    # payload = [key_type] + 57-byte chunk puts key_type at buffer[6] and data at buffer[7:].
    blob = bytes(blob)
    for i in range(0, PQC_PGP_BLOB_LEN, 57):
        chunk = blob[i:i + 57]
        # send_message accepts str(hex)/list/bytearray/int — NOT bytes — so frame
        # the payload as a bytearray: [key_type] + 57-byte chunk (key_type -> buffer[6]).
        ok.send_message(msg=Message.OKSETPRIV, slot_id=slot,
                        payload=bytearray([PQC_KEY_TYPE_BYTE]) + bytearray(chunk))


def decrypt(ok, slot, data):
    """Composite decrypt. Send either the 32-byte X25519 ephemeral point (ECC half)
    or the 1088-byte ML-KEM ciphertext (PQC half); the device picks by size and
    returns the 32-byte shared secret. openpgp.js does the KMAC combine + unwrap."""
    if len(data) not in (X25519_PT_LEN, MLKEM_CT_LEN):
        raise ValueError("decrypt input must be %d (X25519 point) or %d (ML-KEM ct) bytes"
                         % (X25519_PT_LEN, MLKEM_CT_LEN))
    ok.send_large_message2(msg=Message.OKDECRYPT, slot_id=slot, payload=data)
    return ok.read_string(timeout_ms=_op_timeout(len(data)))[:SS_LEN]


def sign(ok, slot, component, digest):
    """Composite sign. component = HALF_ECC (Ed25519) or HALF_PQC (ML-DSA-65).
    Payload is [selector] + digest; returns the 64-byte or 3309-byte signature."""
    if component not in (HALF_ECC, HALF_PQC):
        raise ValueError("component must be HALF_ECC(0) or HALF_PQC(1)")
    payload = bytes([component]) + bytes(digest)
    ok.send_large_message2(msg=Message.OKSIGN, slot_id=slot, payload=payload)
    want = ED25519_SIG_LEN if component == HALF_ECC else MLDSA_SIG_LEN
    return ok.read_string(timeout_ms=_op_timeout(want))[:want]


def _op_timeout(nbytes):
    # ML-DSA keygen-from-seed + sign, or ML-KEM keygen + decaps, take a few 100 ms on the M4.
    return 8000 if nbytes >= MLKEM_CT_LEN or nbytes >= MLDSA_SIG_LEN else 4000
