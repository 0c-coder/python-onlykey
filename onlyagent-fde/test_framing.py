"""Transport tests for the OnlyKey I2C link: CRC agreement with the C firmware,
frame round-trips, and the single-use transit key properties.

Run: python3 onlyagent-fde/test_framing.py
"""
import os
import sys
import importlib.util

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    """Load a module directly (the package __init__ pulls in hid, not needed here)."""
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(_HERE, "..", "onlykey", name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


s = _load("i2csession")
crc16, Session, TransitError = s.crc16, s.Session, s.TransitError
derive_transit_key, FIXED_IV = s.derive_transit_key, s.FIXED_IV
SOF_CMD, SOF_RSP, SOF_RSP_ENC = s.SOF_CMD, s.SOF_RSP, s.SOF_RSP_ENC
REPORT_LEN, FRAME_LEN, ENC_FRAME_LEN = s.REPORT_LEN, s.FRAME_LEN, s.ENC_FRAME_LEN


def crc16_reference(data):
    """Independent re-implementation of the C okic2.cpp crc16()."""
    crc = 0xFFFF
    for b in data:
        crc ^= (b & 0xFF) << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def _seal(key, report):
    """Stand in for the firmware's encrypted response (okic2_queue_response)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    blob = AESGCM(key).encrypt(FIXED_IV, bytes(report), None)
    ct, tag = blob[:-16], blob[-16:]
    frame = bytearray([SOF_RSP_ENC, 1, REPORT_LEN]) + ct + tag
    c = crc16(frame)
    frame += bytes([(c >> 8) & 0xFF, c & 0xFF])
    return bytes(frame)


# ── CRC ────────────────────────────────────────────────────────────────────
def test_crc_known_vector():
    # CRC16-CCITT (init 0xFFFF) of "123456789" == 0x29B1 (standard vector).
    assert crc16(b"123456789") == 0x29B1, hex(crc16(b"123456789"))


def test_crc_matches_c_reference():
    for payload in (b"", b"\x00", bytes(range(64)), b"\xa5\x01\x40" + bytes(64)):
        assert crc16(payload) == crc16_reference(payload)


# ── framing ────────────────────────────────────────────────────────────────
def test_command_is_always_plaintext():
    """Commands carry only public KEM ciphertexts — never encrypted, even with
    a transit key armed."""
    sess = Session(transit_key=derive_transit_key(b"\x01" * 32))
    report = bytes([255, 255, 255, 255, 240] + list(range(59)))
    f = sess.build_command(7, report)
    assert len(f) == FRAME_LEN and f[0] == SOF_CMD and f[1] == 7
    assert bytes(f[3:67]) == report


def test_plaintext_response_roundtrip():
    sess = Session()
    report = bytes([1, 2, 3] + [0] * 61)
    rsp = bytearray([SOF_RSP, 7, REPORT_LEN]) + bytearray(report)
    c = crc16(rsp[:67])
    rsp += bytes([(c >> 8) & 0xFF, c & 0xFF])
    assert sess.parse_response(bytes(rsp)) == report


def test_bad_crc_rejected():
    sess = Session()
    rsp = bytearray([SOF_RSP, 1, REPORT_LEN]) + bytearray(REPORT_LEN) + b"\x00\x00"
    try:
        sess.parse_response(bytes(rsp))
    except TransitError:
        return
    raise AssertionError("bad CRC was accepted")


# ── single-use transit key ─────────────────────────────────────────────────
def test_encrypted_response_roundtrip():
    key = derive_transit_key(bytes(range(32)))
    sess = Session(transit_key=key)
    report = b"KEK" + bytes(REPORT_LEN - 3)
    frame = _seal(key, report)
    assert len(frame) == ENC_FRAME_LEN
    assert sess.parse_response(frame) == report


def test_payload_is_actually_encrypted():
    key = derive_transit_key(b"\x01" * 32)
    report = b"SECRETKEKBYTES" + bytes(REPORT_LEN - 14)
    frame = _seal(key, report)
    assert bytes(frame[3:67]) != report


def test_key_is_consumed_after_one_message():
    """The firmware zeroizes the transit key after one encrypted response;
    the host mirrors that. This is what makes the fixed IV safe."""
    key = derive_transit_key(b"\x02" * 32)
    sess = Session(transit_key=key)
    frame = _seal(key, b"A" * REPORT_LEN)
    assert sess.established
    sess.parse_response(frame)
    assert not sess.established, "transit key survived a message — reuse possible!"


def test_second_encrypted_response_rejected():
    """With the key consumed, a replayed/second encrypted frame cannot be read."""
    key = derive_transit_key(b"\x03" * 32)
    sess = Session(transit_key=key)
    frame = _seal(key, b"B" * REPORT_LEN)
    sess.parse_response(frame)
    try:
        sess.parse_response(frame)      # replay
    except TransitError:
        return
    raise AssertionError("replayed encrypted frame was accepted")


def test_tampered_ciphertext_rejected():
    key = derive_transit_key(b"\x04" * 32)
    sess = Session(transit_key=key)
    frame = bytearray(_seal(key, b"Z" * REPORT_LEN))
    frame[10] ^= 0x01                    # flip a bit in the ciphertext
    c = crc16(frame[:83])                # repair CRC so GCM is what rejects it
    frame[83], frame[84] = (c >> 8) & 0xFF, c & 0xFF
    try:
        sess.parse_response(bytes(frame))
    except TransitError:
        return
    raise AssertionError("tampered ciphertext was accepted — no integrity!")


def test_wrong_key_rejected():
    frame = _seal(derive_transit_key(b"\x05" * 32), b"Q" * REPORT_LEN)
    sess = Session(transit_key=derive_transit_key(b"\x06" * 32))
    try:
        sess.parse_response(frame)
    except TransitError:
        return
    raise AssertionError("frame decrypted under the wrong key")


def test_encrypted_response_without_key_rejected():
    sess = Session()
    frame = _seal(derive_transit_key(b"\x07" * 32), b"C" * REPORT_LEN)
    try:
        sess.parse_response(frame)
    except TransitError:
        return
    raise AssertionError("encrypted frame accepted with no transit key")


def test_distinct_secrets_give_distinct_keys():
    a = derive_transit_key(b"\x08" * 32)
    b = derive_transit_key(b"\x09" * 32)
    assert a != b


def test_transit_key_matches_firmware_derivation():
    """transit_key = SHA256(ss) — same as okic2_session_set()."""
    import hashlib
    ss = bytes(range(32))
    assert derive_transit_key(ss) == hashlib.sha256(ss).digest()


if __name__ == "__main__":
    passed = 0
    for name in sorted(list(globals())):
        fn = globals()[name]
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok:", name)
            passed += 1
    print("\n%d transport/transit tests passed." % passed)
