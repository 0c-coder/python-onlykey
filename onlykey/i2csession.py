"""
onlykey/i2csession.py — framing + single-use transit encryption for the I2C link.

Mirrors okic2.cpp. The on-board I2C bus is probeable, so responses carrying
secrets are encrypted — but with a key that is used for exactly ONE message.

Why no counters: GCM only requires that (key, nonce) never repeat. A fresh key
per message makes that true regardless of the nonce, so a fixed IV is safe and
no message counter is needed. This is the same property that makes the web app's
zero IV safe over WebAuthn (every operation there sends its own OKCONNECT and
gets a freshly derived transit key). The firmware zeroizes the key after one
encrypted response, and `Session.consume()` mirrors that here.

Commands are never encrypted: they carry only public data (KEM ciphertexts).

Framing:
  cmd (always plaintext) : 0xA5, seq, len(=64), report[64], crc16       (69 B)
  rsp plaintext          : 0x5A, seq, len(=64), report[64], crc16       (69 B)
  rsp encrypted          : 0x5B, seq, len(=64), ct[64], tag[16], crc16  (85 B)
"""
import hashlib

SOF_CMD = 0xA5
SOF_RSP = 0x5A
SOF_RSP_ENC = 0x5B

REPORT_LEN = 64
FRAME_LEN = 69
ENC_FRAME_LEN = 85
TAG_LEN = 16

# Session control opcodes (report[4]); see okic2.h
CMD_SESSION = 0xE0
CMD_SESSEND = 0xE1

FIXED_IV = b"\x00" * 12      # safe: the key is single-use (see module docstring)


def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= (b & 0xFF) << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def derive_transit_key(ss32):
    """transit_key = SHA256(ss) — matches okic2_session_set()."""
    if len(ss32) != 32:
        raise ValueError("shared secret must be 32 bytes")
    return hashlib.sha256(bytes(ss32)).digest()


class TransitError(Exception):
    pass


class Session(object):
    """Holds at most one single-use transit key."""

    def __init__(self, transit_key=None):
        self.transit_key = transit_key

    @property
    def established(self):
        return self.transit_key is not None

    def consume(self):
        """Drop the key after one encrypted message — mirrors the firmware."""
        self.transit_key = None

    def end(self):
        self.transit_key = None

    def _aesgcm(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise TransitError(
                "python 'cryptography' is required for I2C transit encryption")
        if not self.established:
            raise TransitError("no transit key set")
        return AESGCM(self.transit_key)

    def open(self, ct, tag):
        try:
            return self._aesgcm().decrypt(FIXED_IV, bytes(ct) + bytes(tag), None)
        except TransitError:
            raise
        except Exception:
            raise TransitError("GCM tag mismatch — frame tampered or wrong key")

    # --- framing ------------------------------------------------------------
    def build_command(self, seq, report):
        """Commands are always plaintext (public data only)."""
        r = bytearray(report[:REPORT_LEN])
        r += bytes(REPORT_LEN - len(r))
        frame = bytearray([SOF_CMD, seq, REPORT_LEN]) + r
        c = crc16(frame)
        return bytes(frame + bytes([(c >> 8) & 0xFF, c & 0xFF]))

    def parse_response(self, buf):
        """Validate/decrypt a response frame; return the 64-byte report."""
        if not buf:
            raise TransitError("empty response frame")

        if buf[0] == SOF_RSP:
            if len(buf) < FRAME_LEN or buf[2] != REPORT_LEN:
                raise TransitError("malformed plaintext response frame")
            want = (buf[67] << 8) | buf[68]
            if crc16(buf[:67]) != want:
                raise TransitError("response CRC mismatch")
            return bytes(buf[3:3 + REPORT_LEN])

        if buf[0] == SOF_RSP_ENC:
            if len(buf) < ENC_FRAME_LEN or buf[2] != REPORT_LEN:
                raise TransitError("malformed encrypted response frame")
            want = (buf[83] << 8) | buf[84]
            if crc16(buf[:83]) != want:
                raise TransitError("response CRC mismatch")
            if not self.established:
                raise TransitError("encrypted response but no transit key")
            report = self.open(buf[3:67], buf[67:83])
            self.consume()          # one key, one message
            return report

        raise TransitError("unknown response SOF 0x%02x" % buf[0])
