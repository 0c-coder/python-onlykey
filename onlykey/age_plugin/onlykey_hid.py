"""OnlyKey USB HID communication for ML-KEM-768 and X-Wing KEM.

Uses the existing onlykey.client.OnlyKey class for HID transport,
with support for multi-packet payloads needed for post-quantum key sizes.

Slots:
  133 (RESERVED_KEY_MLKEM)  - ML-KEM-768 standalone
  134 (RESERVED_KEY_XWING)  - X-Wing hybrid KEM
"""

import hashlib
import sys
import time

from onlykey.client import OnlyKey, Message
from . import OKGETPUBKEY, OKDECRYPT, OKGENKEY, SLOT_MLKEM, SLOT_XWING

KEYTYPE_MLKEM768 = 5
KEYTYPE_XWING = 6


def _challenge_digits(payload):
    """Replicate the firmware's done_process_packets() challenge derivation
    (okcore.cpp) so the 3 confirm buttons can be shown/known ahead of time
    instead of requiring the user to read them off the device LED blinks.
    temp = SHA256(plaintext payload); buttons come from temp[0]/temp[15]/temp[31].
    """
    digest = hashlib.sha256(bytes(payload)).digest()
    return [str((digest[i] % 6) + 1) for i in (0, 15, 31)]

# Sizes
XWING_PK_SIZE = 1216
XWING_CT_SIZE = 1120
XWING_SS_SIZE = 32
MLKEM_PK_SIZE = 1184
MLKEM_CT_SIZE = 1088


class OnlyKeyPQ:
    """Post-quantum KEM interface to OnlyKey hardware."""

    def __init__(self, ok=None):
        """Initialize with existing OnlyKey instance or create new one.

        Args:
            ok: Existing OnlyKey instance, or None to create one.
        """
        if ok is not None:
            self.ok = ok
        else:
            self.ok = OnlyKey()
            self._connect()

    def _connect(self):
        """Connect to OnlyKey device."""
        try:
            self.ok.read_string(timeout_ms=100)
        except Exception:
            pass
        for _ in range(10):
            try:
                self.ok.read_string(timeout_ms=500)
                return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError("Could not connect to OnlyKey. Is it plugged in and unlocked?")

    def _send_and_receive(self, msg_type, slot, payload=b"",
                          expected_size=0, timeout_ms=10000):
        """Send a message and collect multi-packet response."""
        self.ok.send_message(msg=msg_type, slot_id=slot, payload=payload)

        result = bytearray()
        deadline = time.time() + timeout_ms / 1000
        while time.time() < deadline:
            try:
                data = self.ok.read_bytes(64, timeout_ms=2000)
                if data:
                    text = bytes(data).decode("ascii", errors="ignore")
                    if text.startswith("Error"):
                        raise RuntimeError(f"OnlyKey: {text.strip()}")
                    result.extend(data)
                    if expected_size and len(result) >= expected_size:
                        break
            except Exception:
                if result:
                    break
                continue

        return bytes(result[:expected_size] if expected_size else result)

    def _generate_keypair(self, slot, keytype, expected_size, timeout_ms=60000):
        """Trigger on-device keygen for slot 133/134 (ML-KEM/X-Wing).

        The firmware gates keygen behind the same 3-button challenge used by
        decaps (set_private() -> ecc_priv_flash() -> process_packets(), see
        okcore.cpp): the "all 0xFF" trigger payload primes the challenge and
        the firmware replies with nothing until the 3 confirm buttons are
        pressed on the device, at which point it completes the keygen and
        sends the public key. The challenge digits are derived from
        SHA256(payload) and computed here too so they can be shown/known
        ahead of the (silent) device LED blink, rather than requiring the
        user to read them off the device.
        """
        payload = bytearray([keytype]) + bytearray([0xFF] * 8)
        digits = _challenge_digits(payload)
        print(
            f"Press these 3 OnlyKey buttons in order to confirm key generation: "
            f"{digits[0]}, {digits[1]}, {digits[2]}",
            file=sys.stderr,
        )
        pk = self._send_and_receive(
            OKGENKEY, slot,
            payload=payload,
            expected_size=expected_size,
            timeout_ms=timeout_ms,
        )
        if len(pk) != expected_size:
            raise RuntimeError(f"keygen: got {len(pk)} bytes, expected {expected_size}")
        return pk

    def xwing_keygen(self):
        """Generate X-Wing keypair. Returns 1216-byte public key."""
        return self._generate_keypair(SLOT_XWING, KEYTYPE_XWING, XWING_PK_SIZE)

    def xwing_getpubkey(self):
        """Get X-Wing public key. Returns 1216-byte public key."""
        pk = self._send_and_receive(
            OKGETPUBKEY, SLOT_XWING,
            expected_size=XWING_PK_SIZE,
            timeout_ms=10000,
        )
        if len(pk) != XWING_PK_SIZE:
            raise RuntimeError(f"X-Wing getpubkey: got {len(pk)} bytes, expected {XWING_PK_SIZE}")
        return pk

    def xwing_decaps(self, ciphertext):
        """X-Wing decapsulation. Returns 32-byte shared secret."""
        if len(ciphertext) != XWING_CT_SIZE:
            raise ValueError(f"X-Wing CT must be {XWING_CT_SIZE} bytes, got {len(ciphertext)}")
        print("Press OnlyKey button to confirm decryption...", file=sys.stderr)
        ss = self._send_and_receive(
            OKDECRYPT, SLOT_XWING,
            payload=ciphertext,
            expected_size=XWING_SS_SIZE,
            timeout_ms=30000,
        )
        if len(ss) != XWING_SS_SIZE:
            raise RuntimeError(f"X-Wing decaps: got {len(ss)} bytes, expected {XWING_SS_SIZE}")
        return ss

    def mlkem_keygen(self):
        """Generate ML-KEM-768 keypair. Returns 1184-byte public key."""
        return self._generate_keypair(SLOT_MLKEM, KEYTYPE_MLKEM768, MLKEM_PK_SIZE)

    def mlkem_getpubkey(self):
        """Get ML-KEM-768 public key. Returns 1184-byte public key."""
        return self._send_and_receive(
            OKGETPUBKEY, SLOT_MLKEM,
            expected_size=MLKEM_PK_SIZE,
            timeout_ms=10000,
        )

    def mlkem_decaps(self, ciphertext):
        """ML-KEM-768 decapsulation. Returns 32-byte shared secret."""
        if len(ciphertext) != MLKEM_CT_SIZE:
            raise ValueError(f"ML-KEM CT must be {MLKEM_CT_SIZE} bytes, got {len(ciphertext)}")
        print("Press OnlyKey button to confirm decryption...", file=sys.stderr)
        return self._send_and_receive(
            OKDECRYPT, SLOT_MLKEM,
            payload=ciphertext,
            expected_size=32,
            timeout_ms=30000,
        )
