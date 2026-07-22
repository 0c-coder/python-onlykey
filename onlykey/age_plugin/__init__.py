"""age-plugin-onlykey: age encryption plugin for OnlyKey hardware tokens.

Supports ML-KEM-768 (FIPS 203) and X-Wing hybrid KEM
(draft-connolly-cfrg-xwing-kem-09) for post-quantum encryption,
compatible with age v1.3.0's mlkem768x25519 recipient type.
"""

from onlykey.client import Message

__version__ = "0.1.0"
PLUGIN_NAME = "onlykey"

# OnlyKey HID message types (from onlykey.client.Message)
OKGETPUBKEY = Message.OKGETPUBKEY
OKDECRYPT = Message.OKDECRYPT
# Keygen goes through the private-key-set path (set_private() -> ecc_priv_flash()
# -> okcrypto_xwing_keygen/okcrypto_mlkem_keygen in firmware), not OKSETSLOT
# (which just writes generic slot fields like URL/username/password and never
# reaches the keygen code at all - the previous OKSETSLOT mapping was a bug).
OKGENKEY = Message.OKSETPRIV

# OnlyKey ECC key slots used for post-quantum keys. Slots 133/134 don't
# exist as usable slots - firmware's own ecc_priv_flash()/okcrypto_getpubkey()/
# okcrypto_decrypt() all bounds-check buffer[5] against 101-132 (okcore.h's
# comment confirms the design: "KEYTYPE_MLKEM768 and KEYTYPE_XWING can be
# stored in any ECC slot (101-132)" - distinguished by the type byte, not a
# dedicated slot range). 101 matches the maintainer's own TC-04 doc
# (`--slot 101`), which --slot never actually gets threaded through to
# (dead flag as of this writing) - these constants are what's actually used.
SLOT_MLKEM = 102
SLOT_XWING = 101
