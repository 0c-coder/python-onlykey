# onlyagent-fde — OnlyKey full-disk-encryption unlock for LicheeRV/NanoKVM

Boot-time LUKS unlock for the OnlyAgent appliance. The OnlyKey (I2C slave) releases a derived
key-encryption-key after PIN entry; the LicheeRV opens the LUKS2 data partition with it. No key
material touches disk.

## Files

- `okfde-client` — derives the 32-byte KEK from the OnlyKey over I2C. The KEK is an **X-Wing**
  (X25519 + ML-KEM-768) shared secret, HKDF-stretched. `--provision` writes the blob; default
  mode unlocks. Prints the raw KEK to stdout for `cryptsetup --key-file=-`.
- `onlyagent-unlock` — boot script: first-boot LUKS provisioning (single KEK keyslot),
  every-boot open + mount.
- `onlyagent-unlock.service` — systemd unit, ordered before `onlyagentd.service`.
- `test_framing.py` — transport/transit tests (CRC agreement with the C firmware, single-use key
  enforcement, tamper + replay rejection). `python3 onlyagent-fde/test_framing.py`

## Crypto design

**Keys are derived, not stored in a slot.** Both the KEK and the transit key come from
`(OnlyKey web-derivation key, label)` with **full on-device X-Wing** — the ML-KEM seed never
leaves the device. No ECC slot is consumed (101–116 are the user's; 117–132 are reserved), and
because the web-derivation key is covered by OnlyKey backup, the KEK survives device replacement
with no extra provisioning. See `INTEGRATION-i2c.md` §5.

```
  KEK label     : SHA256("fde:onlyagent")
  transit label : SHA256("fde-transit:onlyagent")
```

Those labels are **identifiers, not key derivation** — `SHA256(utf8(label))` is just this
codebase's convention for encoding a label into the 32 bytes the device expects (same as
`age_plugin/derived_xwing.py` and the CLI), and the label is public. The KDF is on-device RFC 5869
HKDF (`okcrypto_hkdf`, reached via `okcrypto_derive_key`):

```
PRK  = HMAC-SHA256(salt = [flag | label32], ikm = web-derivation key)
seed = HMAC-SHA256(PRK, SHA256("onlyagent.app") || 0x01)
```

The HKDF output **is** the X-Wing seed — no second hash. Two details make that work: the call uses
`KEYTYPE_XWING` so `okcrypto_compute_pubkey()` early-returns and leaves the output pristine (the
`KEYTYPE_CURVE25519` path would byte-reverse it via `swap_buffer`), and `flag = 2` domain-separates
it from the age plugin's `sk_X`, which uses flags 0/1 on the same labels.

**KEK (X-Wing).** At provisioning the host reads the derived 1216-byte X-Wing public key,
encapsulates locally → `(ss 32B, ct 1120B)`, and stores `ct` in a blob on the *unencrypted* boot
partition. `KEK = HKDF(ss)`. Every boot the device decapsulates that fixed `ct` on-device, so the
same `ss` — and the same KEK — come back. Because X-Wing is hybrid, an attacker holding the pubkey,
the blob and a disk image must break *both* X25519 and ML-KEM-768.

**Bus (transit encryption).** The I2C traces are probeable, so the KEK response is AES-256-GCM
encrypted. The transit key is itself X-Wing: the host encapsulates to the derived transit key and
the device retains `ss` (encapsulation is randomised, so a fixed device key still yields a fresh
key every boot). `transit_key = SHA256(ss)`. Recorded traffic is therefore PQ-protected too.

**One key, one message — so no counters.** GCM only requires that `(key, nonce)` never repeat; a
fresh key per message makes that true regardless of the nonce, so the fixed IV is safe and no
message counter is needed. This is the same property that makes the web app's zero IV safe over
WebAuthn (each operation there sends its own `OKCONNECT` and gets a freshly derived transit key).
The firmware zeroizes the key right after one encrypted response and `Session.consume()` mirrors
that, so reuse is impossible even by mistake. `LARGE_BUFFER_SIZE` is 1120 — exactly one ct — so
the transit ct and the KEK ct are separate messages anyway.

Commands are never encrypted: they carry only public KEM ciphertexts.

> Unlike `okcrypto_aes_crypto_box()`, okic2 computes and verifies real GCM tags. The firmware's
> fixed IV is fine (one message per key), but `computeTag`/`checkTag` are commented out there, so
> the web transit has no integrity — see the note in `INTEGRATION-i2c.md` §4.

## Install (on the appliance image)

```sh
install -m 0755 okfde-client        /usr/sbin/okfde-client
install -m 0755 onlyagent-unlock    /usr/sbin/onlyagent-unlock
install -m 0644 onlyagent-unlock.service /etc/systemd/system/
pip3 install /path/to/python-onlykey     # the feature/i2c-transport build
systemctl enable onlyagent-unlock.service
```

Requirements on the image: `cryptsetup` (LUKS2), `python3`, `python-onlykey` (I2C transport),
`xxd`. (No `diceware`/`shred` — there is no recovery passphrase; see Recovery above.)

## Configuration (env / unit)

| Var | Default | Meaning |
|-----|---------|---------|
| OKFDE_DEV | /dev/mmcblk0p3 | encrypted data partition |
| OKFDE_NAME | okdata | dm-crypt mapper name |
| OKFDE_MOUNT | /data | mountpoint |
| OKFDE_BUS | 1 | I2C bus number (`/dev/i2c-N`) — match the board |
| OKFDE_ADDR | 0x2c | OnlyKey I2C slave address — match okic2.h |

## Boot flow

1. Unit runs before onlyagentd; skips if `/dev/mapper/okdata` already exists.
2. LED slow-blink → user enters PIN on the OnlyKey keypad (KVM already functional).
3. `okfde-client --wait-pin` polls until unlocked, derives the KEK.
4. First boot: `luksFormat` with a single keyslot (the KEK), `mkfs`.
5. Later boots: `cryptsetup open`, mount `/data`, LED solid, onlyagentd starts.

## Recovery — restore your OnlyKey backup

There is **one LUKS keyslot**: the OnlyKey KEK. Recovery is restoring an OnlyKey backup onto a
replacement device.

That works because the KEK is derived from the web-derivation key (slot 128), and the OnlyKey
backup includes it — `BACKUP` in `okcore.cpp` loops slots 101..132. A restored OnlyKey therefore
re-derives the same X-Wing seed, decapsulates the same stored `ct`, and reproduces the same KEK.
The blob on the boot partition is public and needs no protection.

**There is deliberately no recovery-passphrase keyslot.** It would be a second, weaker path to the
data — a paper passphrase versus a hardware-gated key — and would break the property the product
exists to provide: the disk cannot be opened without the OnlyKey. Keep backups of the OnlyKey
instead; that is the recovery story, and it is the same one users already have for their other
OnlyKey credentials.

Lost OnlyKey + no backup = data unrecoverable, by design.

## Requirements

`kyber-py` (host-side ML-KEM-768, used by `onlykey/age_plugin/mlkem_py.py`) and `cryptography`
(AES-GCM transit) must be on the appliance image, in addition to cryptsetup/python3/xxd/shred.

## Firmware work required (see INTEGRATION-i2c.md)

1. **`okcrypto_xwing_derive_seed(label32)`** — the one genuinely new function, and it is just an
   `okcrypto_derive_key(KEYTYPE_XWING, [2|label32], RESERVED_KEY_WEB_DERIVATION)` call plus RPID
   staging: the HKDF output lands in `ecc_private_key` and *is* the seed. Both
   `okcrypto_xwing_getpubkey()` and `okcrypto_xwing_decaps()` already take the seed from there, so
   they work verbatim. Plus the two dispatch branches (keytype bit 7 = "derived").
   Do not use `KEYTYPE_CURVE25519` here — `swap_buffer` would byte-reverse the seed.
2. **Transit retain flag.** `okcrypto_xwing_decaps()` currently returns `ss`; when
   `okic2_session_target` is set it must call `okic2_session_set(ss)` and ack instead.
3. **Touch policy.** `okcrypto_xwing_decaps()` gates on `CRYPTO_AUTH`. Keep the touch for the KEK
   decapsulation; skip it for transit setup (nothing leaves the device). Boot = PIN + one touch.
4. **Multi-frame reads (provisioning only).** `read_derived_pubkey()` pulls 1216 bytes but
   `okic2_queue_response()` holds one frame. Provision over USB, or add the ring buffer. The
   per-boot unlock never hits this — `pk_transit` is cached in the blob and all responses are 32 B.

## Post-quantum note

The LUKS layer (AES-256-XTS + argon2id) is already quantum-resistant — symmetric only, and Grover
merely halves the margin. PQ effort is confined to the KEK (X-Wing) and the bus (X-Wing session),
both covered above.
