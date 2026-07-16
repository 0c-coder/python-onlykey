"""
onlykey/i2ctransport.py — I2C transport backend for python-onlykey.

Presents the same minimal surface as an hidapi `device` (`write`, `read`,
`close`, `set_nonblocking`) so OnlyKey.send_message()/read_bytes() work unchanged
over I2C. Talks to the OnlyKey firmware I2C slave (okic2.cpp) at address 0x2C.

Commands go out in the clear (they carry only public KEM ciphertexts). A response
is encrypted iff a single-use transit key is set — see i2csession.py.

Linux only (uses /dev/i2c-N via the I2C_RDWR ioctl).
"""
from __future__ import print_function
import time
import fcntl

from .i2csession import (
    Session, TransitError, derive_transit_key,
    FRAME_LEN, ENC_FRAME_LEN, REPORT_LEN,
    SOF_RSP, SOF_RSP_ENC, CMD_SESSION, CMD_SESSEND,
)

I2C_SLAVE = 0x0703          # <linux/i2c-dev.h> set slave address ioctl

ST_LOCKED = 0x01
ST_IDLE = 0x02
ST_BUSY = 0x03
ST_READY = 0x05
ST_ERROR = 0x06
ST_NOSESS = 0x07


class I2CTransportError(Exception):
    pass


class I2CDevice(object):
    """Duck-typed stand-in for hidapi `device`, backed by /dev/i2c-N."""

    def __init__(self, bus=1, addr=0x2C):
        self.bus = bus
        self.addr = addr
        self._seq = 0
        self.session = Session()
        self._fd = open("/dev/i2c-%d" % bus, "r+b", buffering=0)
        fcntl.ioctl(self._fd, I2C_SLAVE, addr)

    # --- hidapi-compatible surface -----------------------------------------
    def set_nonblocking(self, flag):
        return None      # I2C reads here are explicit polled transactions

    def open_path(self, path):
        return None      # already opened in __init__

    def write(self, raw_bytes):
        """Send a 64-byte OnlyKey report (always plaintext)."""
        self._seq = (self._seq + 1) & 0xFF
        self._fd.write(self.session.build_command(self._seq, bytearray(raw_bytes)))
        return REPORT_LEN

    def read(self, n=REPORT_LEN, timeout_ms=1000):
        """Poll status until a response frame is ready, then return the 64-byte
        report as a list of ints (matching hidapi `device.read`)."""
        deadline = time.time() + (timeout_ms / 1000.0)
        while time.time() < deadline:
            status = self._read_status()
            if status == ST_READY:
                report = self._read_frame()
                if report is not None:
                    return list(report[:n])
            elif status == ST_ERROR:
                raise I2CTransportError("device reported frame/CRC error")
            elif status == ST_NOSESS:
                raise I2CTransportError("device has no transit key set")
            time.sleep(0.02)     # 20 ms poll
        return []                # timeout — empty, like a non-blocking hid read

    def close(self):
        try:
            self._fd.close()
        except Exception:
            pass

    def open(self):
        if self._fd.closed:
            self._fd = open("/dev/i2c-%d" % self.bus, "r+b", buffering=0)
            fcntl.ioctl(self._fd, I2C_SLAVE, self.addr)

    # --- transit key --------------------------------------------------------
    def set_transit_key(self, shared_secret):
        """Arm the single-use transit key from the X-Wing shared secret the host
        obtained by encapsulating to the device's derived transit key. The caller
        must already have sent the matching ciphertext with OKIC2_CMD_SESSION so
        the device derived the same ss on-device. Consumed by the next encrypted
        response."""
        self.session.transit_key = derive_transit_key(shared_secret)

    def end_session(self):
        """Tell the device to zeroize any transit key, then drop ours."""
        report = bytearray(64)
        report[0:4] = b"\xff\xff\xff\xff"
        report[4] = CMD_SESSEND
        self.session.end()
        self.write(report)
        try:
            self.read(timeout_ms=2000)
        except I2CTransportError:
            pass

    # --- internals ----------------------------------------------------------
    def _read_status(self):
        try:
            b = self._fd.read(1)
        except OSError:
            return ST_BUSY
        return b[0] if b else ST_BUSY

    def _read_frame(self):
        want = ENC_FRAME_LEN if self.session.established else FRAME_LEN
        buf = self._fd.read(want)
        if not buf:
            return None
        try:
            return self.session.parse_response(buf)
        except TransitError as e:
            raise I2CTransportError(str(e))
