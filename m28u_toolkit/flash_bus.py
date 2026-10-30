"""Explicit writer transports. Not used by the existing read-only CLI paths."""
import os
import platform
import time

from .scaler_bus import MacBus, LinuxBus, ROOT, READ_CONTROLS, VENDOR_CLOCK_SEQUENCE
from .update_sim import encode_write_payload, SETUP

READS = {3, 5, 0x9f, 0x35, 0x15}


class FlashPolicy:
    def init_writer(self):
        self.armed = self.destructive = self.committed = False
        self.wp_pending = False
        self.wp_saved = None
        self.staged = 0
        self.page_address_checked = False
        self.address_bytes = [None] * 3
        self.opcode = None

    def read(self, reg, length=1):
        allowed = reg in (0x6f, 0x60) and length == 1 or self.entered and (
            reg == 0x6f and length == 10 or reg == 0x64 and length == 3 or reg == 0x70 and 1 <= length <= 128 or
            length == 1 and reg in {0x61, 0x55, 0xf2, 0xe3, 0xf5, 0x75, *range(0x64, 0x6a)})
        if not allowed:
            raise ValueError("Writer read is outside its fixed register set")
        self.stream_ready = False
        data = self._read(reg, length)
        if len(data) != length:
            raise OSError("Short writer register read")
        if reg == 0x6f:
            self.mode = data[0]
            if self.attempted:
                self.entered = bool(self.mode & 0x80)
        if reg == 0x60:
            self.control = data[0]
        self.stream_ready = reg == 0x70
        return data

    def _address_valid(self, alignment):
        if None in self.address_bytes:
            return False
        address = int.from_bytes(bytes(self.address_bytes), "big")
        # A host-successful register write can still be ignored by the device.
        actual = bytes(self.read(reg)[0] for reg in (0x64, 0x65, 0x66))
        return actual == bytes(self.address_bytes) and 0x200000 <= address < 0x3b0000 and address % alignment == 0

    def write(self, reg, value):
        if type(reg) is not int or type(value) is not int or not 0 <= reg <= 255 or not 0 <= value <= 255:
            raise ValueError("Writer register/value must be bytes")
        preflight = self.mode is not None and not self.mode & 0x80 and self.control is not None and not self.control & 1
        allowed = reg == 0x6f and value == 0x80 and not self.attempted and preflight or \
                  reg == 0xee and value == 2 and self.attempted and not self.wp_pending and (not self.destructive or self.committed)
        if self.entered:
            allowed |= reg == 0x61 and (value in READS or self.armed and self.wp_pending and value in (1, 0xd8))
            allowed |= reg in (0x64, 0x65, 0x66) or reg == 0x6a and value == 3
            if reg == 0x60:
                allowed |= value in READ_CONTROLS and (not value & 1 or self.read(0x61)[0] in READS)
                allowed |= self.armed and self.wp_pending and value in (0x68, 0xb8)
                if self.armed and self.wp_pending and value in (0x69, 0xb9):
                    actual = self.read(0x61)[0]
                    allowed |= value == 0x69 and actual == 1 and self.address_bytes[0] is not None and self.read(0x64)[0] == self.address_bytes[0] or \
                               value == 0xb9 and actual == 0xd8 and self._address_valid(65536)
                    if allowed:
                        self.destructive = True
            if self.armed:
                allowed |= SETUP.get(reg) == value or reg in (0xf2, 0x55, 0x72, 0x73, 0x74)
                allowed |= reg == 0x6f and self.mode is not None and self.mode & 0x80 and not self.mode & 0x20 and value == self.mode | 4
                if reg == 0x6f and value == 0xa0 and self.wp_pending and self.staged == 256 and self.page_address_checked:
                    allowed = True
                    self.destructive = True
        if not allowed:
            raise ValueError("Writer write refused by fixed command/address policy")
        self.stream_ready = False
        if reg == 0x6f and value == 0x80:
            self.attempted = True
        if reg in (0x64, 0x65, 0x66):
            self.page_address_checked = False
            self.address_bytes[reg - 0x64] = value
            if reg == 0x65:
                self.staged = 0
        if reg == 0x61:
            self.opcode = value
        if reg == 0x6f and value == 0xa0:
            self.staged = 0
            self.page_address_checked = False
        if reg == 0x6f:
            self.mode = None  # A CRC write needs a new mode read, never stale state.
        if reg == 0xee and value == 2:
            try:
                self._write(reg, value)
            finally:
                self.attempted = self.entered = False
        else:
            self._write(reg, value)

    def data(self, chunk):
        if type(chunk) is not bytes or len(chunk) != 64 or not self.armed or not self.entered or not self.wp_pending or self.staged > 192:
            raise ValueError("Page data requires an armed owned ISP session and exactly 64 bytes")
        if self.staged == 0:
            # Some engines advance the visible address while filling the FIFO.
            # Verify the staged start before any data, then retain that evidence
            # only while no host address write intervenes.
            if not self._address_valid(256):
                raise ValueError("Page start address did not verify")
            self.page_address_checked = True
        if not self.page_address_checked:
            raise ValueError("Page address changed during data staging")
        self._data(chunk)
        self.staged += 64

    def arm(self):
        if not self.entered or not self.attempted or self.armed or self.destructive:
            raise ValueError("Cannot arm this session")
        self._arm()
        self.armed = True

    def unlock_wp(self):
        if not self.armed or self.wp_pending or self.wp_saved is not None:
            raise ValueError("Write-protect setup cannot be repeated")
        self.wp_pending = True  # A failed transfer may have reached the monitor.
        self._unlock_wp()

    def restore_wp(self):
        if not self.wp_pending:
            raise ValueError("No owned write-protect setup to restore")
        self._restore_wp()
        self.wp_pending = False

    def commit(self):
        if not self.destructive or self.wp_pending or self.staged:
            raise ValueError("Cannot commit an incomplete writer state")
        self._commit()
        self.committed, self.armed = True, False


class FlashMacBus(FlashPolicy, MacBus):
    def __init__(self):
        super().__init__(allow_vendor_clock=True)
        self.init_writer()

    def worker_args(self):
        return [str(ROOT / "tools/m28u_flash_macos"), "--stdio-writer"]

    def _arm(self):
        self._command("X")

    def _data(self, chunk):
        self._command("D " + chunk.hex())

    def _unlock_wp(self):
        saved = bytes.fromhex(self._command("U"))
        if len(saved) != 2:
            raise ValueError("Unexpected WP snapshot")
        self.wp_saved = tuple(saved)

    def _restore_wp(self):
        self._command("L")

    def _commit(self):
        self._command("K")

    def __exit__(self, exc_type, exc, tb):
        try:
            return super().__exit__(exc_type, exc, tb)
        except Exception as cleanup:
            if exc is None:
                raise
            exc.m28u_writer_cleanup_error = str(cleanup)


class FlashLinuxBus(FlashPolicy, LinuxBus):
    def __init__(self, device):
        super().__init__(device, allow_vendor_clock=True)
        self.init_writer()

    def _arm(self):
        # Independent fixed read, before allowing writes; no guessed chip type.
        for reg, value in ((0x60, 0x46), (0x61, 0x9f), (0x60, 0x47)):
            self._write(reg, value)
        for _ in range(100):
            if not self._read(0x60, 1)[0] & 1:
                if bytes(self._read(reg, 1)[0] for reg in (0x67, 0x68, 0x69)) != b"\xc8\x40\x16":
                    raise ValueError("Writer requires observed C8/40/16")
                return
            time.sleep(0.002)
        raise TimeoutError("Writer chip-ID engine stayed busy")

    def _data(self, chunk):
        self._send(encode_write_payload(b"\x70" + chunk))

    def _unlock_wp(self):
        for reg, value in ((0xf4, 0x9f), (0xf5, 0x10), (0xf4, 0x0a)):
            self._write(reg, value)
        wp = self._read(0xf5, 1)[0]
        e3 = self._read(0xe3, 1)[0]
        self.wp_saved = (wp, e3)
        self._write(0xf4, 0x0a)
        self._write(0xf5, (wp & 0xf9) | 1)
        self._write(0xe3, e3 | 4)
        if self._read(0xf5, 1)[0] != (wp & 0xf9) | 1 or self._read(0xe3, 1)[0] != e3 | 4:
            raise OSError("Write-protect setup readback mismatch")

    def _restore_wp(self):
        if self.wp_saved is None:
            raise ValueError("Original WP values were not acquired")
        for reg, value in ((0xf4, 0x9f), (0xf5, 0x10), (0xf4, 0x0a),
                           (0xf5, self.wp_saved[0]), (0xe3, self.wp_saved[1])):
            self._write(reg, value)
        if self._read(0xf5, 1)[0] != self.wp_saved[0] or self._read(0xe3, 1)[0] != self.wp_saved[1]:
            raise OSError("Write-protect restoration mismatch")

    def _commit(self):
        pass

    def __exit__(self, exc_type, exc, tb):
        if self.wp_pending or self.destructive and not self.committed:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            return
        return super().__exit__(exc_type, exc, tb)


def open_writer(device=None):
    if platform.system() == "Darwin":
        if device is not None:
            raise ValueError("--device is Linux-only")
        return FlashMacBus()
    if platform.system() == "Linux":
        return FlashLinuxBus(device)
    raise ValueError("Writer supports only macOS/Linux")
