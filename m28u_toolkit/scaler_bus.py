"""Constrained register transport for read-only SPI acquisition.

Separate from status GETs: ISP entry/reset affect the display. These operations
must be requested explicitly. No SPI erase/program/status-write is representable.
"""
import contextlib
import os
from pathlib import Path
import platform
import re
import selectors
import stat
import struct
import subprocess
import tempfile
import time

from .protocol import decode_reply, get_request, readback_request
from .transport import descriptor_matches

ROOT = Path(__file__).resolve().parent.parent
READ_OPCODES = {3, 5, 0x9F}
READ_CONTROLS = {0x42, 0x43, 0x46, 0x47, *range(0x5A, 0x60)}
VENDOR_CLOCK_SEQUENCE = ((0xF4, 0x9F), (0xF5, 0x06), (0xF4, 0xA0), (0xF5, 0x74))


@contextlib.contextmanager
def live_lock():
    import fcntl
    path = Path(tempfile.gettempdir()) / f"m28u-toolkit-{os.getuid()}.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("Unexpected toolkit lock file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another toolkit hardware command is active") from None
        yield
    finally:
        os.close(fd)


def read_packet(reg, length, register_length=1):
    result = bytearray(192)
    result[:11] = struct.pack("<BBIBBBBB", 0x40, 0xD6, reg, length, 0, 0x94, register_length, 0x80)
    return bytes(result)


def write_packet(reg, value):
    result = bytearray(192)
    result[:11] = bytes.fromhex("40 c6 00 00 00 00 02 00 94 00 80")
    result[64:66] = bytes((reg, value))
    return bytes(result)


class RegisterBus:
    """Shared policy, enforced before either native backend sees a request."""
    def __init__(self, *, allow_vendor_clock=False):
        if not isinstance(allow_vendor_clock, bool):
            raise ValueError("Vendor clock permission must be boolean")
        self.allow_vendor_clock = allow_vendor_clock
        self.clock_attempted = self.clock_configured = False
        self.attempted = False
        self.entered = False
        self.mode = self.control = None
        self.stream_ready = False

    def configure_vendor_clock(self):
        """One fixed official ISP sequence, separately opted in; no indexed API."""
        if not self.allow_vendor_clock or not self.attempted or not self.entered or self.clock_attempted or self.control is None or self.control & 1:
            raise ValueError("Vendor clock configuration is not permitted in this state")
        self.clock_attempted = True
        self.stream_ready = False
        self._vendor_clock()
        self.clock_configured = True

    def _vendor_clock(self):
        for reg, value in VENDOR_CLOCK_SEQUENCE:
            self._write(reg, value)

    def boot_bank(self):
        """Read FFFF once, only after observing normal mode; never select a bank."""
        if self.mode is None or self.mode & 0x80 or self.attempted or self.entered:
            raise ValueError("Boot-bank read requires an observed normal, unowned session")
        self.stream_ready = False
        data = self._boot_bank()
        if len(data) != 1:
            raise ValueError("Short boot-bank read")
        return data[0]

    def _boot_bank(self):
        return self._read(0xFF, 1)

    def boot_mapping(self):
        """Fixed indexed reads of FFFC/FFFD/FFFF; only index latches are written."""
        if self.mode is None or self.mode & 0x80 or self.attempted or self.entered:
            raise ValueError("Boot mapping requires an observed normal, unowned session")
        self.stream_ready = False
        data = self._boot_mapping()
        if len(data) != 3:
            raise ValueError("Short boot-mapping read")
        return dict(zip(("fffc", "fffd", "ffff"), data))

    def _boot_mapping(self):
        data = bytearray()
        for low in (0xFC, 0xFD, 0xFF):
            for reg, value in ((0xF4, 0x9F), (0xF5, 0xFF), (0xF4, low)):
                self._write(reg, value)
            value = self._read(0xF5, 1)
            if len(value) != 1:
                raise ValueError("Short indexed boot-register read")
            data.extend(value)
        return bytes(data)

    def read(self, reg, length=1):
        allowed = (reg in (0x6F, 0x60) and length == 1) or (
            self.entered and ((reg == 0x70 and 1 <= length <= 128) or
                              (reg in (0x61, 0x67, 0x68, 0x69) and length == 1)))
        if not allowed:
            raise ValueError("Register read refused by SPI-read policy")
        self.stream_ready = False
        data = self._read(reg, length)
        if len(data) != length:
            raise ValueError("Short register read")
        self.stream_ready = self.entered and reg == 0x70
        if reg == 0x6F:
            self.mode = data[0]
            if self.attempted:
                self.entered = bool(self.mode & 0x80)
        elif reg == 0x60:
            self.control = data[0]
        return data

    def read_stream(self, length):
        if not self.entered or not self.stream_ready or not isinstance(length, int) or isinstance(length, bool) or not 1 <= length <= 128:
            raise ValueError("Streaming port is not selected or length is invalid")
        self.stream_ready = False
        data = self._stream(length)
        if len(data) != length:
            raise ValueError("Short streaming read")
        self.stream_ready = True
        return data

    def write(self, reg, value):
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 255:
            raise ValueError("Register value must be a byte")
        preflight = self.mode is not None and not self.mode & 0x80 and self.control is not None and not self.control & 1
        allowed = (reg == 0x6F and value == 0x80 and not self.attempted and preflight) or (
            reg == 0xEE and value == 2 and self.attempted) or (
            self.entered and ((reg == 0x60 and value in READ_CONTROLS) or
                              (reg == 0x61 and value in READ_OPCODES) or
                              (reg in (0x64, 0x65, 0x66)) or (reg == 0x6A and value == 3)))
        if not allowed:
            raise ValueError("Register write refused by SPI-read policy")
        if reg == 0x60 and value & 1:
            if self.read(0x61)[0] not in READ_OPCODES:
                raise ValueError("SPI opcode readback is not a permitted read")
        if reg == 0x6F:
            self.attempted = True  # A failed host transfer may still have reached hardware.
        self.stream_ready = False
        if reg == 0xEE:
            try:
                self._write(reg, value)
            finally:
                # Reset can remove USB before acknowledgement. Do not resend
                # into a rebooting device; the runner must verify fresh state.
                self.attempted = self.entered = False
        else:
            self._write(reg, value)


class MacBus(RegisterBus):
    def __init__(self, *, allow_vendor_clock=False):
        super().__init__(allow_vendor_clock=allow_vendor_clock)
        self.process = None
        self.selector = None
        self.buffer = bytearray()
        self.broken = False

    def worker_args(self):
        args = [str(ROOT / "tools/m28u_scaler_macos"), "--stdio"]
        if self.allow_vendor_clock:
            args.append("--allow-vendor-clock")
        return args

    def __enter__(self):
        args = self.worker_args()
        self.process = subprocess.Popen(args,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=None, bufsize=0)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        try:
            if not re.fullmatch(rb"READY -?\d+", self._line()):
                raise ValueError("Unexpected native worker greeting")
        except BaseException:
            self.__exit__(*sys_exc_info())
            raise
        return self

    def _line(self):
        deadline = time.monotonic() + 8
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise TimeoutError("Native worker timed out; ISP exit may be unconfirmed")
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                raise OSError("Native worker exited before replying")
            self.buffer.extend(chunk)
            if len(self.buffer) > 4096:
                raise ValueError("Oversized native worker reply")
        line, _, remainder = self.buffer.partition(b"\n")
        self.buffer = bytearray(remainder)
        return bytes(line)

    def _command(self, command):
        if self.broken:
            raise OSError("Native IPC is unsynchronized; only worker shutdown/reset fallback is allowed")
        encoded = (command + "\n").encode("ascii")
        try:
            if self.process.stdin.write(encoded) != len(encoded):
                raise OSError("Short native worker command")
            result = self._line().decode("ascii")
        except BaseException:
            self.broken = True
            raise
        if result != "OK" and not result.startswith("OK "):
            raise OSError(f"Native worker refused/stopped: {result}")
        return result[3:] if result.startswith("OK ") else ""

    def firmware(self):
        value = self._command("V")
        if not re.fullmatch(r"F\d{2}", value):
            raise ValueError("Invalid native firmware result")
        return value

    def source(self):
        value = self._command("A")
        if not value.isdecimal() or not 0 <= int(value) <= 65535:
            raise ValueError("Invalid source response")
        return int(value)

    def _read(self, reg, length):
        return bytes.fromhex(self._command(f"R {reg:x} {length}"))

    def _boot_bank(self):
        return bytes.fromhex(self._command("B"))

    def _boot_mapping(self):
        return bytes.fromhex(self._command("I"))

    def _write(self, reg, value):
        if self._command(f"W {reg:x} {value:x}"):
            self.broken = True
            raise ValueError("Unexpected data in write acknowledgement; native IPC stopped")

    def _stream(self, length):
        return bytes.fromhex(self._command(f"S {length}"))

    def _vendor_clock(self):
        if self._command("C"):
            self.broken = True
            raise ValueError("Unexpected data in vendor clock acknowledgement")

    def __exit__(self, exc_type, exc, tb):
        if self.process is not None:
            try:
                if self.process.poll() is None:
                    try:
                        self.process.stdin.write(b"Q\n")
                        self.process.stdin.close()
                    except OSError:
                        pass
                    try:
                        self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.process.terminate()
                        try:
                            self.process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            self.process.kill()
                            self.process.wait(timeout=2)
            finally:
                if self.selector is not None:
                    self.selector.close()
                if not self.process.stdin.closed:
                    try:
                        self.process.stdin.close()
                    except OSError:
                        pass
                self.process.stdout.close()
            if exc_type is None and self.process.returncode != 0:
                raise OSError("Native worker did not finish normally; monitor state unconfirmed")


def sys_exc_info():
    import sys
    return sys.exc_info()


class LinuxBus(RegisterBus):
    """Linux hidraw backend; requires hardware validation on Linux."""
    def __init__(self, device, *, allow_vendor_clock=False):
        super().__init__(allow_vendor_clock=allow_vendor_clock)
        self.device, self.fd = device, None

    @staticmethod
    def _ioc(direction, number, length):
        return direction << 30 | length << 16 | ord("H") << 8 | number

    def __enter__(self):
        import fcntl
        if platform.machine() not in ("x86_64", "aarch64", "arm64"):
            raise ValueError("Unsupported Linux ioctl ABI")
        if not self.device or not re.fullmatch(r"/dev/hidraw\d+", self.device):
            raise ValueError("Select an explicit /dev/hidrawN")
        self.fd = os.open(self.device, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if not stat.S_ISCHR(os.fstat(self.fd).st_mode):
                raise ValueError("Expected hidraw character device")
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            info, size = bytearray(8), bytearray(4)
            fcntl.ioctl(self.fd, self._ioc(2, 3, 8), info, True)
            if struct.unpack("=IHH", info) != (3, 0xBDA, 0x1100):
                raise ValueError("Wrong USB interface")
            fcntl.ioctl(self.fd, self._ioc(2, 1, 4), size, True)
            n = struct.unpack("=I", size)[0]
            if not 1 <= n <= 4096:
                raise ValueError("Invalid descriptor size")
            descriptor = bytearray(4100)
            struct.pack_into("=I", descriptor, 0, n)
            fcntl.ioctl(self.fd, self._ioc(2, 2, 4100), descriptor, True)
            if not descriptor_matches(descriptor[4:4+n]):
                raise ValueError("Unexpected descriptor; no output report sent")
        except BaseException:
            self.__exit__(*sys_exc_info())
            raise
        return self

    def _send(self, report):
        import fcntl
        if fcntl.ioctl(self.fd, self._ioc(3, 0x0B, 193), bytearray(b"\0"+report), True) != 193:
            raise OSError("Short output report")

    def _input(self):
        import fcntl
        buf = bytearray(193)
        if fcntl.ioctl(self.fd, self._ioc(3, 0x0A, 193), buf, True) != 193 or buf[0] != 0:
            raise OSError("Short input report or wrong report ID")
        return bytes(buf[1:])

    def _read(self, reg, length):
        self._send(read_packet(reg, length))
        return self._input()[:length]

    def _write(self, reg, value):
        self._send(write_packet(reg, value))

    def _stream(self, length):
        self._send(read_packet(0, length, register_length=0))
        return self._input()[:length]

    def firmware(self):
        if self.attempted:
            raise ValueError("DDC query refused during ISP")
        self._send(get_request("firmware"))
        time.sleep(0.15)
        self._send(readback_request())
        reply = decode_reply("firmware", self._input())
        return f"F{reply.current & 255:02d}"

    def source(self):
        if self.attempted:
            raise ValueError("DDC query refused during ISP")
        self._send(get_request("source"))
        time.sleep(0.15)
        self._send(readback_request())
        return decode_reply("source", self._input()).current

    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None:
            cleanup_error = None
            try:
                if self.attempted:
                    self.write(0xEE, 2)
            except BaseException as error:
                cleanup_error = error
            finally:
                try:
                    os.close(self.fd)
                except BaseException as error:
                    if cleanup_error is None:
                        cleanup_error = error
                finally:
                    self.fd = None
            if cleanup_error is not None:
                report = getattr(exc, "m28u_report", None)
                if report is not None:
                    report["transport_cleanup_failure"] = f"{type(cleanup_error).__name__}: {cleanup_error}"
                # Keep the owned-session report and original cancellation alive.
                if exc is not None and (isinstance(cleanup_error, Exception) or not isinstance(exc, Exception)):
                    exc.m28u_cleanup_error = cleanup_error
                else:
                    if report is not None:
                        cleanup_error.m28u_report = report
                    raise cleanup_error


def open_bus(device=None, *, allow_vendor_clock=False):
    if platform.system() == "Darwin":
        if device is not None:
            raise ValueError("--device is Linux-only")
        return MacBus(allow_vendor_clock=allow_vendor_clock)
    if platform.system() == "Linux":
        return LinuxBus(device, allow_vendor_clock=allow_vendor_clock)
    raise ValueError("Only macOS/Linux native transports are implemented")
