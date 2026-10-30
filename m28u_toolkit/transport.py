"""Bounded status-only native transports. Never used by offline commands."""
import os
from pathlib import Path
import platform
import re
import subprocess
import time

from .protocol import decode_reply, get_request, readback_request, require_status_report

ROOT = Path(__file__).resolve().parent.parent


def descriptor_matches(data):
    """Conservative parser for one unnumbered FFDA/DA application, 192B I/O.

    Unsupported descriptor constructs are rejected rather than guessed.
    """
    page = size = count = 0
    usage = None
    stack = []
    bits = {8: 0, 9: 0}
    applications = 0
    cursor = 0
    try:
        while cursor < len(data):
            prefix = data[cursor]
            cursor += 1
            if prefix == 0xFE:
                return False
            width = (0, 1, 2, 4)[prefix & 3]
            if cursor + width > len(data):
                return False
            value = int.from_bytes(data[cursor:cursor + width], "little")
            cursor += width
            kind, tag = (prefix >> 2) & 3, prefix >> 4
            if kind == 1:
                if tag == 0:
                    page = value
                elif tag == 7:
                    size = value
                elif tag == 9:
                    count = value
                elif tag in (8, 10, 11):  # IDs / push / pop unsupported.
                    return False
            elif kind == 2 and tag == 0:
                usage = value
            elif kind == 0:
                if tag == 10:
                    if not stack:
                        if value != 1 or page != 0xFFDA or usage != 0xDA:
                            return False
                        applications += 1
                    stack.append(value)
                elif tag == 12:
                    stack.pop()
                elif tag in bits:
                    if not stack or not 1 <= size <= 32 or not 1 <= count <= 4096:
                        return False
                    bits[tag] += size * count
                elif tag == 11:  # No feature reports expected.
                    return False
                else:
                    return False
                usage = None
        return applications == 1 and not stack and bits == {8: 1536, 9: 1536}
    except (ValueError, IndexError):
        return False


def linux_query(name, device):
    # Kernel UAPI _IOC layout on x86_64/aarch64 only; fail on other ABIs.
    if platform.machine() not in ("x86_64", "aarch64", "arm64"):
        raise ValueError("Linux ioctl ABI is only implemented for x86_64/aarch64")
    import fcntl
    import stat
    import struct

    def ioc(direction, number, length):
        return direction << 30 | length << 16 | ord("H") << 8 | number

    path = Path(device)
    if not re.fullmatch(r"/dev/hidraw\d+", str(path)):
        raise ValueError("Provide an explicit /dev/hidrawN path")
    fd = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISCHR(os.fstat(fd).st_mode):
            raise ValueError("Expected a hidraw character device")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = bytearray(8)
        fcntl.ioctl(fd, ioc(2, 3, 8), info, True)
        if struct.unpack("=IHH", info) != (3, 0x0BDA, 0x1100):
            raise ValueError("Not a USB Realtek 0bda:1100 interface")
        size = bytearray(4)
        fcntl.ioctl(fd, ioc(2, 1, 4), size, True)
        n = struct.unpack("=I", size)[0]
        if not 1 <= n <= 4096:
            raise ValueError("Invalid report descriptor size")
        descriptor = bytearray(4100)
        struct.pack_into("=I", descriptor, 0, n)
        fcntl.ioctl(fd, ioc(2, 2, 4100), descriptor, True)
        if not descriptor_matches(descriptor[4:4+n]):
            raise ValueError("Unexpected HID descriptor; no output report sent")
        for request in (get_request(name), readback_request()):
            require_status_report(request)
            buf = bytearray(b"\0" + request)
            # Explicit control-endpoint output report, matching macOS/Sidekick.
            sent = fcntl.ioctl(fd, ioc(3, 0x0B, 193), buf, True)
            if sent != 193:
                raise ValueError(f"Short output report ({sent}); stopping without retry")
            time.sleep(0.15)
        buf = bytearray(193)
        n = fcntl.ioctl(fd, ioc(3, 0x0A, 193), buf, True)
        # hidraw returns the report-ID byte even for an unnumbered report.
        if n != 193 or buf[0] != 0:
            raise ValueError(f"Unexpected input report length or report ID: {n}")
        return decode_reply(name, bytes(buf[1:]))
    finally:
        os.close(fd)


def macos_query(name):
    # The existing IOHID helper implements only fixed GETs, never raw packets.
    flags = {"firmware": "--firmware-get", "brightness": "--brightness-get"}
    if name not in flags:
        raise ValueError("macOS CLI supports one firmware or brightness GET per invocation")
    executable = ROOT / "tools/m28u_probe_macos"
    result = subprocess.run([str(executable), flags[name]], check=True,
                            capture_output=True, text=True, timeout=10)
    if name == "firmware":
        match = re.search(r"Validated installed firmware: (F\d{2})", result.stdout)
        if not match:
            raise ValueError("Native helper did not validate firmware reply")
        return {"firmware": match[1], "transport": "macOS IOHID"}
    match = re.search(r"Checksum-valid brightness reply: (\d+)/100", result.stdout)
    if not match:
        raise ValueError("Native helper did not validate brightness reply")
    return {"brightness_raw": int(match[1]), "maximum": 100,
            "active_brightness_confirmed": False, "transport": "macOS IOHID"}


def _status_without_lock(name, device=None):
    if platform.system() == "Darwin":
        if device is not None:
            raise ValueError("--device applies to Linux only")
        return macos_query(name)
    if platform.system() == "Linux":
        if device is None:
            raise ValueError("Linux requires --device /dev/hidrawN; no device scan is performed")
        reply = linux_query(name, device)
        result = {"query": name, "current": reply.current, "maximum": reply.maximum,
                  "transport": "Linux hidraw (not hardware-tested on Linux)"}
        if name == "firmware":
            result["firmware"] = f"F{reply.current & 255:02d}"
        if name == "brightness":
            result["active_brightness_confirmed"] = False
        return result
    raise ValueError("Live status is only implemented for macOS and Linux")


def status(name, device=None):
    from .scaler_bus import live_lock
    with live_lock():
        return _status_without_lock(name, device)
