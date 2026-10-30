"""Packet layouts audited against the official RtHIDLib/Sidekick binaries.

Only the fixed GET requests below can cross the live transport boundary.
Generic flash read framing belongs to offline research, not this allowlist.
"""
from dataclasses import dataclass
from functools import reduce
from operator import xor

REPORT_SIZE = 192
GETS = {"firmware": (0xE0, 0x38), "source": (0xE0, 0x2D),
        "usb-b": (0xE0, 0x6B), "usb-c": (0xE0, 0x6C),
        "brightness": (0x10, 0)}


def get_request(name):
    code, subcode = GETS[name]
    payload = bytes((0x51, 0x83, 1, code, subcode)) if code == 0xE0 else bytes((0x51, 0x82, 1, code))
    payload += bytes((reduce(xor, payload, 0),))
    report = bytearray(REPORT_SIZE)
    report[:2] = b"\x40\xc6"
    report[6], report[8], report[10] = 36, 0x6E, 0x80
    report[64:64 + len(payload)] = payload
    return bytes(report)


def readback_request():
    report = bytearray(REPORT_SIZE)
    report[:11] = bytes.fromhex("40 d6 51 00 00 00 24 00 6e 01 80")
    return bytes(report)


@dataclass(frozen=True)
class Reply:
    current: int
    maximum: int


def decode_reply(name, raw):
    code, subcode = GETS[name]
    if len(raw) < 11 or len(raw) > REPORT_SIZE:
        raise ValueError("Truncated or oversized HID reply")
    if raw[:6] != bytes((0x6E, 0x88, 2, 0, code, subcode)):
        raise ValueError("Reply header, success code or selector mismatch")
    if reduce(xor, raw[:11], 0x50):
        raise ValueError("Reply checksum mismatch")
    result = Reply(int.from_bytes(raw[8:10], "big"), int.from_bytes(raw[6:8], "big"))
    if name == "firmware" and (result.current >> 8 != ord("F") or result.current & 255 > 99):
        raise ValueError("Invalid firmware version encoding")
    if name == "brightness" and (result.maximum != 100 or result.current > 100):
        raise ValueError("Unexpected brightness range")
    return result


def require_status_report(report):
    allowed = {get_request(name) for name in GETS} | {readback_request()}
    if report not in allowed:
        raise ValueError("Transport refuses all packets except exact allowlisted status GETs/readback")
