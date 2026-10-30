"""Offline packet construction. These functions have no hardware transport."""
import struct


def generic_flash_read(address, length):
    # RtHIDLib HID_readflash, RVA 23e0. Target memory is NOT attributed to the
    # M28U scaler. The official scaler updater instead imports I2C functions.
    if not isinstance(address, int) or isinstance(address, bool) or not 0 <= address <= 0xFFFFFFFF:
        raise ValueError("Address must be a uint32")
    if not isinstance(length, int) or isinstance(length, bool) or not 1 <= length <= 128:
        raise ValueError("Read length must be 1..128 bytes")
    if address + length > 0x100000000:
        raise ValueError("Address range wraps uint32")
    report = bytearray(192)
    report[:8] = struct.pack("<BBIBB", 0xC0, 0xD8, address, length, 0)
    return bytes(report)
