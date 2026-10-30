"""Offline M28U update protocol model. No device/transport code is imported.

The protocol below is traced from Gigabyte RFlash.dll1 variant 2, SHA-256
 e075fff2fe2b9d90da1a520e6f365a15b7fc2ccd96fb5c9f237c9aa566b791b2.
Only SyntheticScaler is accepted. This module cannot open or program hardware.
"""
from .images import IMAGE_SIZE, crc8, identify_stock, make_candidate

SETUP = {0x56: 0x47, 0x57: 0, 0x58: 0, 0x59: 3, 0x5a: 0x36,
         0x5b: 0x22, 0x5c: 0x26, 0x5f: 1, 0x6a: 3, 0x6b: 0x0b,
         0x6c: 0, 0x62: 6, 0x63: 0x50, 0xed: 0x88, 0xee: 4,
         0x6d: 2, 0x71: 255}


def encode_write_payload(payload):
    """Encode traced 2-byte register or 65-byte page I2C writes, offline only."""
    if type(payload) is not bytes or len(payload) not in (2, 65) or (len(payload) == 65 and payload[0] != 0x70):
        raise ValueError("Expected register pair or 64-byte data-port payload")
    result = bytearray(192)
    result[:11] = bytes((0x40, 0xc6, 0, 0, 0, 0, len(payload), 0, 0x94, 0, 0x80))
    result[64:64 + len(payload)] = payload
    return bytes(result)


class SimulatedPowerLoss(Exception):
    """Stops execution immediately; no vendor cleanup is modeled afterward."""


class SyntheticScaler:
    """Immediate-completion model, not a claim about Realtek silicon semantics."""
    def __init__(self, image, fault=None):
        self.flash = bytearray(b"\xa5" * (4 * 1024 * 1024))
        self.flash[0x200000:0x200000 + len(image)] = image
        self.initial = bytes(self.flash)
        self.expected = image
        self.regs = {0x6f: 0, 0x60: 0, 0xe3: 0x90, 0xf2: 0x80, 0x55: 0x81}
        self.indexed = {0x100a: 0xb6}
        self.index_high = self.index_low = 0
        self.staging = bytearray()
        self.events, self.operations = [], []
        self.fault, self.fault_fired = fault, False
        self.reset = False
        self.marker_transitions = []

    def address(self, first=0x64):
        return (self.regs.get(first, 0) << 16) | (self.regs.get(first + 1, 0) << 8) | self.regs.get(first + 2, 0)

    def write(self, payload):
        if not 2 <= len(payload) <= 65:
            raise ValueError("Unexpected synthetic write length")
        self.events.append(("write", bytes(payload).hex()))
        reg, value = payload[:2]
        if reg == 0x70:
            if len(payload) != 65 or len(self.staging) >= 256:
                raise ValueError("Invalid synthetic page staging")
            self.staging.extend(payload[1:])
            return 0
        if len(payload) != 2:
            raise ValueError("Unexpected multi-byte register write")
        self.regs[reg] = value
        if reg == 0xf4:
            self.index_low = value
        elif reg == 0xf5:
            if self.index_low == 0x9f:
                self.index_high = value
            else:
                self.indexed[self.index_high << 8 | self.index_low] = value
        elif reg == 0x60 and value & 1:
            opcode = self.regs[0x61]
            if opcode == 0xd8:
                address = self.address()
                if address % 65536 or not 0x200000 <= address < 0x3b0000:
                    raise ValueError("Vendor erase escaped update area")
                self.flash[address:address + 65536] = b"\xff" * 65536
                self.operations.append(("erase64k", address))
                if self.fault == "power-cut-after-first-erase" and sum(x[0] == "erase64k" for x in self.operations) == 1:
                    self.fault_fired = True
                    raise SimulatedPowerLoss("after first update-bank erase")
            elif opcode == 1:
                self.operations.append(("status-write", self.regs.get(0x64, 0)))
            else:
                raise ValueError(f"Unmodeled SPI command {opcode:#x}")
            self.regs[reg] &= ~1
        elif reg == 0x6f and value & 4:
            first, last = self.address(), self.address(0x72)
            if not 0 <= first <= last < len(self.flash):
                raise ValueError("CRC range escaped flash")
            self.regs[0x75] = crc8(self.flash[first:last + 1])
            if self.fault == "crc-mismatch" and self.operations and self.operations[-1][0] == "program256":
                self.regs[0x75] ^= 1
                self.fault_fired = True
            self.regs[reg] &= ~4
            self.operations.append(("crc", first, last, self.regs[0x75]))
        elif reg == 0x6f and value == 0xa0:
            address = self.address()
            if len(self.staging) != 256 or address % 256 or not 0x200000 <= address < 0x3b0000:
                raise ValueError("Invalid synthetic page program")
            if self.regs.get(0x6d) != 2 or self.regs.get(0x71) != 255:
                raise ValueError("Unexpected program mode")
            for i, byte in enumerate(self.staging):
                self.flash[address + i] &= byte
            self.staging.clear()
            self.operations.append(("program256", address))
            if address == 0x20f800:
                self.marker_transitions.append({"address": address,
                    "marker": self.flash[0x20f8fe:0x20f900].hex(),
                    "complete_image_matches": self.flash[0x200000:0x200000 + len(self.expected)] == self.expected})
                if self.fault == "power-cut-after-marker":
                    self.fault_fired = True
                    raise SimulatedPowerLoss("immediately after marker page")
            self.regs[reg] = (value & ~0x20) | 0x10
            if self.fault == "program-busy":
                self.regs[reg] |= 0x20
                self.fault_fired = True
        elif reg == 0x6f and value == 0x80:
            self.regs[reg] |= 0x10  # Synthetic page FIFO is immediately ready.
        elif reg == 0xee and value == 2:
            self.reset = True
            self.regs[0x6f] = 0
            self.operations.append(("reset",))
        return 0

    def read(self, reg, length):
        if not 1 <= length <= 10:
            raise ValueError("Unexpected synthetic read length")
        data = bytes(self.regs.get(reg + i, 0) for i in range(length))
        if reg == 0xf5:
            data = bytes((self.indexed.get(self.index_high << 8 | self.index_low, 0),))
        status = 0
        if self.fault == "poll-read-error" and reg == 0x60:
            status, data = 1, b"\0" * length
            self.fault_fired = True
        self.events.append(("read", reg, length, data.hex(), status))
        return status, data


class UpdateSimulationError(Exception):
    pass


def replay_update(chip, firmware):
    """Portable register-level implementation, confined to the synthetic chip.

    Successful I2C events must match actual vendor x86 execution exactly.
    Transport failures, polling timeouts and CRC timeouts fail closed here;
    the original updater sometimes ignores these failures. No live bus accepted.
    """
    if type(chip) is not SyntheticScaler or type(firmware) is not bytes or len(firmware) != IMAGE_SIZE:
        raise ValueError("Requires synthetic chip and one complete 27-bank image")
    chip.expected = firmware

    def write(reg, value):
        if chip.write(bytes((reg, value))) != 0:
            raise UpdateSimulationError("I2C write failed")

    def read(reg, length=1):
        status, data = chip.read(reg, length)
        if status != 0 or len(data) != length:
            raise UpdateSimulationError("I2C read failed")
        return data[0] if length == 1 else data

    def poll(reg, mask, target, count=600):
        for _ in range(count):
            if read(reg) & mask == target & mask:
                return
        raise UpdateSimulationError(f"Polling {reg:02x} timed out")

    def pairs(sequence):
        for reg, value in sequence:
            write(reg, value)

    def device_crc(address):
        end = address + 65535
        pairs([(0x64, address >> 16), (0x65, address >> 8 & 255), (0x66, address & 255),
               (0x72, end >> 16), (0x73, end >> 8 & 255), (0x74, end & 255)])
        write(0x6f, read(0x6f, 10)[0] | 4)
        poll(0x6f, 4, 0)
        return read(0x75)

    def erase(bank):
        pairs([(0x64, bank), (0x65, 0), (0x66, 0), (0x60, 0xb8), (0x61, 0xd8), (0x60, 0xb9)])
        poll(0x60, 1, 0)
        if device_crc(bank << 16) != 0xde:
            raise UpdateSimulationError("Erased bank CRC mismatch")

    def program(bank, data):
        pairs([(0x6d, 2), (0x71, 255), (0x64, bank), (0x66, 0)])
        for page in range(256):
            poll(0x6f, 0x10, 0x10, 100)
            write(0x65, page)
            payload = data[page * 256:(page + 1) * 256]
            if payload == b"\xff" * 256:
                continue
            for offset in range(0, 256, 64):
                if chip.write(b"\x70" + payload[offset:offset + 64]) != 0:
                    raise UpdateSimulationError("I2C page staging failed")
            write(0x6f, 0xa0)
            poll(0x6f, 0x20, 0)

    write(0x6f, 0x80)
    poll(0x6f, 0x80, 0x80, 50)
    pairs([(0xf4, 0x9f), (0xf5, 6), (0xf4, 0xa0), (0xf5, 0x74)])
    write(0xf2, read(0xf2) & 0x7f)
    write(0x55, read(0x55) & 0x7f)
    write(0x55, (read(0x55) & 0xfe) | 0x80)
    pairs([(0x56, 0x47), (0x57, 0), (0x58, 0), (0x59, 3),
           (0x5a, 0x36), (0x5b, 0x22), (0x5c, 0x26), (0x5f, 1)])
    pairs([(0x6a, 3), (0x6b, 0x0b), (0x6c, 0), (0x62, 6),
           (0x63, 0x50), (0xed, 0x88), (0xee, 4)])
    pairs([(0xf4, 0x9f), (0xf5, 0x10), (0xf4, 0x0a)])
    wp = (read(0xf5) & 0xf9) | 1
    pairs([(0xf4, 0x0a), (0xf5, wp)])
    write(0xe3, read(0xe3) | 4)
    pairs([(0x60, 0x68), (0x61, 1), (0x64, 0), (0x60, 0x69)])
    poll(0x60, 1, 0)
    erase(32)
    for bank in reversed(range(27)):
        data = firmware[bank * 65536:(bank + 1) * 65536]
        erase(bank + 32)
        program(bank + 32, data)
        if device_crc((bank + 32) << 16) != crc8(data):
            raise UpdateSimulationError("Programmed bank CRC mismatch")
    pairs([(0x60, 0x68), (0x61, 1), (0x64, 255), (0x60, 0x69)])
    poll(0x60, 1, 0)
    write(0xee, 2)
    return 0


def simulate_update(stock, *, candidate=False):
    """User-facing offline path; only exact known public F11 is accepted."""
    if type(candidate) is not bool or identify_stock(stock)[0] != "F11":
        raise ValueError("Requires known F11 and a boolean candidate choice")
    firmware = make_candidate(stock)[0] if candidate else stock
    chip = SyntheticScaler(stock)
    replay_update(chip, firmware)
    if chip.flash[0x200000:0x200000 + IMAGE_SIZE] != firmware:
        raise UpdateSimulationError("Simulation did not reproduce complete firmware")
    return {"kind": "Offline portable M28U update simulation",
            "hardware_access": False, "ready_to_flash": False,
            "candidate": candidate, "i2c_operations": len(chip.events),
            "erase_banks": [x[1] // 65536 for x in chip.operations if x[0] == "erase64k"],
            "program_pages": sum(x[0] == "program256" for x in chip.operations),
            "complete_update_region_matches": True,
            "factory_preserved": chip.flash[:0x200000] == chip.initial[:0x200000],
            "trailing_storage_preserved": chip.flash[0x3b0000:] == chip.initial[0x3b0000:],
            "marker_page_transitions": chip.marker_transitions,
            "reset_requested": chip.reset,
            "limits": ["In-memory SPI model, not hardware execution",
                       "Status-register, electrical and USB/boot recovery semantics are not modeled",
                       "The original read-only transports refuse erase/program/data-port writes"]}

