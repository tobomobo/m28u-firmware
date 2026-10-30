"""Synthetic USB/SPI responses for the real writer and native worker tests."""
from m28u_toolkit.flash_bus import FlashPolicy, FlashMacBus, FlashLinuxBus
from m28u_toolkit.scaler_bus import RegisterBus, ROOT
from m28u_toolkit.update_sim import SyntheticScaler


class HardwareModel:
    def __init__(self, stock, fault=None):
        self.chip = SyntheticScaler(stock)
        self.status = [0x1c, 2, 0]
        self.stream_at = None
        self.reply = bytes(192)
        self.fault = fault
        self.programmed = 0
        self.marker_states = []
        self.precommit_verified = False
        self.gpio_unlocked = False
        self.marker_erase_ignored = False
        self.crc_reads = 0
        self.setup_applied = False

    def write(self, payload):
        reg, value = payload[:2]
        c = self.chip
        if self.fault == "ignored-high-address" and reg == 0x64 and value == 0x20:
            return  # Host-successful address write ignored by the simulated device.
        if self.fault == "ignored-status-payload" and reg == 0x64 and c.regs.get(0x61) == 1:
            return
        if self.fault == "ignored-inrange-high" and reg == 0x64 and value == 0x33:
            return
        if self.fault == "ignored-inrange-middle" and reg == 0x65 and value == 2:
            return
        if self.fault == "ignored-read-address" and reg == 0x65 and c.regs.get(0x61) == 3:
            return
        if self.fault == "ignored-marker-erase-stale-crc" and reg == 0x60 and value == 0xb9 and c.regs.get(0x61) == 0xd8 and c.address() == 0x200000:
            c.regs[0x60] = 0xb8
            self.marker_erase_ignored = True
            return
        if reg == 0x60 and value & 1 and c.regs.get(0x61) in (3, 5, 0x35, 0x15, 0x9f):
            c.events.append(("write", payload.hex()))
            c.regs[0x60] = value & ~1
            opcode = c.regs[0x61]
            if opcode == 3:
                self.stream_at = c.address() if value == 0x47 else None
                data = c.flash[c.address():c.address() + 3]
            elif opcode == 0x9f:
                data = b"\xc8\x40\x16"
            else:
                data = bytes((self.status[{5: 0, 0x35: 1, 0x15: 2}[opcode]],))
            # Hypothetical SETUP-dependent read failures, not observed hardware.
            if self.setup_applied:
                if self.fault == "post-setup-status" and opcode == 5:
                    data = bytes((data[0] ^ 4,))
                if self.fault == "post-setup-marker" and opcode == 3 and value != 0x47:
                    data = bytes((data[0] ^ 1,)) + data[1:]
            for i, b in enumerate(data):
                c.regs[0x67 + i] = b
            return
        if reg == 0x60 and value == 0x69 and c.regs.get(0x61) == 1:
            self.status[0] = c.regs.get(0x64, 0) & 0xfc
        c.write(payload)
        if reg == 0x6c and value == 0:
            self.setup_applied = True
        if reg == 0xf5 and c.indexed.get(0x100a) == 0xb1:
            self.gpio_unlocked = True
        if reg == 0x6f and value == 0xa0:
            self.programmed += 1
            marker = c.flash[0x20f8fe:0x20f900].hex()
            self.marker_states.append(marker)
            if self.fault == "stuck-program":
                c.regs[0x6f] |= 0x20
            if self.fault == "commit-corrupt" and marker == "aa55":
                c.flash[0x20f800] ^= 1

    def read(self, reg, n):
        if reg == 0x75:
            self.crc_reads += 1
        if self.fault == "ignored-marker-erase-stale-crc" and self.marker_erase_ignored and reg == 0x75:
            return b"\xde"
        if self.fault == "prewrite-crc-mismatch" and reg == 0x75:
            return bytes((self.chip.regs[0x75] ^ 1,))
        if self.fault == "second-prewrite-crc-mismatch" and reg == 0x75 and self.crc_reads == 2:
            return bytes((self.chip.regs[0x75] ^ 1,))
        if self.fault == "wp-restore-read-error" and reg == 0xf5 and self.gpio_unlocked and \
           self.chip.indexed.get(0x100a) == 0xb6 and self.chip.regs[0xe3] == 0x90:
            raise OSError("Injected GPIO restoration readback failure")
        if self.fault == "read-error" and self.programmed:
            raise OSError("Injected read failure")
        if reg == 0x70 and self.stream_at is not None:
            shift = int(self.setup_applied and self.fault == "post-setup-stream-shift")
            out = bytes(self.chip.flash[self.stream_at + shift:self.stream_at + shift + n])
            self.stream_at += n
            if self.fault == "readback-corrupt" and self.programmed:
                out = bytes((out[0] ^ 1,)) + out[1:]
            return out
        return self.chip.read(reg, n)[1]

    def packet(self, packet):
        if len(packet) != 192 or packet[8] != 0x94:
            raise ValueError("Unexpected synthetic packet")
        if packet[1] == 0xc6:
            self.write(packet[64:64 + packet[6]])
        elif packet[1] == 0xd6:
            self.reply = self.read(packet[2] if packet[9] else 0x70, packet[6]).ljust(192, b"\0")
        else:
            raise ValueError("Unexpected packet verb")


class FixedRegisterReadModel(HardwareModel):
    """Observed M28U behaviour: a register burst repeats that register.

    The 0x70 FIFO still advances. The live address diagnostic measured
    read(64,3)=323232 but separate 64/65/66 reads=32ffff. Other registers use
    the same no-increment hypothesis; complete simulations exercise it.
    """
    def __init__(self, stock, fault=None):
        super().__init__(stock, fault)
        self.status = [0xfc, 0, 0]  # Also observed during the live diagnostic.

    def read(self, reg, n):
        if reg != 0x70 and n > 1:
            return super().read(reg, 1) * n
        return super().read(reg, n)


class StickyCrcDoneModel(HardwareModel):
    """Unverified hardware possibility: CRC completion retains mode bit 1."""
    def write(self, payload):
        super().write(payload)
        if payload[0] == 0x6f and payload[1] & 4:
            self.chip.regs[0x6f] |= 2


class AdvancingFifoModel(HardwareModel):
    """Unverified possibility: filling FIFO advances visible address registers."""
    def write(self, payload):
        chip = self.chip
        if payload[0] == 0x70 and len(payload) == 65:
            if not chip.staging:
                self.latched = chip.address()
            super().write(payload)
            address = (chip.address() + 64) & 0xffffff
            for reg, byte in zip((0x64, 0x65, 0x66), address.to_bytes(3, "big")):
                chip.regs[reg] = byte
            return
        if payload == b"\x6f\xa0":
            current = chip.address()
            for reg, byte in zip((0x64, 0x65, 0x66), self.latched.to_bytes(3, "big")):
                chip.regs[reg] = byte
            super().write(payload)
            for reg, byte in zip((0x64, 0x65, 0x66), current.to_bytes(3, "big")):
                chip.regs[reg] = byte
            return
        super().write(payload)


class StickyAdvancingFifoModel(AdvancingFifoModel, StickyCrcDoneModel):
    """Both compatibility hypotheses in one synthetic transaction."""


class FakeWriter(FlashPolicy, RegisterBus):
    def __init__(self, model):
        super().__init__(allow_vendor_clock=True)
        self.init_writer()
        self.model = model

    def _read(self, reg, n):
        return self.model.read(reg, n)

    def _write(self, reg, value):
        self.model.write(bytes((reg, value)))

    def _stream(self, n):
        return self.model.read(0x70, n)

    def firmware(self):
        return "F11"

    def _arm(self):
        pass

    def _data(self, chunk):
        self.model.write(b"\x70" + chunk)

    def _unlock_wp(self):
        c = self.model.chip
        self.wp_saved = (c.indexed[0x100a], c.regs[0xe3])
        c.indexed[0x100a] = (self.wp_saved[0] & 0xf9) | 1
        c.regs[0xe3] = self.wp_saved[1] | 4

    def _restore_wp(self):
        c = self.model.chip
        c.indexed[0x100a], c.regs[0xe3] = self.wp_saved

    def _commit(self):
        self.model.precommit_verified = True


class NativeFakeWriter(FlashMacBus):
    def __init__(self, model):
        super().__init__()
        self.model = model
        self.native_packets = 0

    def worker_args(self):
        return [str(ROOT / "tools/m28u_flash_macos"), "--stdio-writer-dry-run"]

    def firmware(self):
        return "F11"  # No DDC replies modeled; the real runner checks normal FW.

    def _line(self):
        while True:
            line = super()._line()
            if line.startswith(b"USB-OUT "):
                packet = bytes.fromhex(line[8:].decode())
                self.native_packets += 1
                try:
                    self.model.packet(packet)
                    self.process.stdin.write(b"ACK\n")
                except OSError:
                    self.process.stdin.write(b"ERR\n")
            elif line == b"USB-IN":
                self.process.stdin.write(b"DATA " + self.model.reply.hex().encode() + b"\n")
            else:
                return line


class LinuxFakeWriter(FlashLinuxBus):
    def __init__(self, model):
        super().__init__("/dev/hidraw999")
        self.model = model

    def _read(self, reg, n): return self.model.read(reg, n)
    def _write(self, reg, value): self.model.write(bytes((reg, value)))
    def _stream(self, n): return self.model.read(0x70, n)
    def _send(self, packet): self.model.packet(packet)
    def firmware(self): return "F11"
