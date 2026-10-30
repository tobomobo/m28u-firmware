"""Read-only SPI engine. ISP entry/reset are volatile display-affecting actions.

Register interface: vendor RFlash.dll, corroborated by flashrom's Realtek MST
driver. Streaming reads remain an unvalidated hypothesis on this M28U hardware.
The runner proves stream alignment against independent small SPI reads before
publishing any main-array capture. No complete-device recovery claim is made.
"""
import hashlib
import json
import os
from pathlib import Path
import time

from .images import BANK_SIZE, identify_stock, read_exact_file

# C2 20 16 and 4 MiB: Macronix MX25L3206E datasheet table 6. This ID may be
# shared by compatible parts; it identifies a supported geometry, not a unique
# part revision. Unknown IDs are refused; capacity is never guessed.
CHIPS = {
    bytes.fromhex("c2 20 16"): ("Macronix C2/20/16 (32 Mbit main array)", 4*1024*1024),
    # Observed twice on this M28U. GD25Q32C Rev4.1: ID table p15,
    # 4096 KiB p4, READ 03h p19, RDSR 05h p18. Exact revision unknown.
    # https://download.gigadevice.com/Datasheet/DS-00088-GD25Q32C-Rev4.1.pdf
    bytes.fromhex("c8 40 16"): ("GigaDevice C8/40/16 (32 Mbit main array)", 4*1024*1024),
}
# RFlash.fnNewFlashBIOS contains both default-base and +32-bank variants.
# Matching a region here does not identify the active boot slot.
REFERENCE_BASES = (0, 32*BANK_SIZE)


class ResetUnconfirmed(OSError):
    """Reset transfer lacked an ACK; only fresh normal responses can resolve it."""


class SpiReader:
    def __init__(self, bus, *, clock=time.monotonic, sleep=time.sleep, timeout_seconds=600):
        if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or not 30 <= timeout_seconds <= 3600:
            raise ValueError("Acquisition timeout must be an integer from 30 to 3600 seconds")
        self.bus, self.clock, self.sleep = bus, clock, sleep
        self.timeout_seconds = timeout_seconds
        self.capacity = None
        self.deadline = None

    def _poll(self, reg, mask, target, timeout=1.0, attempts=100):
        deadline = self.clock()+timeout
        for _ in range(attempts):
            if self.clock() >= deadline:
                break
            if self.bus.read(reg)[0] & mask == target:
                return
            self.sleep(0.002)
        raise TimeoutError(f"Scaler register {reg:#x} did not reach expected state")

    def enter(self, *, configure_clock=True):
        mode, control = self.bus.read(0x6F)[0], self.bus.read(0x60)[0]
        if mode & 0x80 or control & 1:
            raise ValueError("Scaler already in ISP or SPI engine busy; no mode change attempted")
        self.bus.write(0x6F, 0x80)
        self.deadline = self.clock()+self.timeout_seconds
        self._poll(0x6F, 0x80, 0x80)
        if configure_clock and self.bus.allow_vendor_clock:
            self.bus.configure_vendor_clock()

    def close(self):
        if self.bus.attempted:
            self.bus.write(0xEE, 2)  # Same MCU reset request as official updater.

    def _command(self, opcode, length, address=None):
        if opcode not in (3, 5, 0x9F) or not 1 <= length <= 3:
            raise ValueError("Only bounded SPI read commands are permitted")
        if (opcode == 3) != (address is not None):
            raise ValueError("Only READ accepts/requires an address")
        control = 0x40 | (0x18 if address is not None else 0) | length << 1
        self.bus.write(0x60, control)
        self.bus.write(0x61, opcode)
        if address is not None:
            for reg, value in zip((0x64, 0x65, 0x66), address.to_bytes(3, "big")):
                self.bus.write(reg, value)
        self.bus.write(0x60, control | 1)
        self._poll(0x60, 1, 0)
        return bytes(self.bus.read(0x67+i)[0] for i in range(length))

    def identify(self):
        self.capacity = None
        first = self._command(0x9F, 3)
        second = self._command(0x9F, 3)
        if first != second or first not in CHIPS:
            raise ValueError(f"Unstable or unsupported JEDEC ID: {first.hex()}/{second.hex()}; no array read attempted")
        name, capacity = CHIPS[first]
        if self._command(5, 1)[0] & 1:
            raise ValueError("Flash reports a pending write/erase; refusing acquisition")
        self.capacity = capacity
        return {"jedec_id": first.hex(), "geometry": name, "main_array_bytes": self.capacity}

    def _range(self, address, length):
        if self.deadline is not None and self.clock() >= self.deadline:
            raise TimeoutError("Acquisition deadline exceeded; stopping for reset")
        if self.capacity is None:
            raise ValueError("Identify a supported chip before reading its array")
        if not isinstance(address, int) or not isinstance(length, int) or isinstance(address, bool) or isinstance(length, bool) or \
           address < 0 or length <= 0 or address+length > self.capacity:
            raise ValueError("SPI read lies outside the identified main array")

    def read_small(self, address, length=3):
        self._range(address, length)
        if length > 3:
            raise ValueError("Small SPI reads are limited to three bytes")
        return self._command(3, length, address)

    def stream(self, address, length):
        self._range(address, length)
        if address % 256:
            raise ValueError("Streaming read requires a 256-byte aligned start")
        # flashrom's streaming setup uses start-1 and discards one dummy byte.
        # This hardware-specific convention must be checked against read_small.
        self.bus.write(0x60, 0x46)
        self.bus.write(0x61, 3)
        mapped = (address-1) & 0xFFFFFF
        for reg, value in zip((0x64, 0x65, 0x66), mapped.to_bytes(3, "big")):
            self.bus.write(reg, value)
        self.bus.write(0x6A, 3)
        self.bus.write(0x60, 0x47)
        self._poll(0x60, 1, 0)
        self.bus.read(0x70)  # Discard the start-1 byte.
        remaining = length
        while remaining:
            if self.deadline is not None and self.clock() >= self.deadline:
                raise TimeoutError("Acquisition deadline exceeded; stopping for reset")
            n = min(128, remaining)
            yield self.bus.read_stream(n)
            remaining -= n


def sample_offsets(capacity):
    return [bank+offset for bank in range(0, capacity, BANK_SIZE)
            for offset in (0, 0x123, 0x8001, 0xFFFD)]


def _private_json(path, report):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def acquire(bus, stock, output_directory, *, progress=lambda message: None, probe_only=False, timeout_seconds=600):
    """Own one ISP session; always attempt reset after our entry attempt.

    Returns uncommitted .partial captures. The outer runner must close/reopen
    transport and confirm normal firmware before publishing verified filenames.
    """
    version, _ = identify_stock(stock)
    reader = SpiReader(bus, timeout_seconds=timeout_seconds)
    output = Path(output_directory)
    output.mkdir(mode=0o700)  # Fresh directory only; never overwrite a capture.
    report = {"kind": "SPI main-array acquisition", "ready_to_flash": False,
              "reference_firmware": version,
              "complete_device_backup": False, "normal_operation_confirmed": False,
              "captures_verified": False, "probe_only": probe_only,
              "timeout_seconds": timeout_seconds,
              "vendor_isp_clock_requested": bus.allow_vendor_clock,
              "limitations": ["OTP and other nonvolatile devices are outside this capture",
                              "Hardware programmer/boot recovery not verified"]}
    reset_error = primary_error = None
    try:
        if bus.read(0x6F)[0] & 0x80:
            raise ValueError("Scaler already in ISP; no DDC query or mode change attempted")
        if bus.firmware() != version:
            raise ValueError("Installed firmware label does not match the supplied stock reference")
        reader.enter()
        report.update(reader.identify())
        progress(f"Identified {report['jedec_id']}; {reader.capacity} bytes in main array")
        # Independent small reads attribute the target to the expected firmware.
        anchors = (0, 0x10000, 0xA9E80, 0x13A700, len(stock)-3)
        bases = []
        for base in REFERENCE_BASES:
            if base+len(stock) <= reader.capacity and all(
                    reader.read_small(base+offset) == stock[offset:offset+3] for offset in anchors):
                bases.append(base)
        if not bases:
            raise ValueError("No stock reference anchors at documented candidate bases; no bulk capture")
        report["stock_reference_offsets"] = bases
        report["active_boot_slot_identified"] = False
        # Check the stream convention at byte zero and a nonzero bank before
        # requesting the complete chip. Do not silently fall back on mismatch.
        stream_probes = []
        for base in bases:
            for offset in (0, 0xA0000):
                address = base+offset
                started = time.monotonic()
                streamed = b"".join(reader.stream(address, 4096))
                elapsed = time.monotonic()-started
                if streamed != stock[offset:offset+4096]:
                    raise ValueError(f"Streaming read does not match stock at {address:#x}")
                stream_probes.append({"address": address, "bytes": len(streamed),
                                      "elapsed_seconds": elapsed,
                                      "kib_per_second": len(streamed)/1024/elapsed if elapsed > 0 else None})
        report["stream_probe_windows"] = stream_probes
        report["target_reference_anchors_matched"] = True
        report["stream_alignment_checked"] = True
        if probe_only:
            return report
        if os.statvfs(output).f_bavail * os.statvfs(output).f_frsize < reader.capacity*2 + 1024*1024:
            raise OSError("Insufficient free disk space for independent capture passes")
        offsets = sample_offsets(reader.capacity)
        samples = {address: reader.read_small(address) for address in offsets}
        digests = []
        for pass_number in (1, 2):
            progress(f"Reading main array, pass {pass_number}/2")
            path = output / f"pass{pass_number}.partial"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            digest, count = hashlib.sha256(), 0
            with os.fdopen(fd, "wb") as handle:
                for chunk in reader.stream(0, reader.capacity):
                    handle.write(chunk)
                    digest.update(chunk)
                    count += len(chunk)
                    if count % (256*1024) == 0:
                        progress(f"Pass {pass_number}: {count}/{reader.capacity} bytes")
                handle.flush()
                os.fsync(handle.fileno())
            if count != reader.capacity:
                raise ValueError("Incomplete capture")
            # Bounded capture size is derived from the supported geometry.
            captured = read_exact_file(path, reader.capacity)
            if hashlib.sha256(captured).hexdigest() != digest.hexdigest():
                raise ValueError("Saved capture differs from received bytes")
            if any(captured[base:base+len(stock)] != stock for base in bases):
                raise ValueError("Captured firmware region does not exactly match the known stock image")
            for address, expected in samples.items():
                if captured[address:address+3] != expected:
                    raise ValueError(f"Streaming/small-read mismatch at {address:#x}")
            digests.append(digest.hexdigest())
        if digests[0] != digests[1]:
            raise ValueError("Independent full-array passes disagree")
        # A post-pass independent sample catches persistent stream-state changes.
        for address, expected in samples.items():
            if reader.read_small(address) != expected:
                raise ValueError(f"Post-capture small read changed at {address:#x}")
        report.update({"captures_verified": True, "sha256": digests[0],
                       "stock_firmware_region_exact_match": True,
                       "small_read_checks_per_pass": len(samples), "passes": 2})
        return report
    except BaseException as error:
        primary_error = error
        report["failure"] = f"{type(error).__name__}: {error}"
        error.m28u_report = report
        raise
    finally:
        report["isp_entry_attempted"] = bus.attempted
        report["vendor_isp_clock_attempted"] = bus.clock_attempted
        report["vendor_isp_clock_configured"] = bus.clock_configured
        try:
            reset_required = bus.attempted
            report["reset_request_attempted"] = reset_required
            reader.close()
            report["reset_request_sent"] = reset_required and not bus.attempted
        except BaseException as error:
            reset_error = error
            report["reset_request_sent"] = False
            report["reset_failure"] = f"{type(error).__name__}: {error}"
        try:
            _private_json(output / "session.json", report)
        except BaseException as error:
            error.m28u_report = report
            if primary_error is not None and not isinstance(primary_error, Exception):
                raise primary_error from error
            if reset_error is not None and not isinstance(reset_error, Exception):
                reset_error.m28u_report = report
                raise reset_error from error
            raise
        if reset_error is not None:
            if primary_error is not None:
                raise primary_error from reset_error
            if not isinstance(reset_error, Exception):
                reset_error.m28u_report = report
                raise reset_error
            error = ResetUnconfirmed("ISP exit could not be confirmed; manual monitor power cycle may be needed. Captures remain partial.")
            error.m28u_report = report
            raise error from reset_error


def publish_after_normal_check(output_directory, report, firmware):
    """Commit filenames only after a fresh transport verifies normal operation."""
    output = Path(output_directory)
    if not re_firmware(firmware) or firmware != report.get("reference_firmware"):
        raise ValueError("Normal firmware response missing; captures remain partial")
    if not report.get("reset_request_sent") and not (
            report.get("reset_request_attempted") and report.get("reset_confirmed_by_fresh_responses")):
        raise ValueError("No confirmed reset outcome; captures remain partial")
    report = dict(report, normal_operation_confirmed=True, normal_firmware=firmware)
    destination = output / "verified"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Verified output already exists")
    stage = output / ".verified-stage"
    stage.mkdir(mode=0o700)
    if report.get("captures_verified"):
        for n in (1, 2):
            # link() provides no-replace semantics unlike rename() on Unix.
            source = output / f"pass{n}.partial"
            os.link(source, stage / f"spi-main-array-pass{n}.bin")
    _private_json(stage / "result.json", report)
    stage.rename(destination)
    if report.get("captures_verified"):
        for n in (1, 2):
            (output / f"pass{n}.partial").unlink()
    return report


def re_firmware(value):
    import re
    return isinstance(value, str) and bool(re.fullmatch(r"F\d{2}", value))
