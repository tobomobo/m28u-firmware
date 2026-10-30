"""Bounded M28U F11 writer. Only the explicit runner opens writer transports.

Same vendor SPI primitives, with two deliberate changes: original SR1 is
restored instead of writing FF; AA55 is committed after byte-verified firmware.
"""
import hashlib
import json
import os
from pathlib import Path
import time

from .images import (IMAGE_SIZE, SDR_CAP540_BANK20_SHA256, crc8, identify_stock,
                     make_candidate, read_exact_file, read_sdr_cap540, sha256)
from .preflight import CAPACITY, UPDATE_BASE, sector_plan
from .scaler import SpiReader, _private_json
from .update_sim import SETUP

MARKER = 0x20f8fe


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _prefer_failure(previous, incoming):
    # Preserve the first cancellation, otherwise let cancellation outrank an
    # ordinary device/cleanup error without losing failure ownership.
    if previous is None or isinstance(previous, Exception) and not isinstance(incoming, Exception):
        return incoming
    return previous


class FlashReader(SpiReader):
    def _check_address(self, address):
        # M28U register bursts repeat the selected register; select each byte.
        actual = bytes(self.bus.read(reg)[0] for reg in (0x64, 0x65, 0x66))
        if actual != address.to_bytes(3, "big"):
            raise ValueError("Verification read address did not verify")

    def _command(self, opcode, length, address=None):
        if opcode not in (3, 5, 0x9f, 0x35, 0x15) or not 1 <= length <= 3 or (opcode == 3) != (address is not None):
            raise ValueError("Only bounded SPI reads permitted")
        control = 0x40 | (0x18 if address is not None else 0) | length << 1
        self.bus.write(0x60, control)
        self.bus.write(0x61, opcode)
        if address is not None:
            for reg, value in zip((0x64, 0x65, 0x66), address.to_bytes(3, "big")):
                self.bus.write(reg, value)
            self._check_address(address)
        self.bus.write(0x60, control | 1)
        self._poll(0x60, 1, 0, timeout=3, attempts=300)
        return bytes(self.bus.read(0x67 + i)[0] for i in range(length))

    def stream(self, address, length):
        self._range(address, length)
        if address % 256:
            raise ValueError("Streaming read requires a 256-byte aligned start")
        self.bus.write(0x60, 0x46)
        self.bus.write(0x61, 3)
        mapped = (address - 1) & 0xffffff
        for reg, value in zip((0x64, 0x65, 0x66), mapped.to_bytes(3, "big")):
            self.bus.write(reg, value)
        self.bus.write(0x6a, 3)
        self._check_address(mapped)
        self.bus.write(0x60, 0x47)
        self._poll(0x60, 1, 0)
        self.bus.read(0x70)  # Same verified start-1/dummy convention as SpiReader.
        remaining = length
        while remaining:
            if self.deadline is not None and self.clock() >= self.deadline:
                raise TimeoutError("Acquisition deadline exceeded; stopping for reset")
            n = min(128, remaining)
            yield self.bus.read_stream(n)
            remaining -= n

    def statuses(self):
        first = tuple(self._command(op, 1)[0] for op in (5, 0x35, 0x15))
        second = tuple(self._command(op, 1)[0] for op in (5, 0x35, 0x15))
        if first != second or first[0] & 3 or first[1] & 0xc5:
            raise ValueError("Unstable, busy, suspended, inverted-protection or locked status; no write permitted")
        return first


def load_job(first_path, second_path, stock_path, candidate, *, sdr_cap540=None):
    if type(candidate) is not bool:
        raise ValueError("Candidate choice must be boolean")
    if sdr_cap540 is not None and not candidate:
        raise ValueError("Stock-only and SDR cap540 choices are mutually exclusive")
    first, second = (read_exact_file(p, CAPACITY) for p in (first_path, second_path))
    stock = read_exact_file(stock_path, IMAGE_SIZE)
    sector_plan(first, second, stock)
    target = (read_sdr_cap540(sdr_cap540, stock) if sdr_cap540 is not None else
              make_candidate(stock)[0] if candidate else stock)
    target_name = "sdr-cap540" if sdr_cap540 is not None else "standby" if candidate else "stock"
    expected = first[:UPDATE_BASE] + target + first[UPDATE_BASE + IMAGE_SIZE:]
    return first, stock, target, {"backup_sha256": hashlib.sha256(first).hexdigest(),
        "target_sha256": hashlib.sha256(target).hexdigest(), "candidate": candidate,
        "target_name": target_name,
        "sdr_hardware_validated": False,
        "expected_main_array_sha256": hashlib.sha256(expected).hexdigest(),
        "write_region": [UPDATE_BASE, UPDATE_BASE + IMAGE_SIZE],
        "marker_commit": "AA55 programmed only after all image bytes except marker have passed byte-for-byte readback",
        "original_status_restored": True}


def preflight(bus, backup, stock, *, candidate_bank=None, clock=time.monotonic, sleep=time.sleep, progress=lambda s: None):
    if candidate_bank is not None and (type(candidate_bank) is not bytes or len(candidate_bank) != 65536):
        raise ValueError("Known candidate-bank alternative must be exactly 64 KiB")
    reader = FlashReader(bus, clock=clock, sleep=sleep, timeout_seconds=180)
    if bus.read(0x6f)[0] & 0x80 or bus.firmware() != "F11":
        raise ValueError("Expected normal F11 before taking ownership")
    reader.enter(configure_clock=False)
    identity = reader.identify()
    if identity["jedec_id"] != "c84016":
        raise ValueError("Writer is limited to observed C8/40/16")
    statuses = reader.statuses()
    mode_before = bus.read(0x6f)[0]
    # Read both changed banks. Separate allowlists could accept a hybrid image
    # (SDR code with the stock standby bank), so recognize the pair as a unit.
    progress("Read-only preflight: comparing both 64 KiB patch banks and saved-array samples")
    address = 0x330000
    started = clock()
    live = b"".join(reader.stream(address, 65536))
    elapsed = clock() - started
    matches = "stock" if live == backup[address:address + 65536] else "candidate" if candidate_bank is not None and live == candidate_bank else None
    if matches is None:
        raise ValueError("Live patch bank differs from the verified backup")
    sdr_address = 0x340000
    started = clock()
    live_sdr = b"".join(reader.stream(sdr_address, 65536))
    sdr_elapsed = clock() - started
    if live_sdr == stock[0x140000:0x150000]:
        installed = "stock" if matches == "stock" else "standby"
    elif (matches == "candidate" and
          sha256(live_sdr) == SDR_CAP540_BANK20_SHA256):
        installed = "sdr-cap540"
    else:
        raise ValueError("Live SDR bank or installed bank pair is not a recognized F11 image")
    points = [0, 0x123, 0xaff00, 0x1f0000, MARKER, 0x200000, 0x2a9e80,
              0x3b0000, 0x3f0000, 0x3ffffd]
    for address in points:
        if reader.read_small(address, 3) != backup[address:address + 3]:
            raise ValueError(f"Live saved-array sample differs at {address:#x}")
    return reader, {"jedec_id": identity["jedec_id"], "status": list(statuses),
                    "patch_bank_exact": True, "patch_bank_matches": matches, "saved_array_samples": len(points),
                    "isp_mode_raw": mode_before, "patch_bank_read_seconds": elapsed,
                    "patch_bank_read_kib_per_second": 64 / elapsed if elapsed > 0 else None,
                    "sdr_bank_exact": True, "installed_image": installed,
                    "sdr_bank_read_seconds": sdr_elapsed,
                    "sdr_bank_sha256": sha256(live_sdr),
                    "identity_scope": "Complete banks 19/20 and ten array samples; not a full live image capture",
                    "flash_write_sent": False}


class Programmer:
    def __init__(self, bus, reader, *, clock=time.monotonic, sleep=time.sleep, record=lambda *a: None):
        self.bus, self.reader = bus, reader
        self.clock, self.sleep, self.record = clock, sleep, record
        self.deadline = clock() + 3600
        self.reader.deadline = self.deadline

    def poll(self, reg, mask, value, seconds=5):
        until = min(self.deadline, self.clock() + seconds)
        # The fallback bound covers the entire sleep budget even with instant
        # I/O; it only adds termination for a broken/frozen injected clock.
        for _ in range(int(seconds / 0.002) + 2):
            if self.clock() >= until:
                break
            if self.bus.read(reg)[0] & mask == value:
                return
            self.sleep(0.002)
        raise TimeoutError(f"Writer engine timeout at {reg:#x}")

    def ready(self):
        until = min(self.deadline, self.clock() + 10)
        for _ in range(2002):
            if self.clock() >= until:
                break
            if not self.reader._command(5, 1)[0] & 1:
                return
            self.sleep(0.005)
        raise TimeoutError("SPI write-in-progress did not clear")

    def pairs(self, pairs):
        for reg, value in pairs:
            if self.clock() >= self.deadline:
                raise TimeoutError("Whole-update deadline expired")
            self.bus.write(reg, value)

    def status(self, value):
        self.record("status-write", {"value": value})
        self.pairs([(0x60, 0x68), (0x61, 1), (0x64, value), (0x60, 0x69)])
        self.poll(0x60, 1, 0)
        self.ready()
        if self.reader._command(5, 1)[0] & 0xfc != value & 0xfc:
            raise ValueError("Status register write did not verify")

    def crc(self, address, expected):
        end = address + 65535
        self.pairs([(0x64, address >> 16), (0x65, address >> 8 & 255), (0x66, address & 255),
                    (0x72, end >> 16), (0x73, end >> 8 & 255), (0x74, end & 255)])
        mode = self.bus.read(0x6f, 10)[0]
        self.record("crc-request", {"address": address, "mode_before": mode})
        self.bus.write(0x6f, mode | 4)
        self.poll(0x6f, 4, 0)
        if self.bus.read(0x75)[0] != expected:
            raise ValueError(f"Device CRC mismatch at {address:#x}")
        self.record("crc-verified", {"address": address, "crc8": expected, "mode_after": self.bus.mode})

    def erase(self, bank):
        if type(bank) is not int or not 32 <= bank <= 58:
            raise ValueError("Erase bank escaped fixed update region")
        self.record("erase-bank", {"bank": bank})
        self.pairs([(0x64, bank), (0x65, 0), (0x66, 0), (0x60, 0xb8), (0x61, 0xd8), (0x60, 0xb9)])
        self.poll(0x60, 1, 0, 10)
        self.ready()
        self.crc(bank << 16, 0xde)

    def page(self, address, data):
        if type(address) is not int or address % 256 or not UPDATE_BASE <= address < UPDATE_BASE + IMAGE_SIZE or len(data) != 256:
            raise ValueError("Page escaped update region or length")
        if data == b"\xff" * 256:
            return
        self.pairs([(0x6d, 2), (0x71, 255), (0x64, address >> 16),
                    (0x66, 0), (0x65, address >> 8 & 255)])
        self.poll(0x6f, 0x10, 0x10)
        for i in range(0, 256, 64):
            if self.clock() >= self.deadline:
                raise TimeoutError("Update deadline expired during page staging")
            self.bus.data(data[i:i + 64])
        if self.clock() >= self.deadline:
            raise TimeoutError("Update deadline expired before page trigger")
        self.bus.write(0x6f, 0xa0)
        self.poll(0x6f, 0x20, 0)

    def verify_bank(self, address, data):
        self.ready()
        self.crc(address, crc8(data))
        actual = b"".join(self.reader.stream(address, 65536))
        if actual != data:
            raise ValueError(f"Byte readback mismatch at {address:#x}")
        self.record("bank-byte-verified", {"address": address, "sha256": hashlib.sha256(actual).hexdigest()})
        return actual

    def update(self, target, original_status, progress=lambda s: None):
        if len(target) != IMAGE_SIZE or target[0xf8fe:0xf900] != b"\xaa\x55":
            raise ValueError("Target length or marker mismatch")
        self.bus.arm()
        self.bus.configure_vendor_clock()
        self.bus.write(0xf2, self.bus.read(0xf2)[0] & 0x7f)
        self.bus.write(0x55, self.bus.read(0x55)[0] & 0x7f)
        self.bus.write(0x55, (self.bus.read(0x55)[0] & 0xfe) | 0x80)
        self.pairs([(r, SETUP[r]) for r in (0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5f,
                                               0x6a, 0x6b, 0x6c, 0x62, 0x63, 0xed, 0xee)])
        # These banks are unchanged in both accepted targets. Exercise CRC and
        # its post-completion status twice before GPIO or nonvolatile writes.
        for bank in range(2):
            self.crc(UPDATE_BASE + bank * 65536, crc8(target[bank * 65536:(bank + 1) * 65536]))
        self.record("read-only-crc-checks-passed", {"banks": [32, 33]})
        # The vendor verifies by CRC only. Our added SPI reads must also work
        # after its full SETUP, before unlocking GPIO or changing flash/status.
        if self.reader.statuses() != original_status:
            raise ValueError("Post-setup status registers differ from preflight")
        if self.reader.read_small(MARKER, 2) != b"\xaa\x55":
            raise ValueError("Post-setup boot marker read did not verify")
        started = self.clock()
        unchanged = b"".join(self.reader.stream(UPDATE_BASE + 65536, 65536))
        if unchanged != target[65536:131072]:
            raise ValueError("Post-setup bank 33 read did not verify")
        self.ready()  # Leave streaming-read mode before the first write.
        self.record("post-setup-read-checks-passed", {
            "status": list(original_status), "marker": "aa55", "bank": 33,
            "sha256": hashlib.sha256(unchanged).hexdigest(),
            "bank_read_seconds": self.clock() - started})
        self.bus.unlock_wp()
        self.record("original-wp", {"values": self.bus.wp_saved})
        self.status(0)
        self.erase(32)  # Same early marker invalidation as the official updater.
        if self.reader.read_small(MARKER, 2) != b"\xff\xff":
            raise ValueError("Boot marker did not erase; refusing all subsequent bank updates")
        self.record("boot-marker-erased-byte-verified", {})
        verified = [None] * 27
        for bank in reversed(range(27)):
            progress(f"Updating and byte-verifying bank {bank + 32} ({27 - bank}/27)")
            data = bytearray(target[bank * 65536:(bank + 1) * 65536])
            if bank == 0:
                data[0xf8fe:0xf900] = b"\xff\xff"
            data = bytes(data)
            self.erase(bank + 32)
            for page in range(256):
                self.page(((bank + 32) << 16) + page * 256, data[page * 256:(page + 1) * 256])
            verified[bank] = self.verify_bank((bank + 32) << 16, data)
        self.record("all-code-verified-marker-invalid", {})
        self.ready()  # End the preceding streaming-read setup before page staging.
        commit = bytearray(b"\xff" * 256)
        commit[254:256] = b"\xaa\x55"
        self.record("commit-marker", {})
        self.page(MARKER & ~255, bytes(commit))
        verified[0] = self.verify_bank(UPDATE_BASE, target[:65536])
        actual = b"".join(verified)
        if actual != target:
            raise ValueError("Complete verified image differs from target")
        self.status(original_status[0] & 0xfc)
        if self.reader.statuses() != original_status:
            raise ValueError("Original status registers did not restore")
        self.bus.restore_wp()
        self.record("verified-ready-for-reset", {"readback_sha256": hashlib.sha256(actual).hexdigest()})
        self.bus.commit()
        return actual


def run(first_path, second_path, stock_path, output_directory, *, live=False, program=False,
        candidate=True, sdr_cap540=None, device=None, progress=lambda s: None):
    """No transport import/open until all local inputs and explicit flags pass."""
    if type(live) is not bool or type(program) is not bool:
        raise ValueError("Live/program choices must be boolean")
    backup, stock, target, job = load_job(first_path, second_path, stock_path, candidate,
                                        sdr_cap540=sdr_cap540)
    if not live:
        return {**job, "hardware_access": False, "flash_write_sent": False,
                "message": "Offline job only; --live preflights, --live --program permits the update"}
    from .flash_bus import open_writer
    from .scaler_bus import live_lock
    from .backup import _open_after_reset
    candidate_bank = make_candidate(stock)[0][0x130000:0x140000]
    output = Path(output_directory)
    output.mkdir(mode=0o700)
    _private_json(output / "job.json", job)
    events = output / "journal.jsonl"
    fd = os.open(events, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    result = {"job": job, "hardware_access": True, "program_requested": program,
              "flash_write_attempted": False, "update_byte_verified": False,
              "normal_operation_confirmed": False}
    with os.fdopen(fd, "w") as journal:
        # File fsync alone does not persist either newly created directory entry.
        # Fail before opening hardware if the filesystem cannot provide this.
        _sync_directory(output)
        _sync_directory(output.parent)
        def record(event, data):
            journal.write(json.dumps({"event": event, "data": data, "utc_epoch": time.time()}) + "\n")
            journal.flush()
            os.fsync(journal.fileno())
        with live_lock():
            failure = None
            reset_error = None
            dirty = False
            owned = False
            try:
                with open_writer(device) as bus:
                    reader = None
                    try:
                        reader, checks = preflight(bus, backup, stock, candidate_bank=candidate_bank, progress=progress)
                        result["preflight"] = checks
                        record("read-only-preflight-passed", checks)
                        if program:
                            actual = Programmer(bus, reader, record=record).update(target, tuple(checks["status"]), progress)
                            result["update_byte_verified"] = True
                            result["readback_sha256"] = hashlib.sha256(actual).hexdigest()
                            file = output / "image-readback.bin"
                            capture_fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
                            with os.fdopen(capture_fd, "wb") as capture:
                                capture.write(actual);capture.flush();os.fsync(capture.fileno())
                    except BaseException as error:
                        failure = error
                    finally:
                        owned = bus.attempted
                        dirty = bus.destructive and not bus.committed
                        result["flash_write_attempted"] = bus.destructive
                        result["committed"] = bus.committed
                        if not bus.destructive and bus.wp_pending:
                            try:
                                bus.restore_wp()
                            except BaseException as error:
                                result["wp_cleanup_error"] = str(error)
                                failure = _prefer_failure(failure, error)
                        # Unverified GPIO restoration also requires holding ISP,
                        # even if no nonvolatile write was attempted.
                        dirty = dirty or bus.wp_pending
                        if bus.attempted and not dirty:
                            try:
                                bus.write(0xee, 2)
                            except BaseException as error:
                                reset_error = error
                        if dirty:
                            record("held-in-isp-after-failure", {"reason": str(failure)})
                            progress("Update uncommitted; preserving ISP state. Do not power-cycle until recovery is assessed.")
            except BaseException as error:
                failure = _prefer_failure(failure, error)
            if not dirty and owned:
                try:
                    time.sleep(3)
                    with _open_after_reset(device, progress) as fresh:
                        if fresh.read(0x6f)[0] & 0x80:
                            raise ValueError("Still in ISP after reset")
                        result["source_after"] = fresh.source()
                        result["firmware_after"] = fresh.firmware()
                    if result["firmware_after"] != "F11":
                        raise ValueError("Unexpected firmware after reset")
                    result["normal_operation_confirmed"] = True
                except BaseException as error:
                    result["normal_check_error"] = str(error)
                    failure = _prefer_failure(failure, error)
            if reset_error is not None:
                result["reset_transfer_error"] = str(reset_error)
                if not result["normal_operation_confirmed"] and failure is None:
                    failure = reset_error
                if not isinstance(reset_error, Exception):
                    failure = _prefer_failure(failure, reset_error)
            result["held_in_isp"] = dirty
            if failure is not None:
                result["failure"] = f"{type(failure).__name__}: {failure}"
            _private_json(output / "result.json", result)
            if failure is not None:
                failure.m28u_writer_result = result
                raise failure
    return result
