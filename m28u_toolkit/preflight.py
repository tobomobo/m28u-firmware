"""Offline preparation of one preserved 4-KiB sector; no programming transport."""
import hashlib
import json
import os
from pathlib import Path

from .images import IMAGE_SIZE, SIGNATURE, identify_stock, read_exact_file

CAPACITY = 4 * 1024 * 1024
UPDATE_BASE = 0x200000
SECTOR_SIZE = 4096
PAGE_SIZE = 256


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sector_plan(first, second, stock):
    """Consistency and exact stock attribution only; never grants write readiness."""
    if len(first) != CAPACITY or len(second) != CAPACITY or first != second:
        raise ValueError("Two matching, complete 4-MiB captures are required")
    version, timer = identify_stock(stock)
    if version != "F11":
        raise ValueError("This bounded sector plan supports exact stock F11 only")
    if first.find(stock) != UPDATE_BASE or first.find(stock, UPDATE_BASE + 1) != -1:
        raise ValueError("Expected one exact F11 image at 2 MiB")
    if stock[timer:timer + len(SIGNATURE)] != SIGNATURE:
        raise ValueError("Unexpected timer instructions")
    if first[UPDATE_BASE + 0xF8FE:UPDATE_BASE + 0xF900] != b"\xaa\x55":
        raise ValueError("Expected update-image marker is absent")
    changes = [(UPDATE_BASE + timer + 3, 0x88, 0x60),
               (UPDATE_BASE + timer + 5, 0x13, 0xEA)]
    start = changes[0][0] & ~(SECTOR_SIZE - 1)
    if start != 0x33A000 or any(address // SECTOR_SIZE != start // SECTOR_SIZE
                                for address, _, _ in changes):
        raise ValueError("Candidate escaped the audited single sector")
    original = first[start:start + SECTOR_SIZE]
    candidate = bytearray(original)
    for address, before, after in changes:
        if candidate[address - start] != before:
            raise ValueError("Original patch byte mismatch")
        candidate[address - start] = after
    candidate = bytes(candidate)
    changed = [start + i for i, (a, b) in enumerate(zip(original, candidate)) if a != b]
    if changed != [entry[0] for entry in changes]:
        raise ValueError("Unexpected candidate changes")
    virtual = first[:start] + candidate + first[start + SECTOR_SIZE:]
    if virtual[:UPDATE_BASE] != first[:UPDATE_BASE] or \
       virtual[UPDATE_BASE + IMAGE_SIZE:] != first[UPDATE_BASE + IMAGE_SIZE:]:
        raise ValueError("Candidate changed factory or trailing storage")
    report = {
        "kind": "UNVALIDATED offline single-sector standby plan",
        "hardware_access": False, "ready_to_flash": False,
        "capture_sha256": digest(first), "stock_f11_sha256": digest(stock),
        "stock_reference_base": UPDATE_BASE,
        "boot_marker": {"address": UPDATE_BASE + 0xF8FE,
                        "value": "aa55", "preserved": True},
        "sector": {"address": start, "bytes": SECTOR_SIZE,
                   "original_sha256": digest(original),
                   "candidate_sha256": digest(candidate)},
        "changes": [{"address": a, "before": x, "after": y} for a, x, y in changes],
        "timer_counts": {"before": 5000, "after": 60000},
        "erase_required_for_zero_to_one_bits": any((x & y) != y for _, x, y in changes),
        "program_page_bytes": PAGE_SIZE, "program_pages_if_full_sector_restored": 16,
        "unchanged_bytes_in_sector": SECTOR_SIZE - len(changes),
        "bytes_outside_sector_preserved": True,
        "factory_lower_2mib_preserved": True, "trailing_storage_preserved": True,
        "blockers": [
            "Running boot-bank/address mapping needs independent correlation",
            "Recovery from invalid executing code has not been demonstrated",
            "An intact AA55 marker is not proof of valid executing firmware",
            "Write protection and board-specific programming path are unverified",
            "Timer wall-clock behavior and USB retention have not been exercised",
            "One-device programming result is documented in docs/findings.md; failed-boot recovery remains unproven"],
    }
    return original, candidate, report


def prepare_sector(first_path, second_path, stock_path, output_directory):
    first = read_exact_file(first_path, CAPACITY)
    second = read_exact_file(second_path, CAPACITY)
    stock = read_exact_file(stock_path, IMAGE_SIZE)
    original, candidate, report = sector_plan(first, second, stock)
    output = Path(output_directory)
    output.mkdir(mode=0o700)  # Refuses existing directories and symlinks.
    for name, data in (("sector-original.bin", original),
                       ("sector-candidate-UNVALIDATED.bin", candidate),
                       ("plan.json", (json.dumps(report, indent=2) + "\n").encode())):
        fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    return report
