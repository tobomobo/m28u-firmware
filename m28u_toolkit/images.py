"""Offline image checks and deliberately unvalidated standby candidate output."""
import hashlib
import os
from pathlib import Path
import stat

BANK_SIZE = 65536
IMAGE_SIZE = 27 * BANK_SIZE
STOCK = {
    "F10": ("cfdfd5dc5c96208c6f98ca23e444a50f6c4a4cd60c742157df4e1d399c1a4381", 0x13A7D8),
    "F11": ("1ff616f5adcebf5057bd33405709757a68918b3cbfc0fabcad109e8a0a8128d0", 0x13A79B),
}
SIGNATURE = bytes.fromhex("7d 06 7f 88 7e 13 80 43")
MAX_CAPTURE_SIZE = 32 * 1024 * 1024
# One immutable research target, never an arbitrary image override. These pins
# establish identity only; they do not establish electrical or thermal safety.
SDR_CAP540_SHA256 = "abe1e110fcb0feed0aa47841b55c23540d49b24117441eb1f302089257430204"
SDR_CAP540_BANK20_SHA256 = "994a4f137178bc0923e52ae8240e09fde3c62532f002c5d1c73b9f2117462df0"


def read_exact_file(path, expected_bytes):
    """Reject special files and wrong sizes before a bounded regular-file read.

    O_NONBLOCK prevents a supplied FIFO from blocking at open before fstat.
    Checking the read length also catches truncation/growth after fstat.
    """
    if not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool) or not 1 <= expected_bytes <= MAX_CAPTURE_SIZE:
        raise ValueError("Expected capture size must be 1..33554432 bytes")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Input must be a regular file")
        if info.st_size != expected_bytes:
            raise ValueError(f"Input size {info.st_size} does not match expected {expected_bytes} bytes")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(expected_bytes + 1)
        if len(data) != expected_bytes:
            raise ValueError("Input size changed during bounded read")
        return data
    finally:
        os.close(fd)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _crc_table():
    table = []
    for value in range(256):
        for _ in range(8):
            value = ((value << 1) ^ (7 if value & 0x80 else 0)) & 255
        table.append(value)
    return table


CRC_TABLE = _crc_table()


def crc8(data):
    crc = 0
    for value in data:
        crc = CRC_TABLE[crc ^ value]
    return crc


def identify_stock(data):
    if len(data) != IMAGE_SIZE:
        raise ValueError(f"Expected exactly {IMAGE_SIZE} bytes of stock M28U firmware")
    digest = sha256(data)
    for version, (expected, offset) in STOCK.items():
        if digest == expected:
            if data[offset:offset + len(SIGNATURE)] != SIGNATURE or data.count(SIGNATURE) != 1:
                raise ValueError("Standby signature mismatch")
            return version, offset
    raise ValueError("Image is not one of the hash-verified stock M28U F10/F11 files")


def image_report(data):
    version, offset = identify_stock(data)
    return {"version": version, "bytes": len(data), "sha256": sha256(data),
            "timer_setup_offset": hex(offset),
            "bank_crc8": [f"{crc8(data[i:i+BANK_SIZE]):02x}" for i in range(0, len(data), BANK_SIZE)]}


def make_candidate(data):
    version, offset = identify_stock(data)
    candidate = bytearray(data)
    candidate[offset + 3], candidate[offset + 5] = 0x60, 0xEA
    candidate = bytes(candidate)
    changes = [{"offset": hex(i), "before": f"{a:02x}", "after": f"{b:02x}"}
               for i, (a, b) in enumerate(zip(data, candidate)) if a != b]
    if [int(c["offset"], 16) for c in changes] != [offset + 3, offset + 5]:
        raise ValueError("Unexpected candidate changes")
    report = {"kind": "UNVALIDATED standby candidate", "base": image_report(data),
              "candidate_sha256": sha256(candidate), "changes": changes,
              "timer_argument_before": 5000, "timer_argument_after": 60000,
              "changed_banks": [offset // BANK_SIZE],
              "changed_bank_crc8_after": f"{crc8(candidate[(offset//BANK_SIZE)*BANK_SIZE:(offset//BANK_SIZE+1)*BANK_SIZE]):02x}",
              "ready_to_flash": False,
              "limitations": ["Timer unit and real standby duration not measured",
                              "USB retention not established", "No brightness change",
                              "Installed image identity and complete backup not established",
                              "Boot authentication and recovery not validated"]}
    return candidate, report


def read_sdr_cap540(path, stock):
    """Accept only the reviewed research artifact paired with exact stock F11."""
    if identify_stock(stock)[0] != "F11":
        raise ValueError("SDR cap540 requires exact stock F11")
    target = read_exact_file(path, IMAGE_SIZE)
    if sha256(target) != SDR_CAP540_SHA256:
        raise ValueError("SDR cap540 image does not match the pinned research SHA-256")
    standby = make_candidate(stock)[0]
    if (target[:0x140000] != standby[:0x140000] or
            target[0x150000:] != standby[0x150000:] or
            sha256(target[0x140000:0x150000]) != SDR_CAP540_BANK20_SHA256):
        raise ValueError("SDR cap540 bank boundaries do not match the pinned target")
    return target


def compare_captures(first, second, expected_bytes, stock=None):
    if not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool) or expected_bytes <= 0 or expected_bytes > MAX_CAPTURE_SIZE:
        raise ValueError("Expected capture size must be 1..33554432 bytes")
    if len(first) != expected_bytes or len(second) != expected_bytes:
        raise ValueError("Capture size mismatch; no verified capture produced")
    if first != second:
        offset = next(i for i, (a, b) in enumerate(zip(first, second)) if a != b)
        raise ValueError(f"Repeated reads disagree at offset {offset:#x}")
    if len(set(first)) == 1:
        raise ValueError("Constant data cannot establish a valid flash capture")
    report = {"kind": "matching repeated capture", "bytes": len(first), "sha256": sha256(first),
              "complete_device_backup": False,
              "limitations": ["Matching reads establish consistency only",
                              "Flash target, capacity, address map and other nonvolatile storage need independent evidence",
                              "This command compares supplied files; it does not acquire hardware data"]}
    if stock is not None:
        version, _ = identify_stock(stock)
        if len(first) < len(stock):
            raise ValueError("Capture is smaller than the stock firmware region")
        report["stock_comparison"] = {"version": version, "assumed_offset": 0,
                                      "exact_region_match": first[:len(stock)] == stock,
                                      "differing_banks": [i // BANK_SIZE for i in range(0, len(stock), BANK_SIZE)
                                                          if first[i:i+BANK_SIZE] != stock[i:i+BANK_SIZE]]}
    return report


def exclusive_write(path, data):
    """Never silently overwrite firmware, backups or manifests."""
    with Path(path).open("xb") as handle:
        handle.write(data)
