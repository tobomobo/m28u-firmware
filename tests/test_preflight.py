import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from m28u_toolkit.images import IMAGE_SIZE, SIGNATURE
from m28u_toolkit.preflight import CAPACITY, prepare_sector, sector_plan

TIMER = 0x13A79B
STOCK = bytearray(hashlib.shake_256(b"synthetic offline sector fixture").digest(IMAGE_SIZE))
STOCK[TIMER:TIMER + len(SIGNATURE)] = SIGNATURE
STOCK[0xF8FE:0xF900] = b"\xaa\x55"
STOCK = bytes(STOCK)
CAPTURE = bytes([0x11]) * 0x200000 + STOCK + bytes([0xFF]) * (CAPACITY - 0x200000 - len(STOCK))


class SectorPlanTests(unittest.TestCase):
    def plan(self, first=CAPTURE, second=CAPTURE, stock=STOCK):
        # Only stock identity is substituted. The real layout, diff, preservation,
        # erase-bit and bounds checks execute against synthetic bytes.
        with patch("m28u_toolkit.preflight.identify_stock", return_value=("F11", TIMER)):
            return sector_plan(first, second, stock)

    def test_exact_sector_and_preservation(self):
        before, after, report = self.plan()
        self.assertEqual(len(before), 4096)
        self.assertEqual(len(after), 4096)
        self.assertEqual([(i, a, b) for i, (a, b) in enumerate(zip(before, after)) if a != b],
                         [(0x79E, 0x88, 0x60), (0x7A0, 0x13, 0xEA)])
        self.assertEqual(report["sector"]["address"], 0x33A000)
        self.assertTrue(report["erase_required_for_zero_to_one_bits"])
        self.assertTrue(report["factory_lower_2mib_preserved"])
        self.assertTrue(report["trailing_storage_preserved"])
        self.assertFalse(report["ready_to_flash"])
        self.assertFalse(report["hardware_access"])
        self.assertEqual(CAPTURE[0x20F8FE:0x20F900], b"\xaa\x55")

    def test_capture_mismatch_or_truncation_refused(self):
        changed = bytearray(CAPTURE)
        changed[-1] ^= 1
        for first, second in ((CAPTURE[:-1], CAPTURE[:-1]), (CAPTURE, changed)):
            with self.assertRaises(ValueError):
                self.plan(first, second)

    def test_wrong_reference_location_or_modified_region_refused(self):
        for address in (0x200000, 0x33A79E, 0x20F8FE):
            changed = bytearray(CAPTURE)
            changed[address] ^= 1
            with self.assertRaises(ValueError):
                self.plan(changed, changed)
        shifted = STOCK + CAPTURE[IMAGE_SIZE:]
        with self.assertRaises(ValueError):
            self.plan(shifted, shifted)

    def test_unrecognized_stock_is_not_accepted_by_real_validator(self):
        with self.assertRaises(ValueError):
            sector_plan(CAPTURE, CAPTURE, STOCK)

    def test_non_f11_and_changed_signature_refused(self):
        with patch("m28u_toolkit.preflight.identify_stock", return_value=("F10", TIMER)):
            with self.assertRaises(ValueError):
                sector_plan(CAPTURE, CAPTURE, STOCK)
        stock = bytearray(STOCK)
        stock[TIMER] ^= 1
        capture = CAPTURE[:0x200000] + stock + CAPTURE[0x200000 + IMAGE_SIZE:]
        with self.assertRaises(ValueError):
            self.plan(capture, capture, stock)

    def test_private_output_no_overwrite_and_no_hardware(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            paths = [root / n for n in ("first.bin", "second.bin", "stock.bin")]
            for p, data in zip(paths, (CAPTURE, CAPTURE, STOCK)):
                p.write_bytes(data)
            out = root / "plan"
            with patch("m28u_toolkit.preflight.identify_stock", return_value=("F11", TIMER)), \
                 patch("m28u_toolkit.scaler_bus.open_bus", side_effect=AssertionError("hardware")):
                prepare_sector(*paths, out)
                with self.assertRaises(FileExistsError):
                    prepare_sector(*paths, out)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
            for p in out.iterdir():
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            self.assertFalse(json.loads((out / "plan.json").read_text())["ready_to_flash"])
            self.assertEqual(paths[0].read_bytes(), CAPTURE)


if __name__ == "__main__":
    unittest.main()
