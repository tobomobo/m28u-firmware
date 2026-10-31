"""Offline candidate identity and the boundary against the live SDR writer."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from m28u_toolkit.images import IMAGE_SIZE, SDR_CAP540_SHA256, read_sdr_cap540
from m28u_toolkit.writer import run
from tools.build_kvm_experiment import HOOK, STUB, build, stub_bytes
from tools.build_kvm_experiment import (COORDINATED_HOOK, COORDINATED_STUB,
                                       build_coordinated, coordinated_stub_bytes)
from tools.build_sdr_experiment import build as build_sdr
from writer_model import FixedRegisterReadModel

ROOT = Path(__file__).resolve().parents[1]
STOCK = ROOT / "firmware/original/GIGABYTE_M28U_F11.bin"


@unittest.skipUnless(STOCK.is_file(), "Requires the public pinned F11 reference")
class KvmResearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stock = STOCK.read_bytes()
        cls.base = build_sdr(cls.stock)[0]
        cls.target, cls.report = build(cls.stock)

    def test_candidate_keeps_existing_patches_and_marker(self):
        self.assertEqual(hashlib.sha256(self.base).hexdigest(), SDR_CAP540_SHA256)
        self.assertEqual(self.target[:0x100000], self.base[:0x100000])
        self.assertEqual(self.target[0x110000:], self.base[0x110000:])
        self.assertEqual(self.target[0xf8fe:0xf900], b"\xaa\x55")
        self.assertEqual(self.target[HOOK:HOOK+3], bytes.fromhex("02 ff 00"))
        self.assertEqual(self.target[STUB:STUB+len(stub_bytes())], stub_bytes())
        self.assertFalse(self.report["ready_to_flash"] or self.report["writer_accepts_target"])

    def test_only_exact_stock_can_build(self):
        for data in (self.base, self.target, self.stock[:-1], bytes(IMAGE_SIZE)):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                build(data)
        for address in (HOOK, STUB, 0xf8fe, 0x13a79e):
            altered = bytearray(self.stock)
            altered[address] ^= 1
            with self.subTest(address=address), self.assertRaises(ValueError):
                build(bytes(altered))

    def test_coordinated_candidate_is_separate_and_bounded(self):
        target, report = build_coordinated(self.stock)
        allowed = set(range(COORDINATED_HOOK, COORDINATED_HOOK+3)) | set(
            range(COORDINATED_STUB, COORDINATED_STUB+len(coordinated_stub_bytes())))
        changed = {i for i, (a, b) in enumerate(zip(self.base, target)) if a != b}
        self.assertTrue(changed and changed <= allowed)
        self.assertEqual(target[HOOK:HOOK+3], self.base[HOOK:HOOK+3])
        self.assertEqual(target[STUB:STUB+len(stub_bytes())], self.base[STUB:STUB+len(stub_bytes())])
        self.assertEqual(target[0xf8fe:0xf900], b"\xaa\x55")
        self.assertEqual(target[COORDINATED_HOOK:COORDINATED_HOOK+3], bytes.fromhex("02 ff 00"))
        self.assertEqual(hashlib.sha256(target).hexdigest(), report["candidate_sha256"])
        self.assertFalse(report["ready_to_flash"])
        self.assertTrue(report["writer_accepts_target"])
        for data in (self.base, self.target, target, self.stock[:-1], bytes(IMAGE_SIZE)):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                build_coordinated(data)

    def test_kvm_images_refused_by_sdr_selector_before_live_transport_open(self):
        for target in (self.target, build_coordinated(self.stock)[0]):
            with self.subTest(sha256=hashlib.sha256(target).hexdigest()):
                self._assert_writer_refuses(target)

    def _assert_writer_refuses(self, target):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            candidate = folder / "research.bin"
            candidate.write_bytes(target)
            with self.assertRaisesRegex(ValueError, "pinned research SHA-256"):
                read_sdr_cap540(candidate, self.stock)
            backup = FixedRegisterReadModel(self.stock).chip.initial
            first, second = folder / "first.bin", folder / "second.bin"
            first.write_bytes(backup)
            second.write_bytes(backup)
            with patch("m28u_toolkit.flash_bus.open_writer") as opened:
                with self.assertRaisesRegex(ValueError, "pinned research SHA-256"):
                    run(first, second, STOCK, folder / "never-created", live=True,
                        program=True, sdr_cap540=candidate)
                opened.assert_not_called()
            self.assertFalse((folder / "never-created").exists())
