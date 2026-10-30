"""Offline candidate identity and the boundary against the live SDR writer."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from m28u_toolkit.images import IMAGE_SIZE, SDR_CAP540_SHA256, read_sdr_cap540
from m28u_toolkit.writer import run
from tools.build_kvm_experiment import HOOK, STUB, build, stub_bytes
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

    def test_research_image_refused_before_live_transport_open(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            candidate = folder / "research.bin"
            candidate.write_bytes(self.target)
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
