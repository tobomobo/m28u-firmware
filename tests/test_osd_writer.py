"""Exact OSD target and complete synthetic install/rollback, never hardware."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from m28u_toolkit.__main__ import main
from m28u_toolkit.images import (IMAGE_SIZE, OSD_NO_SIGNAL_SHA256,
                                 OSD_NO_SIGNAL_BANK19_SHA256, read_osd_no_signal)
from m28u_toolkit.writer import load_job, run
from tools.build_kvm_experiment import build_coordinated
from tools.build_osd_experiment import HOOK, TIMER_HOOK, STUB, build, stub_bytes
import test_sdr_writer as sdr_tests

STOCK = sdr_tests.STOCK


@unittest.skipUnless(STOCK.is_file(), "Requires public pinned F11")
class OsdWriterTests(unittest.TestCase):
    fixture = sdr_tests.SdrWriterTests.fixture
    backends = sdr_tests.SdrWriterTests.backends

    @classmethod
    def setUpClass(cls):
        sdr_tests.SdrWriterTests.setUpClass.__func__(cls)
        cls.kvm = build_coordinated(cls.stock)[0]
        cls.osd, cls.manifest = build(cls.stock)
        cls.kvm_path, cls.osd_path = cls.directory / "kvm.bin", cls.directory / "osd.bin"
        cls.kvm_path.write_bytes(cls.kvm)
        cls.osd_path.write_bytes(cls.osd)

    def test_bounded_builder_and_offline_selector(self):
        self.assertEqual(hashlib.sha256(self.osd).hexdigest(), OSD_NO_SIGNAL_SHA256)
        self.assertEqual(hashlib.sha256(self.osd[0x130000:0x140000]).hexdigest(), OSD_NO_SIGNAL_BANK19_SHA256)
        self.assertEqual(read_osd_no_signal(self.osd_path, self.stock), self.osd)
        stub, timer = stub_bytes()
        allowed = set(range(HOOK, HOOK+3)) | set(range(TIMER_HOOK, TIMER_HOOK+3)) | set(range(STUB, STUB+len(stub)))
        changed = {i for i, (a, b) in enumerate(zip(self.kvm, self.osd)) if a != b}
        self.assertTrue(changed and changed <= allowed)
        self.assertEqual(len(changed), self.manifest["changed_bytes_from_base"])
        self.assertEqual(self.osd[0x13ff00:0x140000], self.kvm[0x13ff00:0x140000])
        self.assertEqual(self.osd[STUB:STUB+len(stub)], stub)
        self.assertEqual(self.osd[TIMER_HOOK:TIMER_HOOK+3], bytes((2,(timer>>8)&255,timer&255)))
        self.assertEqual(self.osd[0xf8fe:0xf900], b"\xaa\x55")
        self.assertFalse(self.manifest["ready_to_flash"])
        for data in (self.osd, self.kvm, self.sdr, self.stock[:-1], bytes(IMAGE_SIZE)):
            with self.assertRaises(ValueError):
                build(data)
        with patch("m28u_toolkit.flash_bus.open_writer") as opened:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                status = main(["writer", str(self.first), str(self.second), str(self.directory / "offline"),
                               "--osd-no-signal", str(self.osd_path)])
            report = json.loads(output.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual(report["target_name"], "osd-no-signal")
            self.assertEqual(report["target_sha256"], OSD_NO_SIGNAL_SHA256)
            self.assertFalse(report["hardware_access"] or report["flash_write_sent"] or report["osd_hardware_validated"])
            opened.assert_not_called()
        self.assertFalse((self.directory / "offline").exists())

    def test_rejects_wrong_images_and_selector_conflicts_before_open(self):
        wrong = self.directory / "wrong.bin"
        mutations = [self.stock, self.standby, self.sdr, self.kvm, self.osd[:-1]]
        for offset in (0xf8fe, 0x10ff00, STUB, HOOK, TIMER_HOOK, 0x13ff00, 0x148d90):
            data = bytearray(self.osd)
            data[offset] ^= 1
            mutations.append(bytes(data))
        with patch("m28u_toolkit.flash_bus.open_writer") as opened:
            for data in mutations:
                wrong.write_bytes(data)
                with self.subTest(sha=hashlib.sha256(data).hexdigest()), self.assertRaises(ValueError):
                    run(self.first, self.second, STOCK, self.directory / "invalid", live=True, program=True,
                        osd_no_signal=wrong)
            for other in ({"candidate": False}, {"sdr_cap540": self.sdr_path}, {"kvm_coordinated": self.kvm_path}):
                options = {"candidate": True, "osd_no_signal": self.osd_path, **other}
                with self.assertRaisesRegex(ValueError, "mutually exclusive"):
                    load_job(self.first, self.second, STOCK, **options)
            for other in (["--stock-only"], ["--sdr-cap540", str(self.sdr_path)], ["--kvm-coordinated", str(self.kvm_path)]):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                    main(["writer", "a", "b", "out", "--osd-no-signal", str(self.osd_path)] + other)
                self.assertEqual(stopped.exception.code, 2)
            opened.assert_not_called()
        self.assertFalse((self.directory / "invalid").exists())

    def test_install_and_all_supported_rollbacks(self):
        cases = [("kvm-coordinated", self.kvm, self.osd, {"osd_no_signal": self.osd_path}),
                 ("osd-no-signal", self.osd, self.kvm, {"kvm_coordinated": self.kvm_path}),
                 ("osd-no-signal", self.osd, self.sdr, {"sdr_cap540": self.sdr_path}),
                 ("osd-no-signal", self.osd, self.standby, {}),
                 ("osd-no-signal", self.osd, self.stock, {"candidate": False})]
        for backend in self.backends():
            for name, installed, target, options in cases:
                with self.subTest(backend=backend.__name__, target=hashlib.sha256(target).hexdigest()), tempfile.TemporaryDirectory() as temp:
                    with self.fixture(installed, backend) as (model, bus):
                        result = run(self.first, self.second, STOCK, Path(temp) / "job", live=True, program=True, **options)
                        self.assertEqual(result["preflight"]["installed_image"], name)
                        self.assertEqual(result["readback_sha256"], hashlib.sha256(target).hexdigest())
                        self.assertTrue(result["normal_operation_confirmed"] and result["committed"])
                        self.assertFalse(result["held_in_isp"] or bus.wp_pending)
                        self.assertEqual(model.chip.flash[0x200000:0x3b0000], target)
                        self.assertEqual(model.chip.flash[:0x200000], self.backup[:0x200000])
                        self.assertEqual(model.chip.flash[0x3b0000:], self.backup[0x3b0000:])
                        self.assertEqual(model.status, result["preflight"]["status"])
                        self.assertEqual(model.chip.indexed[0x100a], 0xb6)
                        self.assertEqual(model.chip.regs[0xe3], 0x90)
                        self.assertTrue(model.chip.reset)
                        self.assertTrue(all(value == "ffff" for value in model.marker_states[:-1]))
                        self.assertEqual(model.marker_states[-1], "aa55")

    def test_unknown_installed_osd_hybrids_refuse_and_reset(self):
        hybrids = []
        for offset, value in ((STUB, self.osd[STUB] ^ 1), (HOOK+2, self.kvm[HOOK+2]), (TIMER_HOOK, 0x90)):
            altered = bytearray(self.osd)
            altered[offset] = value
            hybrids.append(bytes(altered))
        altered = bytearray(self.osd)
        altered[0x140000:0x150000] = self.stock[0x140000:0x150000]
        hybrids.append(bytes(altered))
        for backend in self.backends():
            for installed in hybrids:
                with self.subTest(backend=backend.__name__), tempfile.TemporaryDirectory() as temp:
                    with self.fixture(installed, backend) as (model, bus):
                        before = bytes(model.chip.flash)
                        with self.assertRaises(ValueError):
                            run(self.first, self.second, STOCK, Path(temp) / "job", live=True, program=True,
                                osd_no_signal=self.osd_path)
                        self.assertFalse(bus.armed or bus.destructive or bus.wp_pending)
                        self.assertEqual(model.chip.flash, before)
                        self.assertEqual(model.chip.operations, [("reset",)])
                        report = json.loads((Path(temp) / "job/result.json").read_text())
                        self.assertTrue(report["normal_operation_confirmed"])
                        self.assertFalse(report["flash_write_attempted"] or report["held_in_isp"])
