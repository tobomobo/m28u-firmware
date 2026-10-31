"""Exact coordinated target, installed identity and complete rollback replays."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from m28u_toolkit.__main__ import main
from m28u_toolkit.images import (KVM_COORDINATED_SHA256,
                                 KVM_COORDINATED_BANK19_SHA256,
                                 read_kvm_coordinated)
from m28u_toolkit.writer import load_job, run
import test_sdr_writer as sdr_tests

STOCK = sdr_tests.STOCK
from tools.build_kvm_experiment import build, build_coordinated


@unittest.skipUnless(STOCK.is_file(), "Requires public pinned F11")
class KvmWriterTests(unittest.TestCase):
    # Reuse the same synthetic transport/reset fixture as the proven SDR lane.
    fixture = sdr_tests.SdrWriterTests.fixture
    backends = sdr_tests.SdrWriterTests.backends

    @classmethod
    def setUpClass(cls):
        sdr_tests.SdrWriterTests.setUpClass.__func__(cls)
        cls.kvm = build_coordinated(cls.stock)[0]
        cls.old_kvm = build(cls.stock)[0]
        cls.kvm_path = cls.directory / "coordinated.bin"
        cls.kvm_path.write_bytes(cls.kvm)

    def test_exact_rebuilt_target_and_offline_cli(self):
        self.assertEqual(hashlib.sha256(self.kvm).hexdigest(), KVM_COORDINATED_SHA256)
        self.assertEqual(hashlib.sha256(self.kvm[0x130000:0x140000]).hexdigest(),
                         KVM_COORDINATED_BANK19_SHA256)
        self.assertEqual(read_kvm_coordinated(self.kvm_path, self.stock), self.kvm)
        with patch("m28u_toolkit.flash_bus.open_writer") as opened:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = main(["writer", str(self.first), str(self.second),
                             str(self.directory / "offline"),
                             "--kvm-coordinated", str(self.kvm_path)])
            report = json.loads(output.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(report["target_name"], "kvm-coordinated")
            self.assertEqual(report["target_sha256"], KVM_COORDINATED_SHA256)
            self.assertFalse(report["hardware_access"] or report["flash_write_sent"])
            opened.assert_not_called()
            self.assertFalse((self.directory / "offline").exists())

    def test_wrong_target_and_selector_conflicts_refuse_without_open(self):
        wrong = self.directory / "wrong.bin"
        mutations = [self.stock, self.standby, self.sdr, self.old_kvm, self.kvm[:-1]]
        for offset in (0xf8fe, 0x10ff00, 0x138c9c, 0x13a79e, 0x13ff00, 0x148d90):
            data = bytearray(self.kvm)
            data[offset] ^= 1
            mutations.append(bytes(data))
        with patch("m28u_toolkit.flash_bus.open_writer") as opened:
            for data in mutations:
                wrong.write_bytes(data)
                with self.subTest(sha=hashlib.sha256(data).hexdigest()), self.assertRaises(ValueError):
                    run(self.first, self.second, STOCK, self.directory / "invalid",
                        live=True, program=True, kvm_coordinated=wrong)
            for candidate, sdr in ((False, None), (True, self.sdr_path)):
                with self.assertRaisesRegex(ValueError, "mutually exclusive"):
                    load_job(self.first, self.second, STOCK, candidate,
                             sdr_cap540=sdr, kvm_coordinated=self.kvm_path)
            for other in (["--stock-only"], ["--sdr-cap540", str(self.sdr_path)]):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                    main(["writer", "a", "b", "out", "--kvm-coordinated", str(self.kvm_path)] + other)
                self.assertEqual(stopped.exception.code, 2)
            opened.assert_not_called()
        self.assertFalse((self.directory / "invalid").exists())

    def test_full_install_and_all_rollbacks(self):
        cases = [("sdr-cap540", self.sdr, self.kvm, {"kvm_coordinated": self.kvm_path}),
                 ("kvm-coordinated", self.kvm, self.sdr, {"sdr_cap540": self.sdr_path}),
                 ("kvm-coordinated", self.kvm, self.standby, {}),
                 ("kvm-coordinated", self.kvm, self.stock, {"candidate": False})]
        for backend in self.backends():
            for name, installed, target, options in cases:
                with self.subTest(backend=backend.__name__, target=hashlib.sha256(target).hexdigest()), tempfile.TemporaryDirectory() as temp:
                    with self.fixture(installed, backend) as (model, bus):
                        result = run(self.first, self.second, STOCK, Path(temp) / "job",
                                     live=True, program=True, **options)
                        self.assertEqual(result["preflight"]["installed_image"], name)
                        self.assertTrue(result["preflight"]["legacy_kvm_bank16_exact"])
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

    def test_unknown_hybrids_and_superseded_bank16_refuse_then_reset(self):
        stock_sdr_bank = bytearray(self.kvm)
        stock_sdr_bank[0x140000:0x150000] = self.stock[0x140000:0x150000]
        changed_stub = bytearray(self.kvm)
        changed_stub[0x13ff10] ^= 1
        both_stubs = bytearray(self.kvm)
        both_stubs[0x100000:0x110000] = self.old_kvm[0x100000:0x110000]
        for backend in self.backends():
            for installed in (self.old_kvm, bytes(stock_sdr_bank), bytes(changed_stub), bytes(both_stubs)):
                with self.subTest(backend=backend.__name__), tempfile.TemporaryDirectory() as temp:
                    with self.fixture(installed, backend) as (model, bus):
                        before = bytes(model.chip.flash)
                        with self.assertRaises(ValueError):
                            run(self.first, self.second, STOCK, Path(temp) / "job",
                                live=True, program=True, kvm_coordinated=self.kvm_path)
                        self.assertFalse(bus.armed or bus.destructive or bus.wp_pending)
                        self.assertEqual(model.chip.flash, before)
                        self.assertEqual(model.chip.operations, [("reset",)])
                        report = json.loads((Path(temp) / "job/result.json").read_text())
                        self.assertTrue(report["normal_operation_confirmed"])
                        self.assertFalse(report["flash_write_attempted"] or report["held_in_isp"])
