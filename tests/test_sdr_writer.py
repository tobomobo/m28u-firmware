"""Pinned target and real runner acceptance with synthetic USB/SPI only."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from m28u_toolkit.__main__ import main
from m28u_toolkit.images import (IMAGE_SIZE, SDR_CAP540_SHA256,
                                 SDR_CAP540_BANK20_SHA256, make_candidate,
                                 read_sdr_cap540)
from m28u_toolkit.writer import load_job, run
from tools.build_sdr_experiment import build
from writer_model import (FixedRegisterReadModel, FakeWriter, LinuxFakeWriter,
                          NativeFakeWriter)

ROOT = Path(__file__).resolve().parents[1]
STOCK = ROOT / "firmware/original/GIGABYTE_M28U_F11.bin"


@unittest.skipUnless(STOCK.is_file(), "Requires the public pinned F11 reference")
class SdrWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="m28u-sdr-test-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.stock = STOCK.read_bytes()
        cls.standby = make_candidate(cls.stock)[0]
        cls.sdr = build(cls.stock)[0]
        cls.sdr_path = cls.directory / "pinned-sdr.bin"
        cls.sdr_path.write_bytes(cls.sdr)
        cls.backup = FixedRegisterReadModel(cls.stock).chip.initial
        cls.first, cls.second = (cls.directory / name for name in ("first.bin", "second.bin"))
        cls.first.write_bytes(cls.backup)
        cls.second.write_bytes(cls.backup)

    def job(self, **kwargs):
        return load_job(self.first, self.second, STOCK, True, **kwargs)

    def test_rebuild_and_pins_and_offline_selector(self):
        self.assertEqual(hashlib.sha256(self.sdr).hexdigest(), SDR_CAP540_SHA256)
        self.assertEqual(hashlib.sha256(self.sdr[0x140000:0x150000]).hexdigest(),
                         SDR_CAP540_BANK20_SHA256)
        self.assertEqual(read_sdr_cap540(self.sdr_path, self.stock), self.sdr)
        _, _, target, job = self.job(sdr_cap540=self.sdr_path)
        self.assertEqual(target, self.sdr)
        self.assertEqual(job["target_name"], "sdr-cap540")
        with patch("m28u_toolkit.flash_bus.open_writer") as opened:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                status = main(["writer", str(self.first), str(self.second),
                               str(self.directory / "never-created"), "--sdr-cap540", str(self.sdr_path)])
            report = json.loads(output.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual(report["target_sha256"], SDR_CAP540_SHA256)
            self.assertFalse(report["hardware_access"] or report["flash_write_sent"])
            opened.assert_not_called()
            self.assertFalse((self.directory / "never-created").exists())

    def test_bad_targets_and_conflicts_refuse_before_device_open(self):
        invalid = self.directory / "invalid.bin"
        mutations = [self.stock, self.standby, self.sdr[:-1], bytes(IMAGE_SIZE)]
        for offset in (0xf8fe, 0x13a79e, 0x148d90, 0x14c000, 0x1affff):
            data = bytearray(self.sdr)
            data[offset] ^= 1
            mutations.append(bytes(data))
        with patch("m28u_toolkit.flash_bus.open_writer") as opened:
            for data in mutations:
                invalid.write_bytes(data)
                with self.subTest(sha=hashlib.sha256(data).hexdigest()), self.assertRaises(ValueError):
                    run(self.first, self.second, STOCK, self.directory / "invalid-output",
                        live=True, program=True, sdr_cap540=invalid)
            with self.assertRaisesRegex(ValueError, "mutually exclusive"):
                load_job(self.first, self.second, STOCK, False, sdr_cap540=self.sdr_path)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                main(["writer", "a", "b", "out", "--stock-only", "--sdr-cap540", str(self.sdr_path)])
            self.assertEqual(stopped.exception.code, 2)
            opened.assert_not_called()
        self.assertFalse((self.directory / "invalid-output").exists())

    @contextlib.contextmanager
    def fixture(self, installed, backend):
        model = FixedRegisterReadModel(self.stock)
        model.chip.flash[0x200000:0x3b0000] = installed
        instance = backend(model)
        bus_context = instance if backend is NativeFakeWriter else contextlib.nullcontext(instance)
        fresh = Mock()
        fresh.read.return_value = b"\0"
        fresh.firmware.return_value = "F11"
        fresh.source.return_value = 3
        with contextlib.ExitStack() as stack:
            bus = stack.enter_context(bus_context)
            stack.enter_context(patch("m28u_toolkit.flash_bus.open_writer", return_value=contextlib.nullcontext(bus)))
            stack.enter_context(patch("m28u_toolkit.scaler_bus.live_lock", return_value=contextlib.nullcontext()))
            stack.enter_context(patch("m28u_toolkit.backup._open_after_reset", return_value=contextlib.nullcontext(fresh)))
            stack.enter_context(patch("m28u_toolkit.writer.time.sleep"))
            yield model, bus

    def backends(self):
        yield FakeWriter
        yield LinuxFakeWriter
        if sys.platform == "darwin" and (ROOT / "tools/m28u_flash_macos").is_file():
            yield NativeFakeWriter  # worker_args forces --stdio-writer-dry-run.

    def test_supported_runner_sdr_update_and_standby_rollback(self):
        for backend in self.backends():
            for rollback in (False, True):
                installed, expected = (self.sdr, self.standby) if rollback else (self.standby, self.sdr)
                with self.subTest(backend=backend.__name__, rollback=rollback), tempfile.TemporaryDirectory() as temp:
                    with self.fixture(installed, backend) as (model, bus):
                        result = run(self.first, self.second, STOCK, Path(temp) / "job",
                                     live=True, program=True,
                                     sdr_cap540=None if rollback else self.sdr_path)
                        self.assertEqual(result["preflight"]["installed_image"], "sdr-cap540" if rollback else "standby")
                        self.assertEqual(result["job"]["target_name"], "standby" if rollback else "sdr-cap540")
                        self.assertEqual(result["readback_sha256"], hashlib.sha256(expected).hexdigest())
                        self.assertTrue(result["normal_operation_confirmed"] and result["committed"])
                        self.assertFalse(result["held_in_isp"] or bus.wp_pending)
                        self.assertEqual(model.chip.flash[0x200000:0x3b0000], expected)
                        self.assertEqual(model.chip.flash[:0x200000], self.backup[:0x200000])
                        self.assertEqual(model.chip.flash[0x3b0000:], self.backup[0x3b0000:])
                        self.assertEqual(model.status, result["preflight"]["status"])
                        self.assertEqual(model.chip.indexed[0x100a], 0xb6)
                        self.assertEqual(model.chip.regs[0xe3], 0x90)
                        self.assertTrue(model.chip.reset)
                        self.assertTrue(all(value == "ffff" for value in model.marker_states[:-1]))
                        self.assertEqual(model.marker_states[-1], "aa55")

    def test_preflight_refuses_unknown_bank_and_hybrid_then_resets(self):
        altered = bytearray(self.standby)
        altered[0x145678] ^= 1  # Outside all ten old sample points.
        hybrid = bytearray(self.sdr)
        hybrid[0x130000:0x140000] = self.stock[0x130000:0x140000]
        for backend in self.backends():
            for installed in (bytes(altered), bytes(hybrid)):
                with self.subTest(backend=backend.__name__), tempfile.TemporaryDirectory() as temp:
                    out = Path(temp) / "refused"
                    with self.fixture(installed, backend) as (model, bus):
                        before = bytes(model.chip.flash)
                        with self.assertRaisesRegex(ValueError, "not a recognized"):
                            run(self.first, self.second, STOCK, out, live=True, program=True,
                                sdr_cap540=self.sdr_path)
                        self.assertFalse(bus.armed or bus.destructive or bus.wp_pending)
                        self.assertEqual(model.chip.flash, before)
                        self.assertEqual(model.chip.operations, [("reset",)])
                        self.assertTrue(model.chip.reset)
                        result = json.loads((out / "result.json").read_text())
                        self.assertTrue(result["normal_operation_confirmed"])
                        self.assertFalse(result["flash_write_attempted"] or result["held_in_isp"])


if __name__ == "__main__":
    unittest.main()
