import contextlib
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from m28u_toolkit.images import IMAGE_SIZE
from m28u_toolkit.writer import FlashReader, Programmer, preflight, run
from writer_model import (HardwareModel, FakeWriter, NativeFakeWriter, LinuxFakeWriter,
                          StickyCrcDoneModel, AdvancingFifoModel, StickyAdvancingFifoModel,
                          FixedRegisterReadModel)


class WriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        b = bytearray(b"\xff" * IMAGE_SIZE)
        # Non-empty pages in every bank, including pages after the marker.
        for bank in range(27):
            b[bank * 65536:bank * 65536 + 256] = bytes(range(256))
        b[0xf800:0xff00] = bytes(range(256)) * 7
        b[0xf8fe:0xf900] = b"\xaa\x55"
        cls.stock = bytes(b)
        b[0x13a79e] = 0x60;b[0x13a7a0] = 0xea
        cls.target = bytes(b)

    def fixture(self, fault=None):
        model = HardwareModel(self.stock, fault)
        bus = FakeWriter(model)
        reader, checks = preflight(bus, model.chip.initial, self.stock, clock=lambda: 0, sleep=lambda s: None)
        engine = Programmer(bus, reader, clock=lambda: 0, sleep=lambda s: None)
        return model, bus, engine, checks

    def test_complete_candidate_byte_verification_and_marker_last(self):
        model, bus, engine, checks = self.fixture()
        actual = engine.update(self.target, tuple(checks["status"]))
        self.assertEqual(actual, self.target)
        self.assertEqual(model.chip.flash[0x200000:0x3b0000], self.target)
        self.assertTrue(all(x == "ffff" for x in model.marker_states[:-1]))
        self.assertEqual(model.marker_states[-1], "aa55")
        self.assertEqual(model.chip.indexed[0x100a], 0xb6)
        self.assertEqual(model.chip.regs[0xe3], 0x90)
        self.assertEqual(model.status, checks["status"])
        self.assertTrue(bus.committed)
        self.assertFalse(model.chip.reset)
        bus.write(0xee, 2)
        self.assertTrue(model.chip.reset)

    def test_nonincrementing_register_reads_complete_update(self):
        backends = [FakeWriter, LinuxFakeWriter]
        if sys.platform == "darwin" and Path("tools/m28u_flash_macos").exists():
            backends.append(NativeFakeWriter)
        for backend in backends:
            with self.subTest(backend=backend):
                model = FixedRegisterReadModel(self.stock)
                instance = backend(model)
                context = instance if backend is NativeFakeWriter else contextlib.nullcontext(instance)
                with context as bus:
                    reader, checks = preflight(bus, model.chip.initial, self.stock)
                    self.assertEqual(checks["status"], [0xfc, 0, 0])
                    actual = Programmer(bus, reader).update(self.target, tuple(checks["status"]))
                    self.assertEqual(actual, self.target)
                    self.assertTrue(bus.committed)
                    self.assertEqual(model.status, checks["status"])
                    self.assertEqual(model.chip.indexed[0x100a], 0xb6)
                    self.assertEqual(model.chip.regs[0xe3], 0x90)
                    self.assertTrue(all(x == "ffff" for x in model.marker_states[:-1]))
                    self.assertEqual(model.marker_states[-1], "aa55")
                    bus.write(0xee, 2)

    def test_fixed_register_reads_still_refuse_ignored_address(self):
        backends = [FakeWriter, LinuxFakeWriter]
        if sys.platform == "darwin" and Path("tools/m28u_flash_macos").exists():
            backends.append(NativeFakeWriter)
        for backend in backends:
            for operation, fault in (("erase", "ignored-inrange-high"),
                                     ("page", "ignored-inrange-high"),
                                     ("page", "ignored-inrange-middle")):
                with self.subTest(backend=backend, operation=operation, fault=fault):
                    model = FixedRegisterReadModel(self.stock)
                    instance = backend(model)
                    context = instance if backend is NativeFakeWriter else contextlib.nullcontext(instance)
                    with context as bus:
                        preflight(bus, model.chip.initial, self.stock)
                        bus.arm(); bus.unlock_wp()
                        model.fault = fault
                        if backend is NativeFakeWriter:
                            # Bypass Python to retain proof of the independent guard.
                            commands = ("W 64 33", "W 65 1", "W 66 0", "W 65 2") if fault == "ignored-inrange-middle" else (
                                "W 64 20", "W 65 0", "W 66 0", "W 64 33")
                            for command in commands:
                                bus._command(command)
                            if operation == "erase":
                                bus._command("W 60 b8"); bus._command("W 61 d8")
                                command = "W 60 b9"
                            else:
                                bus._command("W 6d 2"); bus._command("W 71 ff")
                                command = "D " + bytes(64).hex()
                            with self.assertRaises(OSError): bus._command(command)
                        else:
                            engine = Programmer(bus, FlashReader(bus))
                            # Both the stale and intended addresses are in range
                            # and page-aligned; checking only 0x64 must not pass.
                            bus.write(0x64, 0x20)
                            bus.write(0x65, 1 if fault == "ignored-inrange-middle" else 0)
                            address = 0x330200 if fault == "ignored-inrange-middle" else 0x330000
                            with self.assertRaises(ValueError):
                                if operation == "erase": engine.erase(0x33)
                                else: engine.page(address, bytes(256))
                        self.assertFalse(bus.destructive)
                        self.assertEqual(model.chip.flash, model.chip.initial)
                        self.assertFalse(any(x[0] in ("erase64k", "program256", "status-write")
                                             for x in model.chip.operations))
                        bus.restore_wp(); bus.write(0xee, 2)

    def test_preflight_uses_no_write_opcode_or_gpio_change(self):
        model, bus, engine, checks = self.fixture()
        self.assertFalse(bus.armed or bus.destructive or bus.wp_pending)
        self.assertEqual(model.chip.flash, model.chip.initial)
        self.assertEqual(model.chip.operations, [])
        self.assertEqual(model.chip.indexed[0x100a], 0xb6)

    def test_preflight_accepts_exact_known_candidate_for_stock_restore(self):
        model=HardwareModel(self.stock)
        original=model.chip.initial
        model.chip.flash[0x330000:0x340000]=self.target[0x130000:0x140000]
        bus=FakeWriter(model)
        reader,checks=preflight(bus,original,self.stock,candidate_bank=self.target[0x130000:0x140000])
        self.assertEqual(checks["patch_bank_matches"],"candidate")
        self.assertFalse(bus.destructive)

    def test_ignored_address_byte_cannot_erase_factory_bank(self):
        model,bus,engine,checks=self.fixture()
        model.fault="ignored-high-address"
        with self.assertRaises(ValueError):
            engine.update(self.target,tuple(checks["status"]))
        self.assertFalse(any(x[0]=="erase64k" for x in model.chip.operations))
        self.assertEqual(model.chip.flash[:0x200000],model.chip.initial[:0x200000])

    def test_ignored_status_payload_never_triggers_nonvolatile_write(self):
        for backend in (FakeWriter,LinuxFakeWriter):
            with self.subTest(backend=backend):
                model=HardwareModel(self.stock,"ignored-status-payload")
                bus=backend(model)
                reader,checks=preflight(bus,model.chip.initial,self.stock)
                with self.assertRaises(ValueError):
                    Programmer(bus,reader).update(self.target,tuple(checks["status"]))
                self.assertFalse(bus.destructive)
                self.assertEqual(model.status,checks["status"])
                self.assertEqual(model.chip.flash,model.chip.initial)
                bus.restore_wp();bus.write(0xee,2)

    @unittest.skipUnless(sys.platform=="darwin" and Path("tools/m28u_flash_macos").exists(),"native worker build required")
    def test_native_raw_status_trigger_checks_staged_payload(self):
        model=HardwareModel(self.stock,"ignored-status-payload")
        with NativeFakeWriter(model) as bus:
            reader,checks=preflight(bus,model.chip.initial,self.stock)
            bus.arm();bus.unlock_wp()
            # Bypass the Python guard to exercise the independent native check.
            for command in ("W 60 68","W 61 1","W 64 0"):
                bus._command(command)
            with self.assertRaises(OSError):bus._command("W 60 69")
            self.assertEqual(model.status,checks["status"])
            self.assertEqual(model.chip.flash,model.chip.initial)
            bus.restore_wp();bus.write(0xee,2)

    @unittest.skipUnless(sys.platform=="darwin" and Path("tools/m28u_flash_macos").exists(),"native worker build required")
    def test_native_raw_erase_and_page_require_exact_intended_address(self):
        for operation in ("erase","page"):
            with self.subTest(operation=operation):
                model=HardwareModel(self.stock)
                with NativeFakeWriter(model) as bus:
                    preflight(bus,model.chip.initial,self.stock)
                    # The expanded preflight itself uses high byte 0x33;
                    # inject only at the destructive guard being tested.
                    model.fault="ignored-inrange-high"
                    bus.arm();bus.unlock_wp()
                    # Both addresses are in range; a range check alone is insufficient.
                    for command in ("W 64 32","W 65 0","W 66 0","W 64 33","W 66 0","W 65 0"):
                        bus._command(command)
                    if operation=="erase":
                        bus._command("W 60 b8");bus._command("W 61 d8")
                        trigger="W 60 b9"
                    else:
                        bus._command("W 6d 2");bus._command("W 71 ff")
                        with self.assertRaises(OSError):bus._command("D "+bytes(64).hex())
                        trigger="W 6f a0"
                    with self.assertRaises(OSError):bus._command(trigger)
                    self.assertFalse(any(x[0] in ("erase64k","page") for x in model.chip.operations))
                    self.assertEqual(model.chip.flash,model.chip.initial)
                    bus.restore_wp();bus.write(0xee,2)

    def test_crc_compatibility_and_advancing_fifo_complete_on_portable_backends(self):
        for model_type in (StickyCrcDoneModel,AdvancingFifoModel,StickyAdvancingFifoModel):
            for backend in (FakeWriter,LinuxFakeWriter):
                with self.subTest(model=model_type,backend=backend):
                    model=model_type(self.stock)
                    bus=backend(model)
                    reader,checks=preflight(bus,model.chip.initial,self.stock)
                    self.assertEqual(Programmer(bus,reader).update(self.target,tuple(checks["status"])),self.target)
                    self.assertTrue(bus.committed)
                    self.assertEqual(model.status,checks["status"])
                    bus.write(0xee,2)

    @unittest.skipUnless(sys.platform=="darwin" and Path("tools/m28u_flash_macos").exists(),"native worker build required")
    def test_native_compatibility_with_sticky_crc_and_advancing_fifo(self):
        for model_type in (StickyCrcDoneModel,AdvancingFifoModel,StickyAdvancingFifoModel):
            with self.subTest(model=model_type):
                model=model_type(self.stock)
                with NativeFakeWriter(model) as bus:
                    reader,checks=preflight(bus,model.chip.initial,self.stock)
                    self.assertEqual(Programmer(bus,reader).update(self.target,tuple(checks["status"])),self.target)
                    bus.write(0xee,2)

    def test_prewrite_crc_failure_stops_before_gpio_and_nonvolatile_writes(self):
        backends=[FakeWriter,LinuxFakeWriter]
        if sys.platform=="darwin" and Path("tools/m28u_flash_macos").exists():
            backends.append(NativeFakeWriter)
        for backend in backends:
            for fault in ("prewrite-crc-mismatch","second-prewrite-crc-mismatch"):
                with self.subTest(backend=backend,fault=fault):
                    model=HardwareModel(self.stock,fault)
                    instance=backend(model)
                    context=instance if backend is NativeFakeWriter else contextlib.nullcontext(instance)
                    with context as bus:
                        reader,checks=preflight(bus,model.chip.initial,self.stock)
                        with self.assertRaisesRegex(ValueError,"CRC mismatch"):
                            Programmer(bus,reader).update(self.target,tuple(checks["status"]))
                        self.assertFalse(bus.wp_pending or bus.destructive)
                        self.assertIsNone(bus.wp_saved)
                        self.assertFalse(any(x[0] in ("erase64k","program256","status-write") for x in model.chip.operations))
                        self.assertEqual(model.chip.flash,model.chip.initial)
                        bus.write(0xee,2)

    def test_page_address_write_invalidates_staged_page(self):
        for backend in (FakeWriter,LinuxFakeWriter):
            for reg in (0x64,0x65,0x66):
                with self.subTest(backend=backend,reg=reg):
                    model=HardwareModel(self.stock)
                    bus=backend(model)
                    preflight(bus,model.chip.initial,self.stock)
                    bus.arm();bus.unlock_wp()
                    for r,v in ((0x6d,2),(0x71,255),(0x64,0x20),(0x66,0),(0x65,0)):
                        bus.write(r,v)
                    for _ in range(4):bus.data(bytes(64))
                    bus.write(reg,bus.address_bytes[reg-0x64])
                    with self.assertRaises(ValueError):bus.write(0x6f,0xa0)
                    self.assertEqual(model.programmed,0)
                    bus.restore_wp();bus.write(0xee,2)

    @unittest.skipUnless(sys.platform=="darwin" and Path("tools/m28u_flash_macos").exists(),"native worker build required")
    def test_native_raw_address_write_invalidates_staged_page(self):
        for reg,value in ((0x64,0x20),(0x65,0),(0x66,0)):
            with self.subTest(reg=reg):
                model=HardwareModel(self.stock)
                with NativeFakeWriter(model) as bus:
                    preflight(bus,model.chip.initial,self.stock)
                    bus.arm();bus.unlock_wp()
                    for command in ("W 6d 2","W 71 ff","W 64 20","W 66 0","W 65 0"):
                        bus._command(command)
                    for _ in range(4):bus._command("D "+bytes(64).hex())
                    bus._command(f"W {reg:x} {value:x}")
                    with self.assertRaises(OSError):bus._command("W 6f a0")
                    self.assertEqual(model.programmed,0)
                    bus.restore_wp();bus.write(0xee,2)

    def test_verification_reads_reject_ignored_address_before_trigger(self):
        for backend in (FakeWriter,LinuxFakeWriter):
            for kind in ("small","stream"):
                with self.subTest(backend=backend,kind=kind):
                    model=HardwareModel(self.stock)
                    bus=backend(model)
                    reader,checks=preflight(bus,model.chip.initial,self.stock)
                    model.chip.flash[0x200000:0x210000]=b"\xff"*65536
                    model.chip.flash[0x20f8fe:0x20f900]=b"\xaa\x55"
                    model.chip.regs.update({0x64:0x20,0x65:0,0x66:0})
                    model.fault="ignored-read-address"
                    start=len(model.chip.events)
                    with self.assertRaisesRegex(ValueError,"Verification read address"):
                        if kind=="small":reader.read_small(0x20f8fe,2)
                        else:list(reader.stream(0x330000,128))
                    self.assertFalse(any(x[0]=="write" and x[1] in ("605d","6047") for x in model.chip.events[start:]))
                    self.assertFalse(bus.destructive)
                    bus.write(0xee,2)

    def test_crc_policy_rejects_unobserved_bits_and_busy_engine(self):
        model,bus,engine,checks=self.fixture()
        bus.arm()
        bus.read(0x6f)
        with self.assertRaises(ValueError):bus.write(0x6f,0x96)
        model.chip.regs[0x6f]=0xb0
        bus.read(0x6f)
        with self.assertRaises(ValueError):bus.write(0x6f,0xb4)
        self.assertFalse(bus.destructive)
        bus.write(0xee,2)

    @unittest.skipUnless(sys.platform=="darwin" and Path("tools/m28u_flash_macos").exists(),"native worker build required")
    def test_native_crc_policy_rejects_unobserved_bits_and_busy_engine(self):
        model=HardwareModel(self.stock)
        with NativeFakeWriter(model) as bus:
            preflight(bus,model.chip.initial,self.stock)
            bus.arm();bus._command("R 6f 10")
            with self.assertRaises(OSError):bus._command("W 6f 96")
            model.chip.regs[0x6f]=0xb0
            bus._command("R 6f 10")
            with self.assertRaises(OSError):bus._command("W 6f b4")
            bus.write(0xee,2)

    def test_reset_and_linux_cleanup_refuse_pending_gpio_even_without_flash_write(self):
        model=HardwareModel(self.stock)
        bus=LinuxFakeWriter(model)
        preflight(bus,model.chip.initial,self.stock)
        bus.arm();bus.unlock_wp()
        with self.assertRaises(ValueError):bus.write(0xee,2)
        bus.__exit__(None,None,None)
        self.assertFalse(model.chip.reset)

    def test_marker_commit_exits_read_stream_via_status_command(self):
        model,bus,engine,checks=self.fixture()
        original=engine.page
        def inspect_page(address,data):
            if address==0x20f800 and data[:254]==b"\xff"*254 and data[254:]==b"\xaa\x55":
                self.assertEqual(model.chip.regs[0x61],5)
                self.assertEqual(model.chip.regs[0x60],0x42)
            return original(address,data)
        engine.page=inspect_page
        engine.update(self.target,tuple(checks["status"]))

    def test_linux_protocol_and_bulk_packets_with_simulated_io(self):
        model=HardwareModel(self.stock)
        bus=LinuxFakeWriter(model)
        reader,checks=preflight(bus,model.chip.initial,self.stock)
        self.assertEqual(Programmer(bus,reader).update(self.target,tuple(checks["status"])),self.target)
        self.assertEqual(model.chip.indexed[0x100a],0xb6)
        self.assertEqual(model.chip.regs[0xe3],0x90)
        self.assertTrue(bus.committed)
        bus.write(0xee,2)

    def test_failed_readback_keeps_marker_invalid_and_refuses_reset(self):
        model, bus, engine, checks = self.fixture("readback-corrupt")
        with self.assertRaisesRegex(ValueError, "readback mismatch"):
            engine.update(self.target, tuple(checks["status"]))
        self.assertFalse(bus.committed)
        self.assertEqual(model.chip.flash[0x20f8fe:0x20f900], b"\xff\xff")
        with self.assertRaises(ValueError):
            bus.write(0xee, 2)

    def test_ignored_initial_erase_with_stale_crc_stops_before_other_banks(self):
        for backend in (FakeWriter,LinuxFakeWriter):
            with self.subTest(backend=backend):
                model=HardwareModel(self.stock,"ignored-marker-erase-stale-crc")
                bus=backend(model)
                reader,checks=preflight(bus,model.chip.initial,self.stock)
                with self.assertRaisesRegex(ValueError,"Boot marker did not erase"):
                    Programmer(bus,reader).update(self.target,tuple(checks["status"]))
                self.assertEqual(model.chip.flash,model.chip.initial)
                self.assertEqual(model.programmed,0)
                self.assertFalse(bus.committed or model.chip.reset)

    def test_stuck_program_has_bounded_poll_and_no_commit(self):
        model, bus, engine, checks = self.fixture("stuck-program")
        with self.assertRaises(TimeoutError):
            engine.update(self.target, tuple(checks["status"]))
        self.assertEqual(model.programmed, 1)
        self.assertFalse(bus.committed)

    def test_polling_allows_slow_completion_for_the_full_hardware_deadline(self):
        for method in ("ready","poll"):
            for completes in (True,False):
                with self.subTest(method=method,completes=completes):
                    now=[0.0]
                    def sleeping(seconds):now[0]+=seconds
                    def state(*args):
                        return bytes((int(not completes or now[0]<9.5),))
                    bus=unittest.mock.Mock()
                    reader=unittest.mock.Mock()
                    bus.read.side_effect=state
                    reader._command.side_effect=state
                    engine=Programmer(bus,reader,clock=lambda:now[0],sleep=sleeping)
                    def check():
                        if method=="ready":engine.ready()
                        else:engine.poll(0x60,1,0,seconds=10)
                    if completes:
                        check()
                        self.assertGreaterEqual(now[0],9.5)
                        self.assertLess(now[0],9.51)
                    else:
                        with self.assertRaises(TimeoutError):check()
                        self.assertGreaterEqual(now[0],10)
                        self.assertLess(now[0],10.01)

    def test_final_commit_page_is_byte_verified(self):
        model, bus, engine, checks = self.fixture("commit-corrupt")
        with self.assertRaisesRegex(ValueError, "CRC mismatch"):
            engine.update(self.target, tuple(checks["status"]))
        self.assertFalse(bus.committed or model.chip.reset)

    def test_address_and_page_guard_prevent_factory_writes(self):
        model, bus, engine, checks = self.fixture()
        before = len(model.chip.events)
        with self.assertRaises(ValueError):
            engine.erase(31)
        with self.assertRaises(ValueError):
            engine.page(0x1fff00, bytes(256))
        self.assertEqual(before, len(model.chip.events))

    def test_suspend_inversion_and_lock_status_refused(self):
        for bit in (1, 4, 0x40, 0x80):
            model = HardwareModel(self.stock)
            model.status[1] |= bit
            bus = FakeWriter(model)
            with self.assertRaises(ValueError):
                preflight(bus, model.chip.initial, self.stock, clock=lambda: 0, sleep=lambda s: None)
            self.assertFalse(bus.destructive)

    @unittest.skipUnless(sys.platform == "darwin" and Path("tools/m28u_flash_macos").exists(), "native worker build required")
    def test_actual_native_worker_policy_and_packets_without_device(self):
        model = HardwareModel(self.stock)
        with NativeFakeWriter(model) as bus:
            reader, checks = preflight(bus, model.chip.initial, self.stock)
            actual = Programmer(bus, reader).update(self.target, tuple(checks["status"]))
            self.assertEqual(actual, self.target)
            self.assertGreater(bus.native_packets, 10000)
            bus.write(0xee, 2)
        self.assertTrue(model.chip.reset)

    def run_fixture(self, temp, *, program=False, fault=None, reset_error=None, context_error=None,
                    backend=FakeWriter):
        import m28u_toolkit.flash_bus as transports
        import m28u_toolkit.scaler_bus as lock_module
        import m28u_toolkit.backup as backup_module
        model = HardwareModel(self.stock, fault)
        bus = backend(model)
        class Context:
            def __enter__(self):
                return bus.__enter__() if backend is NativeFakeWriter else bus
            def __exit__(self, *args):
                if backend is NativeFakeWriter:
                    bus.__exit__(*args)
                if context_error is not None:
                    raise context_error
                return False
        fresh = unittest.mock.Mock()
        fresh.read.return_value = b"\0"
        fresh.firmware.return_value = "F11"
        fresh.source.return_value = 3
        fresh_context = contextlib.nullcontext(fresh)
        writer = bus._write
        if reset_error is not None:
            def failing_reset(reg, value):
                writer(reg, value)
                if reg == 0xee and value == 2:
                    raise reset_error
            bus._write = failing_reset
        stack = contextlib.ExitStack()
        stack.enter_context(patch("m28u_toolkit.writer.load_job", return_value=(model.chip.initial,self.stock,self.target,{})))
        stack.enter_context(patch("m28u_toolkit.writer.make_candidate",return_value=(self.target,{})))
        stack.enter_context(patch.object(transports,"open_writer",return_value=Context()))
        stack.enter_context(patch.object(lock_module,"live_lock",return_value=contextlib.nullcontext()))
        reopen = stack.enter_context(patch.object(backup_module,"_open_after_reset",return_value=fresh_context))
        stack.enter_context(patch("m28u_toolkit.writer.time.sleep"))
        return model,bus,stack,reopen

    def test_post_setup_read_failures_reset_before_gpio_or_nonvolatile_writes(self):
        import tempfile, json
        backends = [FakeWriter, LinuxFakeWriter]
        if sys.platform == "darwin" and Path("tools/m28u_flash_macos").exists():
            backends.append(NativeFakeWriter)
        for backend in backends:
            for fault, message in (("post-setup-status", "Post-setup status"),
                                   ("post-setup-marker", "Post-setup boot marker"),
                                   ("post-setup-stream-shift", "Post-setup bank 33")):
                with self.subTest(backend=backend, fault=fault), tempfile.TemporaryDirectory() as temp:
                    model, bus, stack, reopen = self.run_fixture(temp, fault=fault, backend=backend)
                    out = Path(temp) / "job"
                    with stack, self.assertRaisesRegex(ValueError, message):
                        run("a", "b", "c", out, live=True, program=True)
                    result = json.loads((out / "result.json").read_text())
                    self.assertTrue(model.setup_applied and model.chip.reset)
                    self.assertTrue(result["normal_operation_confirmed"])
                    self.assertFalse(result["held_in_isp"] or result["flash_write_attempted"])
                    self.assertFalse(bus.wp_pending or bus.destructive or bus.committed)
                    self.assertIsNone(bus.wp_saved)
                    self.assertFalse(model.gpio_unlocked)
                    self.assertEqual(model.chip.indexed[0x100a], 0xb6)
                    self.assertEqual(model.chip.regs[0xe3], 0x90)
                    self.assertEqual(model.status, [0x1c, 2, 0])
                    self.assertFalse(any(x[0] in ("status-write", "erase64k", "program256")
                                         for x in model.chip.operations))
                    self.assertEqual(model.chip.flash, model.chip.initial)
                    self.assertEqual(model.programmed, 0)
                    reopen.assert_called_once()

    def test_post_setup_read_checks_finish_before_gpio_unlock(self):
        model, bus, engine, checks = self.fixture()
        records = []
        engine.record = lambda event, data: records.append((event, data))
        original = bus.unlock_wp
        def checked_unlock():
            self.assertFalse(bus.destructive or bus.wp_pending)
            self.assertEqual(model.chip.flash, model.chip.initial)
            self.assertEqual(model.chip.regs[0x61], 5)
            self.assertEqual(model.chip.regs[0x60], 0x42)
            self.assertEqual(records[-1][0], "post-setup-read-checks-passed")
            self.assertEqual(records[-1][1]["status"], checks["status"])
            self.assertEqual(records[-1][1]["marker"], "aa55")
            self.assertEqual(records[-1][1]["bank"], 33)
            original()
        bus.unlock_wp = checked_unlock
        self.assertEqual(engine.update(self.target, tuple(checks["status"])), self.target)
        self.assertTrue(bus.committed)
        bus.write(0xee, 2)

    def test_journal_directory_entries_are_synced_before_device_open(self):
        import tempfile
        import m28u_toolkit.writer as writer_module
        import m28u_toolkit.flash_bus as transports
        with tempfile.TemporaryDirectory() as temp:
            model,bus,stack,reopen=self.run_fixture(temp)
            out=Path(temp)/"job"
            synced=[]
            original=writer_module._sync_directory
            def sync(path):
                if path==out:
                    self.assertTrue((out/"journal.jsonl").is_file())
                    self.assertTrue((out/"job.json").is_file())
                original(path)
                synced.append(path)
            with stack,patch.object(writer_module,"_sync_directory",side_effect=sync):
                context=transports.open_writer.return_value
                def opened(*args):
                    self.assertEqual(synced,[out,out.parent])
                    return context
                transports.open_writer.side_effect=opened
                run("a","b","c",out,live=True)

    def test_directory_sync_failure_never_opens_device(self):
        import tempfile
        import m28u_toolkit.flash_bus as transports
        for failed_path in ("output","parent"):
            with self.subTest(path=failed_path),tempfile.TemporaryDirectory() as temp:
                model,bus,stack,reopen=self.run_fixture(temp)
                out=Path(temp)/"job"
                failing=out if failed_path=="output" else out.parent
                def sync(path):
                    if path==failing:
                        raise OSError("directory sync failed")
                opened=transports.open_writer
                with stack,patch("m28u_toolkit.writer._sync_directory",side_effect=sync),self.assertRaises(OSError):
                    run("a","b","c",out,live=True,program=True)
                opened.assert_not_called()
                self.assertFalse(bus.attempted)

    def test_later_cancellation_outranks_prior_device_failure(self):
        import tempfile,json
        import m28u_toolkit.writer as writer_module
        for stage in ("gpio","context","fresh","reset"):
            for cancellation in (KeyboardInterrupt,SystemExit):
                with self.subTest(stage=stage,cancellation=cancellation),tempfile.TemporaryDirectory() as temp:
                    model,bus,stack,reopen=self.run_fixture(temp,
                        context_error=cancellation() if stage=="context" else None,
                        reset_error=cancellation() if stage=="reset" else None)
                    original=writer_module.preflight
                    def failed_preflight(*args,**kwargs):
                        original(*args,**kwargs)
                        if stage=="gpio":
                            bus.arm();bus.unlock_wp()
                        raise OSError("initial device failure")
                    if stage=="gpio":
                        bus.restore_wp=unittest.mock.Mock(side_effect=cancellation())
                    if stage=="fresh":
                        reopen.side_effect=cancellation()
                    out=Path(temp)/"job"
                    with stack,patch.object(writer_module,"preflight",side_effect=failed_preflight),self.assertRaises(cancellation):
                        run("a","b","c",out,live=True)
                    result=json.loads((out/"result.json").read_text())
                    self.assertTrue(result["failure"].startswith(cancellation.__name__))
                    self.assertEqual(result["held_in_isp"],stage=="gpio")

    def test_runner_preflight_resets_and_checks_fresh_normal_mode(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            model,bus,stack,reopen = self.run_fixture(temp)
            with stack:
                result = run("a","b","c",Path(temp)/"job",live=True)
            self.assertTrue(result["normal_operation_confirmed"])
            self.assertFalse(result["flash_write_attempted"])
            self.assertTrue(model.chip.reset)
            reopen.assert_called_once()

    def test_runner_failed_update_preserves_isp_and_result(self):
        import tempfile,json
        with tempfile.TemporaryDirectory() as temp:
            model,bus,stack,reopen = self.run_fixture(temp,program=True,fault="readback-corrupt")
            out = Path(temp)/"job"
            with stack, self.assertRaises(ValueError):
                run("a","b","c",out,live=True,program=True)
            result=json.loads((out/"result.json").read_text())
            self.assertTrue(result["held_in_isp"])
            self.assertFalse(model.chip.reset)
            reopen.assert_not_called()

    def test_runner_failed_wp_cleanup_without_flash_write_preserves_isp(self):
        import tempfile,json
        with tempfile.TemporaryDirectory() as temp:
            model,bus,stack,reopen=self.run_fixture(temp)
            original=bus.unlock_wp
            def failed_unlock():
                original()
                raise OSError("WP setup readback failed")
            bus.unlock_wp=failed_unlock
            bus.restore_wp=unittest.mock.Mock(side_effect=OSError("WP restore failed"))
            out=Path(temp)/"job"
            with stack,self.assertRaises(OSError):
                run("a","b","c",out,live=True,program=True)
            result=json.loads((out/"result.json").read_text())
            self.assertTrue(result["held_in_isp"])
            self.assertFalse(result["flash_write_attempted"] or model.chip.reset)
            reopen.assert_not_called()

    @unittest.skipUnless(sys.platform=="darwin" and Path("tools/m28u_flash_macos").exists(),"native worker build required")
    def test_native_shutdown_restores_gpio_before_reset_or_holds_on_failure(self):
        import signal
        for fault in (None,"wp-restore-read-error"):
            model=HardwareModel(self.stock,fault)
            with self.assertRaises(OSError):
                with NativeFakeWriter(model) as bus:
                    preflight(bus,model.chip.initial,self.stock)
                    bus.arm();bus.unlock_wp()
                    bus.process.send_signal(signal.SIGTERM)
                    # Service synthetic HID calls made by native shutdown until EOF.
                    with self.assertRaises(OSError):bus._line()
                    bus.process.wait(timeout=3)
            self.assertEqual(model.chip.reset,fault is None)
            self.assertEqual(model.chip.indexed[0x100a],0xb6)
            self.assertEqual(model.chip.regs[0xe3],0x90)

    @unittest.skipUnless(sys.platform=="darwin" and Path("tools/m28u_flash_macos").exists(),"native worker build required")
    def test_native_raw_reset_is_refused_until_gpio_restored(self):
        model=HardwareModel(self.stock)
        with NativeFakeWriter(model) as bus:
            preflight(bus,model.chip.initial,self.stock)
            bus.arm();bus.unlock_wp()
            with self.assertRaises(OSError):bus._command("W ee 2")
            self.assertFalse(model.chip.reset)
            bus.restore_wp();bus.write(0xee,2)

    def test_runner_reset_nack_requires_fresh_normal_response(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            model,bus,stack,reopen=self.run_fixture(temp,reset_error=OSError("USB reset NACK"))
            with stack:
                result=run("a","b","c",Path(temp)/"job",live=True)
            self.assertTrue(result["normal_operation_confirmed"])
            self.assertIn("reset_transfer_error",result)

    def test_runner_cancellation_during_reset_is_preserved(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            model,bus,stack,reopen=self.run_fixture(temp,reset_error=KeyboardInterrupt())
            with stack, self.assertRaises(KeyboardInterrupt):
                run("a","b","c",Path(temp)/"job",live=True)

    def test_runner_wrong_firmware_does_not_enter_or_query_after_failure(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            model,bus,stack,reopen=self.run_fixture(temp)
            bus.firmware=lambda:"F10"
            with stack,self.assertRaises(ValueError):
                run("a","b","c",Path(temp)/"job",live=True)
            self.assertFalse(bus.attempted or model.chip.reset)
            reopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
