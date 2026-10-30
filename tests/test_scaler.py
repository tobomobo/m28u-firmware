import contextlib
import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from m28u_toolkit.__main__ import main
from m28u_toolkit.images import IMAGE_SIZE
from m28u_toolkit.scaler import SpiReader, acquire, publish_after_normal_check
from m28u_toolkit.scaler_bus import LinuxBus, MacBus, RegisterBus, READ_CONTROLS, READ_OPCODES, VENDOR_CLOCK_SEQUENCE, read_packet, write_packet
from m28u_toolkit.backup import run_backup, _open_after_reset

DATA = hashlib.shake_256(b"M28U synthetic SPI fixture; no vendor binary").digest(4*1024*1024)
STOCK = DATA[:IMAGE_SIZE]


class FakeBus(RegisterBus):
    """Independent synthetic SPI chip/register model, never a native backend."""
    def __init__(self, **faults):
        super().__init__(allow_vendor_clock=faults.pop("allow_vendor_clock",False))
        self.regs = {0x6F: 0, 0x60: 0, 0x61: 2}
        self.data = DATA
        self.id = bytes.fromhex("c2 20 16")
        self.cursor = 0
        self.stream_number = 0
        self.events = []
        self.faults = faults

    def firmware(self):
        return "F11"

    def _read(self, reg, length):
        self.events.append(("R", reg, length))
        if reg == 0x70:
            return self._stream(length)
        return bytes((self.regs.get(reg, 0),))

    def _write(self, reg, value):
        self.events.append(("W", reg, value))
        if reg == 0x61 and self.faults.get("dropped_opcode"):
            return
        if reg == 0xEE and self.faults.get("reset_failure"):
            raise OSError("Injected reset transport failure")
        if reg == 0xEE and self.faults.get("reset_interrupt"):
            raise KeyboardInterrupt()
        if reg == 0xF5 and self.faults.get("clock_failure"):
            raise OSError("Injected clock transfer failure")
        self.regs[reg] = value
        if reg == 0x6F and self.faults.get("entry_transfer_failure"):
            raise OSError("Injected host failure after device entered ISP")
        if reg == 0xEE:
            self.regs[0x6F] = self.regs[0x60] = 0
        if reg == 0x60 and value & 1:
            opcode = self.regs[0x61]
            address = sum(self.regs.get(r, 0) << shift for r, shift in ((0x64,16),(0x65,8),(0x66,0)))
            if opcode == 0x9F:
                result = self.id
            elif opcode == 5:
                result = bytes((1 if self.faults.get("flash_busy") else 0,))
            elif opcode == 3 and value == 0x47:
                self.cursor = (address + self.faults.get("stream_shift", 0)) % len(self.data)
                self.stream_number += 1
                result = b""
            elif opcode == 3:
                n = (value >> 1) & 3
                result = self.data[address:address+n]
            else:
                raise AssertionError(f"Unsafe SPI opcode reached fake chip: {opcode:#x}")
            for i, byte in enumerate(result):
                self.regs[0x67+i] = byte
            if not self.faults.get("stuck_busy"):
                self.regs[0x60] &= ~1

    def _stream(self, length):
        start = self.cursor
        result = bytes(self.data[(start+i) % len(self.data)] for i in range(length))
        self.cursor = (self.cursor+length) % len(self.data)
        # Full capture pass two follows two alignment probes and pass one.
        corrupt = 0x300456
        if self.faults.get("second_pass_corruption") and self.stream_number == 4 and start <= corrupt < start+length:
            result = bytearray(result)
            result[corrupt-start] ^= 1
            result = bytes(result)
        return result[:-1] if self.faults.get("short_stream") else result


class ReaderTests(unittest.TestCase):
    def ready(self, **faults):
        bus = FakeBus(**faults)
        reader = SpiReader(bus, clock=lambda: 0, sleep=lambda unused: None)
        reader.enter()
        reader.identify()
        return reader, bus

    def test_packet_layouts(self):
        self.assertEqual(read_packet(0x6F,1)[:11].hex(), "40d66f0000000100940180")
        self.assertEqual(read_packet(0,128,0)[:11].hex(), "40d6000000008000940080")
        self.assertEqual(write_packet(0x61,3)[64:66], bytes((0x61,3)))

    def test_vendor_clock_is_explicit_fixed_once_and_owned(self):
        bus = FakeBus()
        with self.assertRaises(ValueError): bus.configure_vendor_clock()
        reader,bus = self.ready()
        with self.assertRaises(ValueError): bus.configure_vendor_clock()
        self.assertFalse(any(e[1] in (0xF4,0xF5) for e in bus.events))
        reader.close()
        bus = FakeBus(allow_vendor_clock=True)
        reader = SpiReader(bus,clock=lambda:0,sleep=lambda unused:None)
        reader.enter()
        self.assertEqual([e[1:] for e in bus.events if e[0]=='W' and e[1] in (0xF4,0xF5)],list(VENDOR_CLOCK_SEQUENCE))
        self.assertTrue(bus.clock_configured)
        with self.assertRaises(ValueError): bus.configure_vendor_clock()
        reader.close()
        with self.assertRaises(ValueError): bus.configure_vendor_clock()

    def test_fixed_clock_sequence_matches_audited_vendor_entry(self):
        path=Path(__file__).resolve().parent.parent/'analysis/vendor-scaler-trace.json'
        if not path.exists(): self.skipTest('Optional vendor trace unavailable')
        trace=json.loads(path.read_text())['traces'][0]['events']
        self.assertEqual([(e['register'],e['value']) for e in trace if e['op']=='write' and e['register'] in (0xF4,0xF5)],list(VENDOR_CLOCK_SEQUENCE))

    def test_observed_gigadevice_geometry_uses_existing_read_commands(self):
        bus = FakeBus()
        bus.id = bytes.fromhex("c8 40 16")
        reader = SpiReader(bus, clock=lambda: 0, sleep=lambda unused: None)
        reader.enter()
        identity = reader.identify()
        self.assertEqual(identity["jedec_id"], "c84016")
        self.assertEqual(identity["main_array_bytes"], len(DATA))
        self.assertEqual(reader.read_small(0x3FFFFD), DATA[-3:])
        with self.assertRaises(ValueError):
            reader.read_small(0x3FFFFE)
        reader.close()

    def test_read_only_policy_rejects_program_erase_and_data_writes(self):
        reader, bus = self.ready()
        for value in range(256):
            if value not in READ_OPCODES:
                with self.assertRaises(ValueError):
                    bus.write(0x61,value)
            if value not in READ_CONTROLS:
                with self.assertRaises(ValueError):
                    bus.write(0x60,value)
            with self.assertRaises(ValueError):
                bus.write(0x70,value)
        for reg,value in ((0x6F,0xA0),(0xF4,0x9F),(0xF5,0x74),(0x62,6),(0xEE,0)):
            with self.assertRaises(ValueError):
                bus.write(reg,value)
        reader.close()
        self.assertEqual(bus.regs[0x6F],0)

    def test_ipc_timeout_stops_subsequent_commands(self):
        bus = MacBus()
        sink = io.BytesIO()
        bus.process = SimpleNamespace(stdin=sink)
        with patch.object(bus,"_line",side_effect=TimeoutError("injected")):
            with self.assertRaises(TimeoutError):
                bus._command("R 6f 1")
        written = sink.getvalue()
        with self.assertRaises(OSError):
            bus._command("W ee 2")
        self.assertEqual(sink.getvalue(),written)

    def test_write_ack_must_not_consume_a_late_read_reply(self):
        bus = MacBus()
        bus.process = SimpleNamespace(stdin=io.BytesIO())
        with patch.object(bus,"_line",return_value=b"OK 80"):
            with self.assertRaises(ValueError):
                bus._write(0xEE,2)
        self.assertTrue(bus.broken)

    def test_stream_and_small_reads_agree_at_boundaries(self):
        reader,bus = self.ready()
        for address in (0,256,0xA0000,len(DATA)-256):
            self.assertEqual(b"".join(reader.stream(address,256)),DATA[address:address+256])
            self.assertEqual(reader.read_small(address+253),DATA[address+253:address+256])
        for address,length in ((-1,3),(len(DATA)-1,3),(0,4)):
            with self.assertRaises(ValueError):
                reader.read_small(address,length)
        reader.close()

    def test_do_not_take_over_existing_isp_session(self):
        bus = FakeBus()
        bus.regs[0x6F] = 0x80
        reader = SpiReader(bus)
        with self.assertRaises(ValueError):
            reader.enter()
        reader.close()
        self.assertFalse(any(event[0]=="W" for event in bus.events))

    def test_trigger_checks_actual_opcode_readback(self):
        bus = FakeBus(dropped_opcode=True)
        reader = SpiReader(bus)
        reader.enter()
        with self.assertRaisesRegex(ValueError,"opcode readback"):
            reader.identify()
        self.assertFalse(any(op=="W" and reg==0x60 and value&1 for op,reg,value in bus.events))
        reader.close()

    def test_timeout_has_poll_count_bound_even_with_frozen_clock(self):
        bus = FakeBus(stuck_busy=True)
        reader = SpiReader(bus,clock=lambda:0,sleep=lambda unused:None)
        reader.enter()
        with self.assertRaises(TimeoutError):
            reader.identify()
        self.assertLess(len(bus.events),120)
        reader.close()

    def test_short_stream_invalidates_port(self):
        reader,bus = self.ready(short_stream=True)
        with self.assertRaises(ValueError):
            b"".join(reader.stream(0,128))
        self.assertFalse(bus.stream_ready)
        with self.assertRaises(ValueError):
            bus.read_stream(128)
        reader.close()

    def test_unknown_chip_and_busy_flash_refused(self):
        for busy in (False,True):
            bus = FakeBus(flash_busy=busy)
            if not busy:
                bus.id = b"\xff\xff\xff"
            reader = SpiReader(bus)
            reader.enter()
            with self.assertRaises(ValueError):
                reader.identify()
            self.assertEqual(bus.stream_number,0)
            self.assertIsNone(reader.capacity)
            reader.close()

    def test_session_deadline_does_not_prevent_cleanup(self):
        reader,bus = self.ready()
        reader.clock = lambda: 601
        with self.assertRaises(TimeoutError):
            reader.read_small(0)
        reader.close()
        self.assertEqual(bus.regs[0x6F],0)

    def test_explicit_long_deadline_retains_poll_and_range_safeguards(self):
        bus = FakeBus()
        reader = SpiReader(bus,clock=lambda:0,sleep=lambda unused:None,timeout_seconds=3600)
        reader.enter()
        reader.identify()
        reader.clock = lambda:601
        self.assertEqual(reader.read_small(0),DATA[:3])
        reader.clock = lambda:3601
        with self.assertRaises(TimeoutError):
            reader.read_small(0)
        reader.close()
        self.assertEqual(bus.regs[0x6F],0)


class AcquisitionTests(unittest.TestCase):
    def call_acquire(self, bus, destination, **kwargs):
        # Synthetic input is allowed only by this test seam. The real CLI and
        # acquire() retain exact vendor SHA-256 validation in production.
        with patch("m28u_toolkit.scaler.identify_stock",return_value=("F11",0)):
            return acquire(bus,STOCK,destination,**kwargs)

    def test_two_pass_capture_and_publish_after_normal_check(self):
        bus = FakeBus()
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)/"backup"
            report = self.call_acquire(bus,destination)
            self.assertTrue(report["captures_verified"])
            self.assertTrue(report["reset_request_sent"])
            self.assertFalse(report["complete_device_backup"])
            self.assertFalse((destination/"verified").exists())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE((destination/"pass1.partial").stat().st_mode),0o600)
            with self.assertRaises(ValueError):
                publish_after_normal_check(destination,report,"F10")
            result = publish_after_normal_check(destination,report,"F11")
            self.assertTrue(result["normal_operation_confirmed"])
            for n in (1,2):
                self.assertEqual((destination/f"verified/spi-main-array-pass{n}.bin").read_bytes(),DATA)
                self.assertFalse((destination/f"pass{n}.partial").exists())
            self.assertEqual(bus.regs[0x6F],0)

    def test_partial_clock_configuration_failure_still_resets(self):
        bus=FakeBus(allow_vendor_clock=True,clock_failure=True)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(OSError,'clock transfer'):
                self.call_acquire(bus,Path(directory)/'probe',probe_only=True)
            self.assertTrue(bus.clock_attempted)
            self.assertFalse(bus.clock_configured)
            self.assertEqual(bus.regs[0x6F],0)
            self.assertEqual(bus.events.count(('W',0xEE,2)),1)

    def test_second_slot_is_attributed_without_assuming_active_boot_slot(self):
        bus = FakeBus()
        half = len(DATA)//2
        bus.data = DATA[half:] + DATA[:half]
        with tempfile.TemporaryDirectory() as directory:
            report = self.call_acquire(bus,Path(directory)/"probe",probe_only=True)
            self.assertEqual(report["stock_reference_offsets"],[0x200000])
            self.assertFalse(report["active_boot_slot_identified"])
            self.assertTrue(report["reset_request_sent"])

    def test_mismatched_passes_stay_partial_and_reset(self):
        bus = FakeBus(second_pass_corruption=True)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)/"backup"
            with self.assertRaisesRegex(ValueError,"passes disagree"):
                self.call_acquire(bus,destination)
            self.assertFalse((destination/"verified").exists())
            self.assertTrue((destination/"pass1.partial").exists())
            self.assertTrue(json.loads((destination/"session.json").read_text())["reset_request_sent"])
            self.assertEqual(bus.regs[0x6F],0)

    def test_stream_mismatch_aborts_before_bulk_and_resets(self):
        bus = FakeBus(stream_shift=1)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)/"backup"
            with self.assertRaisesRegex(ValueError,"Streaming read"):
                self.call_acquire(bus,destination)
            self.assertFalse((destination/"pass1.partial").exists())
            self.assertEqual(bus.regs[0x6F],0)

    def test_entry_transfer_error_still_resets_owned_attempt(self):
        bus = FakeBus(entry_transfer_failure=True)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(OSError):
                self.call_acquire(bus,Path(directory)/"backup")
            self.assertEqual(bus.regs[0x6F],0)

    def test_reset_failure_prevents_success(self):
        bus = FakeBus(reset_failure=True)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)/"probe"
            with self.assertRaisesRegex(OSError,"ISP exit"):
                self.call_acquire(bus,destination,probe_only=True)
            self.assertFalse((destination/"verified").exists())
            self.assertFalse(json.loads((destination/"session.json").read_text())["reset_request_sent"])
            self.assertFalse(bus.attempted)
            self.assertEqual(bus.events.count(("W",0xEE,2)),1)

    def test_reset_interrupt_preserves_control_flow_and_owned_report(self):
        bus = FakeBus(reset_interrupt=True)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.call_acquire(bus,Path(directory)/"probe",probe_only=True)
            report = caught.exception.m28u_report
            self.assertTrue(report["isp_entry_attempted"])
            self.assertFalse(report["reset_request_sent"])
            self.assertIn("KeyboardInterrupt",report["reset_failure"])

    def test_session_save_failure_is_not_hidden_by_reset_nack(self):
        for failure in (KeyboardInterrupt(),OSError("session save failed")):
            bus = FakeBus(reset_failure=True)
            with tempfile.TemporaryDirectory() as directory, \
                 patch("m28u_toolkit.scaler._private_json",side_effect=failure):
                with self.assertRaises(type(failure)) as caught:
                    self.call_acquire(bus,Path(directory)/"probe",probe_only=True)
                self.assertIs(caught.exception,failure)
                self.assertTrue(caught.exception.m28u_report["isp_entry_attempted"])

    def test_linux_cleanup_keeps_active_report_on_repeat_reset_failure(self):
        bus = LinuxBus("/dev/fake")
        bus.fd = 123
        bus.attempted = True
        error = KeyboardInterrupt()
        error.m28u_report = {"isp_entry_attempted":True}
        with patch.object(bus,"write",side_effect=OSError("second reset failed")), \
             patch("m28u_toolkit.scaler_bus.os.close") as close:
            self.assertIsNone(bus.__exit__(KeyboardInterrupt,error,None))
        self.assertIn("second reset failed",error.m28u_report["transport_cleanup_failure"])
        self.assertIsNone(bus.fd)
        close.assert_called_once_with(123)

    def test_publish_failure_does_not_commit_half_a_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            (destination/"pass1.partial").write_bytes(b"test")
            report = {"reference_firmware":"F11","reset_request_sent":True,"captures_verified":True}
            with self.assertRaises(FileNotFoundError):
                publish_after_normal_check(destination,report,"F11")
            self.assertTrue((destination/"pass1.partial").exists())
            self.assertFalse((destination/"verified").exists())

    def test_missing_live_or_mode_flags_never_load_hardware(self):
        with patch("m28u_toolkit.backup.open_bus",side_effect=AssertionError("Hardware access")):
            cases = [(["backup","newdir","--live"],3),
                     (["backup","newdir","--enter-isp"],3),
                     (["backup","--live","--enter-isp"],3),
                     (["scaler-probe"],0)]
            for args,expected in cases:
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(args),expected)


class RunnerTests(unittest.TestCase):
    def test_invalid_timeout_refuses_before_hardware(self):
        for value in (0,29,3601,True,600.5):
            with patch("m28u_toolkit.backup.open_bus",side_effect=AssertionError("hardware")):
                with self.assertRaises(ValueError):
                    run_backup("not-read.bin","not-created",timeout_seconds=value)

    def test_acquisition_interrupt_survives_failed_final_firmware_check(self):
        output = None
        class Fresh:
            def read(self,reg): return b"\0"
            def source(self): return 3
            def firmware(self): raise OSError("firmware query failed")
        def interrupted(*args,**kwargs):
            output.mkdir()
            failure = KeyboardInterrupt()
            failure.m28u_report = {"isp_entry_attempted":True,"reference_firmware":"F11"}
            raise failure
        with tempfile.TemporaryDirectory() as directory:
            stock = Path(directory)/"stock.bin"
            stock.write_bytes(STOCK)
            output = Path(directory)/"capture"
            with patch("m28u_toolkit.backup.live_lock",side_effect=contextlib.nullcontext), \
                 patch("m28u_toolkit.backup.open_bus",side_effect=[contextlib.nullcontext(None),contextlib.nullcontext(Fresh())]), \
                 patch("m28u_toolkit.backup.identify_stock",return_value=("F11",0)), \
                 patch("m28u_toolkit.backup.time.sleep"), \
                 patch("m28u_toolkit.backup.acquire",side_effect=interrupted):
                with self.assertRaises(KeyboardInterrupt):
                    run_backup(stock,output)
            self.assertFalse((output/"verified").exists())
            self.assertIn("firmware query failed",json.loads((output/"normal-check.json").read_text())["normal_check_failure"])

    def test_reenumeration_retries_open_only_and_stops_after_connection(self):
        fresh = object()
        with patch("m28u_toolkit.backup.open_bus",side_effect=[OSError("absent"),contextlib.nullcontext(fresh)]) as opened, \
             patch("m28u_toolkit.backup.time.sleep"):
            with self.assertRaisesRegex(ValueError,"query failure"):
                with _open_after_reset(None,lambda unused:None) as bus:
                    self.assertIs(bus,fresh)
                    raise ValueError("query failure")
            self.assertEqual(opened.call_count,2)

    def test_reenumeration_wait_is_bounded_and_identity_errors_are_not_retried(self):
        for failure,count in ((OSError("absent"),16),(ValueError("wrong interface"),1)):
            with patch("m28u_toolkit.backup.open_bus",side_effect=failure) as opened, \
                 patch("m28u_toolkit.backup.time.sleep"), \
                 patch("m28u_toolkit.backup.time.monotonic",return_value=0):
                with self.assertRaises(type(failure)):
                    with _open_after_reset(None,lambda unused:None):
                        self.fail("Should not yield a bus")
                self.assertEqual(opened.call_count,count)

    def test_interrupt_is_reraised_only_after_fresh_normal_check(self):
        events = []
        class Fresh:
            def read(self,reg):
                events.append("mode")
                return b"\0"
            def source(self):
                events.append("source")
                return 3
            def firmware(self):
                events.append("firmware")
                return "F11"
        with tempfile.TemporaryDirectory() as directory:
            stock = Path(directory)/"stock.bin"
            stock.write_bytes(STOCK)
            output = Path(directory)/"capture"
            def interrupted(*args,**kwargs):
                output.mkdir()
                error = KeyboardInterrupt()
                error.m28u_report = {"isp_entry_attempted":True,"reference_firmware":"F11","reset_request_sent":True}
                raise error
            with patch("m28u_toolkit.backup.live_lock",side_effect=contextlib.nullcontext), \
                 patch("m28u_toolkit.backup.open_bus",side_effect=[contextlib.nullcontext(None),contextlib.nullcontext(Fresh())]), \
                 patch("m28u_toolkit.backup.identify_stock",return_value=("F11",0)), \
                 patch("m28u_toolkit.backup.time.sleep"), \
                 patch("m28u_toolkit.backup.acquire",side_effect=interrupted):
                with self.assertRaises(KeyboardInterrupt):
                    run_backup(stock,output)
            self.assertEqual(events,["mode","source","firmware"])
            self.assertTrue(json.loads((output/"normal-check.json").read_text())["normal_operation_confirmed"])
            self.assertFalse((output/"verified").exists())

    def test_second_interrupt_warns_if_final_mode_check_is_aborted(self):
        messages = []
        class Fresh:
            def read(self,reg):
                raise KeyboardInterrupt()
        with tempfile.TemporaryDirectory() as directory:
            stock = Path(directory)/"stock.bin"
            stock.write_bytes(STOCK)
            output = Path(directory)/"capture"
            def finished(*args,**kwargs):
                output.mkdir()
                return {"isp_entry_attempted":True,"reference_firmware":"F11","reset_request_sent":True}
            with patch("m28u_toolkit.backup.live_lock",side_effect=contextlib.nullcontext), \
                 patch("m28u_toolkit.backup.open_bus",side_effect=[contextlib.nullcontext(None),contextlib.nullcontext(Fresh())]), \
                 patch("m28u_toolkit.backup.identify_stock",return_value=("F11",0)), \
                 patch("m28u_toolkit.backup.time.sleep"), \
                 patch("m28u_toolkit.backup.acquire",side_effect=finished):
                with self.assertRaises(KeyboardInterrupt):
                    run_backup(stock,output,progress=messages.append)
            self.assertTrue(any("power-cycle" in message for message in messages))
            self.assertFalse((output/"verified").exists())

    def exercise(self, directory, *, unknown_id=False, fresh_mode=0, fresh_firmware="F11", reset_failure=False):
        bus = FakeBus(reset_failure=reset_failure)
        if unknown_id:
            bus.id = b"\xff\xff\xff"
        events = []

        class Fresh:
            def read(self, reg):
                events.append(("R",reg))
                return bytes((fresh_mode,))
            def source(self):
                events.append("source")
                return 3
            def firmware(self):
                events.append("firmware")
                return fresh_firmware

        stock_path = Path(directory)/"stock.bin"
        stock_path.write_bytes(STOCK)
        destination = Path(directory)/"capture"
        with patch("m28u_toolkit.backup.open_bus",side_effect=[contextlib.nullcontext(bus),contextlib.nullcontext(Fresh())]), \
             patch("m28u_toolkit.backup.live_lock",side_effect=contextlib.nullcontext), \
             patch("m28u_toolkit.backup.time.sleep"), \
             patch("m28u_toolkit.backup.identify_stock",return_value=("F11",0)), \
             patch("m28u_toolkit.scaler.identify_stock",return_value=("F11",0)):
            try:
                result = run_backup(stock_path,destination,probe_only=True)
                error = None
            except ValueError as failure:
                result,error = None,failure
        return result,error,events,destination,bus

    def test_fresh_mode_source_and_firmware_required_before_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            result,error,events,destination,bus = self.exercise(directory)
            self.assertIsNone(error)
            self.assertEqual(events,[("R",0x6F),"source","firmware"])
            self.assertTrue(result["normal_operation_confirmed"])
            self.assertFalse(result["captures_verified"])
            self.assertTrue((destination/"verified/result.json").is_file())

    def test_reset_nack_requires_fresh_normal_responses_before_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            result,error,events,destination,bus = self.exercise(directory,reset_failure=True)
            self.assertIsNone(error)
            self.assertFalse(result["reset_request_sent"])
            self.assertTrue(result["reset_request_attempted"])
            self.assertTrue(result["reset_confirmed_by_fresh_responses"])
            self.assertEqual(events,[("R",0x6F),"source","firmware"])
            self.assertTrue((destination/"verified/result.json").is_file())

    def test_reset_nack_does_not_hide_failed_acquisition(self):
        with tempfile.TemporaryDirectory() as directory:
            result,error,events,destination,bus = self.exercise(directory,unknown_id=True,reset_failure=True)
            self.assertIsInstance(error,ValueError)
            self.assertFalse((destination/"verified").exists())
            self.assertEqual(events,[("R",0x6F),"source","firmware"])

    def test_reset_nack_and_failed_normal_check_never_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            result,error,events,destination,bus = self.exercise(directory,reset_failure=True,fresh_mode=0x80)
            self.assertIsInstance(error,ValueError)
            self.assertFalse((destination/"verified").exists())
            self.assertEqual(events,[("R",0x6F)])

    def test_failure_still_checks_owned_session_returned_to_normal(self):
        with tempfile.TemporaryDirectory() as directory:
            result,error,events,destination,bus = self.exercise(directory,unknown_id=True)
            self.assertIsInstance(error,ValueError)
            self.assertEqual(events,[("R",0x6F),"source","firmware"])
            self.assertTrue(json.loads((destination/"normal-check.json").read_text())["normal_operation_confirmed"])
            self.assertFalse((destination/"verified").exists())
            self.assertEqual(bus.regs[0x6F],0)

    def test_still_in_isp_never_sends_ddc_or_publishes(self):
        with tempfile.TemporaryDirectory() as directory:
            result,error,events,destination,bus = self.exercise(directory,fresh_mode=0x80)
            self.assertIsInstance(error,ValueError)
            self.assertEqual(events,[("R",0x6F)])
            self.assertFalse((destination/"verified").exists())

    def test_unexpected_normal_firmware_does_not_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            result,error,events,destination,bus = self.exercise(directory,fresh_firmware="F10")
            self.assertIsInstance(error,ValueError)
            self.assertFalse((destination/"verified").exists())


if __name__ == "__main__":
    unittest.main()
