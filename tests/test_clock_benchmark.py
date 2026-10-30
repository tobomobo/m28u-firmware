import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_scaler import FakeBus, STOCK
from tools.benchmark_isp_clock import compare, main


class ClockBenchmarkTests(unittest.TestCase):
    def compare(self,bus,output):
        clock=iter((0,2,3,5,6,7,8,9)).__next__
        with patch('tools.benchmark_isp_clock.identify_stock',return_value=('F11',0)):
            return compare(bus,STOCK,output,clock=clock)

    def test_same_session_same_bytes_before_after_and_one_reset(self):
        class Tracked(FakeBus):
            def configure_vendor_clock(self):
                self.streams_before_clock=self.stream_number
                super().configure_vendor_clock()
        bus=Tracked(allow_vendor_clock=True)
        with tempfile.TemporaryDirectory() as d:
            report=self.compare(bus,Path(d)/'probe')
            self.assertEqual(report['speed_ratio'],2)
            self.assertEqual(report['before']['bytes'],8192)
            self.assertEqual(report['after']['bytes'],8192)
            self.assertEqual(bus.streams_before_clock,2)
            self.assertEqual(bus.stream_number,4)
            self.assertEqual(bus.events.count(('W',0x6F,0x80)),1)
            self.assertEqual(bus.events.count(('W',0xEE,2)),1)
            self.assertFalse(report['normal_operation_confirmed'])
            self.assertFalse(report['ready_to_flash'])
            self.assertTrue(report['reset_acknowledged'])

    def test_post_clock_corruption_fails_and_resets(self):
        class Corrupt(FakeBus):
            def _vendor_clock(self):
                super()._vendor_clock()
                data=bytearray(self.data)
                data[20]^=1
                self.data=bytes(data)
        bus=Corrupt(allow_vendor_clock=True)
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/'probe'
            with self.assertRaisesRegex(ValueError,'differ from known stock'):
                self.compare(bus,output)
            self.assertEqual(bus.regs[0x6F],0)
            report=json.loads((output/'comparison.json').read_text())
            self.assertNotIn('speed_ratio',report)
            self.assertIn('failure',report)

    def test_clock_transfer_failure_resets_without_repeating_configuration(self):
        bus=FakeBus(allow_vendor_clock=True,clock_failure=True)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(OSError):
                self.compare(bus,Path(d)/'probe')
            self.assertEqual(bus.regs[0x6F],0)
            self.assertEqual(bus.events.count(('W',0xF4,0x9F)),1)
            self.assertEqual(bus.events.count(('W',0xEE,2)),1)

    def test_reset_failure_preserves_measurements_but_raises(self):
        bus=FakeBus(allow_vendor_clock=True,reset_failure=True)
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/'probe'
            with self.assertRaisesRegex(OSError,'reset transport'):
                self.compare(bus,output)
            report=json.loads((output/'comparison.json').read_text())
            self.assertEqual(report['speed_ratio'],2)
            self.assertFalse(report['reset_acknowledged'])
            self.assertFalse(report['normal_operation_confirmed'])

    def test_reset_interrupt_is_preserved_after_report_is_saved(self):
        bus=FakeBus(allow_vendor_clock=True,reset_interrupt=True)
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/'probe'
            with self.assertRaises(KeyboardInterrupt):
                self.compare(bus,output)
            report=json.loads((output/'comparison.json').read_text())
            self.assertEqual(report['speed_ratio'],2)
            self.assertIn('KeyboardInterrupt',report['reset_failure'])

    def test_missing_flags_never_open_hardware(self):
        for flags in ([],['--live'],['--live','--enter-isp'],['--enter-isp','--vendor-isp-clock']):
            with patch('tools.benchmark_isp_clock.open_bus',side_effect=AssertionError('hardware')),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['new-output']+flags),3)

    def test_existing_isp_is_not_taken_over(self):
        bus=FakeBus(allow_vendor_clock=True)
        bus.regs[0x6F]=0x80
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'Existing ISP'):
                self.compare(bus,Path(d)/'probe')
        self.assertFalse(any(e[0]=='W' for e in bus.events))
