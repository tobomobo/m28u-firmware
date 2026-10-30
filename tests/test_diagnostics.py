import contextlib
import io
import json
import unittest
from unittest.mock import patch

from m28u_toolkit.__main__ import main
from m28u_toolkit.diagnostics import boot_state
from m28u_toolkit.scaler_bus import MacBus, RegisterBus


class ObservationBus(RegisterBus):
    def __init__(self, modes=(0, 0), bank=b"\x20", version="F11"):
        super().__init__()
        self.modes, self.bank, self.version = iter(modes), bank, version
        self.events = []

    def _read(self, reg, length):
        self.events.append(("R", reg, length))
        return bytes((next(self.modes),)) if reg == 0x6F else self.bank

    def _write(self, *args):
        raise AssertionError("Boot observation must never write registers")

    def firmware(self):
        self.events.append(("V",))
        return self.version


class BootObservationTests(unittest.TestCase):
    def run_observation(self, bus, **kwargs):
        with patch("m28u_toolkit.diagnostics.live_lock", contextlib.nullcontext), \
             patch("m28u_toolkit.diagnostics.open_bus", return_value=contextlib.nullcontext(bus)):
            return boot_state(**kwargs)

    def test_exact_bounded_observation_and_no_writes(self):
        bus = ObservationBus()
        result = self.run_observation(bus)
        self.assertEqual(bus.events, [("R", 0x6F, 1), ("R", 0xFF, 1), ("R", 0x6F, 1), ("V",)])
        self.assertEqual(result["boot_bank_raw"], 32)
        self.assertEqual(result["firmware"], "F11")
        self.assertFalse(result["ready_to_flash"])
        self.assertFalse(result["isp_or_reset_sent"])

    def test_existing_isp_stops_before_bank_or_firmware_query(self):
        bus = ObservationBus(modes=(0x80,))
        with self.assertRaisesRegex(ValueError, "already in ISP"):
            self.run_observation(bus)
        self.assertEqual(bus.events, [("R", 0x6F, 1)])

    def test_external_mode_change_stops_before_ddc(self):
        bus = ObservationBus(modes=(0, 0x80))
        with self.assertRaisesRegex(ValueError, "externally"):
            self.run_observation(bus)
        self.assertNotIn(("V",), bus.events)

    def test_unusual_bank_is_observed_without_inventing_mapping(self):
        result = self.run_observation(ObservationBus(bank=b"\x34"))
        self.assertEqual(result["boot_bank_raw"], 0x34)
        self.assertFalse(result["ready_to_flash"])

    def test_separate_bank_api_requires_normal_unowned_session(self):
        bus = ObservationBus()
        for mode, attempted, entered in ((None, False, False), (0x80, False, False),
                                         (0, True, False), (0, False, True)):
            bus.mode, bus.attempted, bus.entered = mode, attempted, entered
            with self.assertRaises(ValueError):
                bus.boot_bank()
        self.assertEqual(bus.events, [])
        bus.mode, bus.attempted, bus.entered = 0, False, False
        with self.assertRaises(ValueError):
            bus.read(0xFF)
        with self.assertRaises(ValueError):
            bus.write(0xFF, 0x20)
        bus.bank = b""
        with self.assertRaisesRegex(ValueError, "Short boot-bank"):
            bus.boot_bank()

    def test_mac_uses_dedicated_native_command(self):
        bus = MacBus()
        bus.mode = 0
        with patch.object(bus, "_command", return_value="20") as command:
            self.assertEqual(bus.boot_bank(), 32)
        command.assert_called_once_with("B")

    def test_cli_stays_offline_by_default(self):
        with patch("m28u_toolkit.diagnostics.boot_state", side_effect=AssertionError("hardware access")):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["boot-state"]), 0)
            self.assertFalse(json.loads(output.getvalue())["hardware_access"])

    def test_indexed_api_has_fixed_selectors_and_no_target_writes(self):
        class IndexedBus(ObservationBus):
            def _write(self, reg, value):
                self.events.append(("W", reg, value))

            def _read(self, reg, length):
                if reg == 0xF5:
                    self.events.append(("R", reg, length))
                    return b"\x20"
                return super()._read(reg, length)

        bus = IndexedBus()
        result = self.run_observation(bus, indexed=True)
        expected = [("R", 0x6F, 1)]
        for low in (0xFC, 0xFD, 0xFF):
            expected.extend([("W", 0xF4, 0x9F), ("W", 0xF5, 0xFF),
                             ("W", 0xF4, low), ("R", 0xF5, 1)])
        expected.extend([("R", 0x6F, 1), ("V",)])
        self.assertEqual(bus.events, expected)
        self.assertEqual(result["boot_registers_raw"], {"fffc": 32, "fffd": 32, "ffff": 32})
        self.assertEqual(result["indexed_address_select_writes"], 9)
        self.assertFalse(result["ready_to_flash"])

    def test_indexed_read_requires_normal_state_and_stops_on_failure(self):
        bus = ObservationBus()
        for mode, attempted, entered in ((None, False, False), (0x80, False, False),
                                         (0, True, False), (0, False, True)):
            bus.mode, bus.attempted, bus.entered = mode, attempted, entered
            with self.assertRaises(ValueError):
                bus.boot_mapping()
        self.assertEqual(bus.events, [])
        bus.mode, bus.attempted, bus.entered = 0, False, False
        with patch.object(bus, "_write", side_effect=OSError("index transfer failed")) as write:
            with self.assertRaises(OSError):
                bus.boot_mapping()
            write.assert_called_once_with(0xF4, 0x9F)
        with patch.object(bus, "_boot_mapping", return_value=b"\0\0"):
            with self.assertRaisesRegex(ValueError, "Short boot-mapping"):
                bus.boot_mapping()

    def test_mac_indexed_observation_uses_fixed_native_command(self):
        bus = MacBus()
        bus.mode = 0
        with patch.object(bus, "_command", return_value="1f2000") as command:
            self.assertEqual(bus.boot_mapping(), {"fffc": 31, "fffd": 32, "ffff": 0})
        command.assert_called_once_with("I")

    def test_invalid_indexed_permission_refuses_before_bus_open(self):
        with patch("m28u_toolkit.diagnostics.open_bus", side_effect=AssertionError("hardware access")):
            with self.assertRaises(ValueError):
                boot_state(indexed=1)


if __name__ == "__main__":
    unittest.main()
