import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from m28u_toolkit.__main__ import main
from m28u_toolkit.images import IMAGE_SIZE
from m28u_toolkit.update_sim import (SyntheticScaler, SimulatedPowerLoss,
                                    UpdateSimulationError, encode_write_payload,
                                    replay_update)


class UpdateSimulationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Synthetic data, not a stock/capture fixture. Exercise all page bytes.
        cls.image = bytes(range(256)) * (IMAGE_SIZE // 256)
        image = bytearray(cls.image)
        image[0xf8fe:0xf900] = b"\xaa\x55"
        cls.image = bytes(image)

    def test_complete_image_and_boundaries(self):
        chip = SyntheticScaler(self.image)
        self.assertEqual(replay_update(chip, self.image), 0)
        self.assertEqual(chip.flash[0x200000:0x3b0000], self.image)
        self.assertEqual(chip.flash[:0x200000], chip.initial[:0x200000])
        self.assertEqual(chip.flash[0x3b0000:], chip.initial[0x3b0000:])
        self.assertEqual([x[1] // 65536 for x in chip.operations if x[0] == "erase64k"],
                         [32] + list(reversed(range(32, 59))))
        self.assertEqual([x[1] for x in chip.operations if x[0] == "status-write"], [0, 255])
        self.assertTrue(chip.reset)

    def test_erased_pages_are_skipped(self):
        image = b"\xff" * IMAGE_SIZE
        chip = SyntheticScaler(image)
        replay_update(chip, image)
        self.assertFalse(any(x[0] == "program256" for x in chip.operations))
        self.assertEqual(chip.flash[0x200000:0x3b0000], image)

    def test_read_error_stops_before_erase(self):
        chip = SyntheticScaler(self.image, "poll-read-error")
        with self.assertRaisesRegex(UpdateSimulationError, "read failed"):
            replay_update(chip, self.image)
        self.assertEqual(chip.flash, chip.initial)
        self.assertFalse(chip.reset)

    def test_program_timeout_stops_before_next_page(self):
        chip = SyntheticScaler(self.image, "program-busy")
        with self.assertRaisesRegex(UpdateSimulationError, "timed out"):
            replay_update(chip, self.image)
        self.assertEqual(sum(x[0] == "program256" for x in chip.operations), 1)
        self.assertFalse(chip.reset)

    def test_crc_mismatch_stops_before_next_bank(self):
        chip = SyntheticScaler(self.image, "crc-mismatch")
        with self.assertRaisesRegex(UpdateSimulationError, "CRC mismatch"):
            replay_update(chip, self.image)
        self.assertEqual(set(x[1] // 65536 for x in chip.operations if x[0] == "program256"), {58})
        self.assertFalse(chip.reset)

    def test_marker_can_return_before_image_is_complete(self):
        chip = SyntheticScaler(self.image, "power-cut-after-marker")
        with self.assertRaises(SimulatedPowerLoss):
            replay_update(chip, self.image)
        self.assertEqual(chip.flash[0x20f8fe:0x20f900], b"\xaa\x55")
        self.assertNotEqual(chip.flash[0x200000:0x3b0000], self.image)
        self.assertFalse(chip.marker_transitions[-1]["complete_image_matches"])

    def test_only_synthetic_bus_and_complete_bytes_accepted(self):
        for chip, firmware in [(object(), self.image), (SyntheticScaler(self.image), b"short")]:
            with self.assertRaises(ValueError):
                replay_update(chip, firmware)

    def test_fixed_packet_lengths_and_padding(self):
        payload = b"\x70" + bytes(range(64))
        packet = encode_write_payload(payload)
        self.assertEqual(len(packet), 192)
        self.assertEqual(packet[6], 65)
        self.assertEqual(packet[64:129], payload)
        self.assertEqual(packet[129:], bytes(63))
        for invalid in [b"", b"\x70", bytes(65), b"\x70" + bytes(63), bytearray(b"\xee\x02")]:
            with self.assertRaises(ValueError):
                encode_write_payload(invalid)

    def test_cli_is_offline_and_unrecognized_image_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "unrecognized.bin"
            p.write_bytes(self.image)
            with patch.dict(sys.modules, {"m28u_toolkit.transport": None, "m28u_toolkit.scaler_bus": None}), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["simulate-update", str(p)]), 2)


if __name__ == "__main__":
    unittest.main()
