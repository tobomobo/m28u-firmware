import contextlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from m28u_toolkit.__main__ import main
from m28u_toolkit.images import BANK_SIZE, compare_captures, crc8, identify_stock, make_candidate, read_exact_file
from m28u_toolkit.protocol import GETS, decode_reply, get_request, readback_request, require_status_report
from m28u_toolkit.research import generic_flash_read
from m28u_toolkit.transport import descriptor_matches, linux_query

ROOT = Path(__file__).resolve().parent.parent
DESCRIPTOR = bytes.fromhex("06 da ff 09 da a1 01 15 00 26 ff 00 75 08 95 c0 09 da 81 02 09 da 91 02 c0")
FIRMWARE_REPLY = bytes.fromhex("6e 88 02 00 e0 38 ff ff 46 0b 21") + bytes(181)
HAS_VENDOR_IMAGES = all((ROOT / f"firmware/original/GIGABYTE_M28U_{v}.bin").is_file() for v in ("F10", "F11"))


class ProtocolTests(unittest.TestCase):
    def test_known_packets_and_reply(self):
        self.assertEqual(get_request("firmware")[64:70].hex(), "518301e0380b")
        self.assertEqual(get_request("brightness")[64:69].hex(), "51820110c2")
        self.assertEqual(decode_reply("firmware", FIRMWARE_REPLY).current, 0x460B)
        self.assertEqual(readback_request()[:11].hex(), "40d65100000024006e0180")

    def test_bad_replies(self):
        for position in range(11):
            for bit in range(8):
                corrupt = bytearray(FIRMWARE_REPLY)
                corrupt[position] ^= 1 << bit
                with self.assertRaises(ValueError):
                    decode_reply("firmware", corrupt)
        for length in range(11):
            with self.assertRaises(ValueError):
                decode_reply("firmware", FIRMWARE_REPLY[:length])
        corrupt = bytearray(FIRMWARE_REPLY)
        corrupt[5] ^= 1
        corrupt[10] ^= 1
        with self.assertRaises(ValueError):
            decode_reply("firmware", corrupt)

    def test_transport_rejects_dangerous_and_mutated_packets(self):
        for name in GETS:
            request = get_request(name)
            require_status_report(request)
            for position in range(len(request)):
                altered = bytearray(request)
                altered[position] ^= 1
                with self.assertRaises(ValueError):
                    require_status_report(bytes(altered))
        for packet in (generic_flash_read(0, 128), bytes.fromhex("40 c8")+bytes(190),
                       bytes.fromhex("40 c9")+bytes(190)):
            with self.assertRaises(ValueError):
                require_status_report(packet)

    def test_generic_read_bounds(self):
        self.assertEqual(generic_flash_read(0x12345678, 128)[:8].hex(), "c0d8785634128000")
        for address, length in ((-1, 1), (2**32, 1), (0, 0), (0, 129), (2**32-1, 2)):
            with self.assertRaises(ValueError):
                generic_flash_read(address, length)


class ImageTests(unittest.TestCase):
    @unittest.skipUnless(HAS_VENDOR_IMAGES, "Optional integration check requires official F10/F11 downloads")
    def test_candidates_and_stock_rejection(self):
        for version in ("F10", "F11"):
            original = (ROOT / f"firmware/original/GIGABYTE_M28U_{version}.bin").read_bytes()
            candidate, report = make_candidate(original)
            self.assertEqual(len(candidate), len(original))
            self.assertEqual(sum(a != b for a, b in zip(original, candidate)), 2)
            self.assertEqual(report["changed_banks"], [19])
            self.assertFalse(report["ready_to_flash"])
            for invalid in (original[:-1], candidate, bytes(len(original))):
                with self.assertRaises(ValueError):
                    identify_stock(invalid)

    def test_crc_reference_vectors(self):
        self.assertEqual(crc8(bytes(BANK_SIZE)), 0)
        self.assertEqual(crc8(bytes(range(256))*256), 0x17)
        self.assertEqual(crc8(b"123456789"), 0xF4)

    def test_repeated_capture_failures_and_limits(self):
        capture = bytes(range(256))*8
        report = compare_captures(capture, capture, len(capture))
        self.assertFalse(report["complete_device_backup"])
        changed = bytearray(capture)
        changed[100] ^= 1
        for a, b, n in ((capture, changed, len(capture)), (capture, capture[:-1], len(capture)),
                        (capture, capture, 0), (bytes(256), bytes(256), 256)):
            with self.assertRaises(ValueError):
                compare_captures(a, b, n)

    def test_bounded_file_loading(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "capture.bin"
            path.write_bytes(bytes(range(256)))
            self.assertEqual(read_exact_file(path, 256), path.read_bytes())
            for size in (0, -1, 255, 257, 32*1024*1024+1):
                with self.assertRaises(ValueError):
                    read_exact_file(path, size)
            fifo = Path(temporary) / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                read_exact_file(fifo, 256)
        with self.assertRaises(ValueError):
            read_exact_file("/dev/zero", 256)


class LinuxTransportTests(unittest.TestCase):
    def test_descriptor_rejections(self):
        self.assertTrue(descriptor_matches(DESCRIPTOR))
        for invalid in (DESCRIPTOR[:-1], DESCRIPTOR+DESCRIPTOR,
                        DESCRIPTOR.replace(bytes.fromhex("06 da ff"), bytes.fromhex("06 db ff")),
                        DESCRIPTOR.replace(b"\x95\xc0", b"\x95\xbf"),
                        DESCRIPTOR[:7] + b"\x85\x01" + DESCRIPTOR[7:]):
            self.assertFalse(descriptor_matches(invalid))

    def fake_query(self, *, wrong_vid=False, short_send=False, short_reply=False, bad_descriptor=False):
        import fcntl
        import stat
        sent = []

        def ioctl(fd, request, buf, mutate):
            number = request & 255
            if number == 3:
                buf[:] = struct.pack("=IHH", 3, 0 if wrong_vid else 0xBDA, 0x1100)
            elif number == 1:
                buf[:] = struct.pack("=I", len(DESCRIPTOR))
            elif number == 2:
                buf[4:4+len(DESCRIPTOR)] = DESCRIPTOR if not bad_descriptor else bytes(len(DESCRIPTOR))
            elif number == 0x0B:
                sent.append(bytes(buf))
                return 192 if short_send else 193
            elif number == 0x0A:
                buf[:] = b"\0" + FIRMWARE_REPLY
                return 192 if short_reply else 193
            return 0

        with patch("m28u_toolkit.transport.platform.machine", return_value="x86_64"), \
             patch("m28u_toolkit.transport.os.open", return_value=7), \
             patch("m28u_toolkit.transport.os.fstat") as fstat, \
             patch("m28u_toolkit.transport.os.close") as close, \
             patch("m28u_toolkit.transport.time.sleep"), \
             patch.object(fcntl, "flock"), patch.object(fcntl, "ioctl", side_effect=ioctl):
            fstat.return_value.st_mode = stat.S_IFCHR
            try:
                result = linux_query("firmware", "/dev/hidraw4")
            except ValueError:
                result = None
            close.assert_called_once_with(7)
        return result, sent

    def test_one_bounded_get(self):
        result, sent = self.fake_query()
        self.assertEqual(result.current, 0x460B)
        self.assertEqual(sent, [b"\0"+get_request("firmware"), b"\0"+readback_request()])

    def test_stop_before_output_for_identity_failure(self):
        for flags in ({"wrong_vid": True}, {"bad_descriptor": True}):
            result, sent = self.fake_query(**flags)
            self.assertIsNone(result)
            self.assertEqual(sent, [])

    def test_short_transfers_stop_without_retry(self):
        result, sent = self.fake_query(short_send=True)
        self.assertIsNone(result)
        self.assertEqual(len(sent), 1)
        result, sent = self.fake_query(short_reply=True)
        self.assertIsNone(result)
        self.assertEqual(len(sent), 2)


class CliTests(unittest.TestCase):
    def test_offline_and_blocked_commands_never_load_transport(self):
        with patch("m28u_toolkit.transport.status", side_effect=AssertionError("Unexpected hardware access")):
            for args, expected in ((["status", "firmware"], 0), (["readiness"], 0),
                                   (["backup"], 3), (["flash"], 3), (["packet", "firmware"], 0)):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main(args), expected)
                self.assertFalse(json.loads(output.getvalue())["hardware_access"])

    @unittest.skipUnless(HAS_VENDOR_IMAGES, "Optional integration check requires official F10/F11 downloads")
    def test_candidate_refuses_overwrite(self):
        original = ROOT / "firmware/original/GIGABYTE_M28U_F11.bin"
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)/"candidate"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["candidate", str(original), str(destination)]), 0)
            image = destination/"M28U-standby-UNVALIDATED.candidate.bin"
            before = image.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["candidate", str(original), str(destination)]), 2)
            self.assertEqual(image.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
