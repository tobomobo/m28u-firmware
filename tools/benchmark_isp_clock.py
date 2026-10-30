"""Experimental fixed vendor-clock comparison. Default invocation is offline.

Same owned ISP session, same two 4-KiB reference windows before/after one fixed
clock sequence, then one reset request. Never a backup or flash readiness check.
"""
import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from m28u_toolkit.images import identify_stock, read_exact_file, IMAGE_SIZE
from m28u_toolkit.scaler import SpiReader, REFERENCE_BASES, _private_json
from m28u_toolkit.scaler_bus import open_bus, live_lock


def measure(reader, base, stock, clock):
    windows = []
    for offset in (0, 0xA0000):
        started = clock()
        data = b"".join(reader.stream(base+offset, 4096))
        elapsed = clock()-started
        if data != stock[offset:offset+4096]:
            raise ValueError("Benchmark bytes differ from known stock; stop comparison")
        if elapsed <= 0:
            raise ValueError("Invalid benchmark clock interval")
        windows.append({"address": base+offset, "bytes": len(data), "elapsed_seconds": elapsed})
    elapsed = sum(w["elapsed_seconds"] for w in windows)
    return {"windows": windows, "bytes": 8192, "elapsed_seconds": elapsed,
            "kib_per_second": 8/elapsed, "stock_bytes_matched": True}


def compare(bus, stock, output, *, clock=time.monotonic):
    version, _ = identify_stock(stock)
    output = Path(output)
    output.mkdir(mode=0o700)
    reader = SpiReader(bus, timeout_seconds=60)
    report = {"ready_to_flash": False, "complete_device_backup": False,
              "normal_operation_confirmed": False, "reference_firmware": version,
              "kind": "Fixed vendor ISP clock timing comparison", "spi_program_or_erase_sent": False}
    primary_error = None
    try:
        if not bus.allow_vendor_clock:
            raise ValueError("Clock comparison requires explicit vendor-clock permission")
        if bus.read(0x6F)[0] & 0x80:
            raise ValueError("Existing ISP session; refusing takeover")
        if bus.firmware() != version:
            raise ValueError("Installed firmware label differs from stock reference")
        reader.enter(configure_clock=False)
        report.update(reader.identify())
        anchors = (0, 0x10000, 0xA9E80, 0x13A700, len(stock)-3)
        bases = [base for base in REFERENCE_BASES if base+len(stock) <= reader.capacity and all(
            reader.read_small(base+offset) == stock[offset:offset+3] for offset in anchors)]
        if not bases:
            raise ValueError("No stock reference anchors; no clock change")
        base = bases[0]
        report["reference_base"] = base
        report["active_boot_slot_identified"] = False
        report["before"] = measure(reader, base, stock, clock)
        bus.configure_vendor_clock()
        if reader.identify()["jedec_id"] != report["jedec_id"]:
            raise ValueError("Chip identity changed after clock configuration")
        report["after"] = measure(reader, base, stock, clock)
        report["speed_ratio"] = report["after"]["kib_per_second"]/report["before"]["kib_per_second"]
        return report
    except BaseException as error:
        primary_error = error
        report["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        report["isp_entry_attempted"] = bus.attempted
        report["vendor_clock_attempted"] = bus.clock_attempted
        report["vendor_clock_configured"] = bus.clock_configured
        try:
            report["reset_request_attempted"] = bus.attempted
            reader.close()
            report["reset_acknowledged"] = report["reset_request_attempted"]
        except BaseException as error:
            report["reset_acknowledged"] = False
            report["reset_failure"] = f"{type(error).__name__}: {error}"
            if primary_error is None or (isinstance(primary_error, Exception) and not isinstance(error, Exception)):
                primary_error = error
        try:
            _private_json(output/"comparison.json", report)
        except BaseException as error:
            if primary_error is not None and not isinstance(primary_error, Exception):
                raise primary_error from error
            raise
        if primary_error is not None:
            raise primary_error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--stock", type=Path, default=ROOT/"firmware/original/GIGABYTE_M28U_F11.bin")
    parser.add_argument("--device")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--enter-isp", action="store_true")
    parser.add_argument("--vendor-isp-clock", action="store_true")
    args = parser.parse_args(argv)
    if not (args.output and args.live and args.enter_isp and args.vendor_isp_clock):
        print(json.dumps({"hardware_access": False, "message": "Requires NEW_OUTPUT --live --enter-isp --vendor-isp-clock. Temporary display/KVM interruption; fixed volatile clock configuration; no flash program/erase."}))
        return 3
    try:
        stock = read_exact_file(args.stock, IMAGE_SIZE)
        identify_stock(stock)
        if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
            raise ValueError("Output must be a fresh directory under an existing parent")
        with live_lock(), open_bus(args.device, allow_vendor_clock=True) as bus:
            report = compare(bus, stock, args.output)
        print(json.dumps(report, indent=2))
        print("Normal return is not verified by this diagnostic. Confirm picture/KVM and a fresh normal firmware response before more work.", file=sys.stderr)
        return 0
    except KeyboardInterrupt:
        print("Interrupted; reset cleanup attempted. If needed, power-cycle monitor manually. No flash erase/program sent.", file=sys.stderr)
        return 130
    except (ValueError, OSError) as error:
        print(f"Stopped: {error}. If the monitor stays blank, power-cycle it manually. No flash erase/program sent.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
