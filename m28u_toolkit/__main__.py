"""python3 -m m28u_toolkit --help"""
import argparse
import json
from pathlib import Path
import sys

from .images import IMAGE_SIZE, compare_captures, exclusive_write, image_report, make_candidate, read_exact_file
from .protocol import GETS, get_request, readback_request


def emit(value):
    print(json.dumps(value, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description="M28U firmware research. Writer defaults offline; explicit live/program flags are required.")
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="Verify a known stock M28U image offline")
    inspect.add_argument("image", type=Path)
    patch = sub.add_parser("candidate", help="Write the unvalidated two-byte standby candidate offline")
    patch.add_argument("image", type=Path)
    patch.add_argument("output_directory", type=Path, help="Must not exist")
    compare = sub.add_parser("verify-captures", help="Compare two supplied dumps; never declares complete device backup")
    compare.add_argument("first", type=Path)
    compare.add_argument("second", type=Path)
    compare.add_argument("--expected-bytes", type=int, required=True)
    compare.add_argument("--stock", type=Path)
    compare.add_argument("--output-directory", type=Path)
    packets = sub.add_parser("packet", help="Print a status GET and readback offline")
    packets.add_argument("query", choices=GETS)
    status = sub.add_parser("status", help="One status query; --live required to contact hardware")
    status.add_argument("query", choices=("firmware", "brightness"))
    status.add_argument("--live", action="store_true")
    status.add_argument("--device")
    sub.add_parser("readiness", help="Show unresolved prerequisites; no hardware access")
    backup = sub.add_parser("backup", help="Experimental SPI main-array backup; ISP/reset require explicit flags")
    backup.add_argument("output_directory", type=Path, nargs="?")
    backup.add_argument("--stock", type=Path, default=Path(__file__).resolve().parent.parent / "firmware/original/GIGABYTE_M28U_F11.bin")
    backup.add_argument("--live", action="store_true")
    backup.add_argument("--enter-isp", action="store_true", help="Permit temporary programming mode and MCU reset; display/KVM may be interrupted")
    backup.add_argument("--probe-only", action="store_true", help="Read chip ID and reference windows, then reset; no full backup")
    backup.add_argument("--timeout-seconds", type=int, default=600, help="Acquisition deadline: 30..3600 seconds; default 600. Does not change poll or reconnect limits.")
    backup.add_argument("--vendor-isp-clock", action="store_true", help="Opt in to the official updater's fixed volatile MCU clock sequence during ISP; unvalidated on hardware")
    backup.add_argument("--device")
    probe = sub.add_parser("scaler-probe", help="Two raw scaler register reads; no ISP transition")
    probe.add_argument("--live", action="store_true")
    probe.add_argument("--device")
    boot = sub.add_parser("boot-state", help="Observe normal-mode bank register and firmware; no ISP or reset")
    boot.add_argument("--live", action="store_true")
    boot.add_argument("--device")
    boot.add_argument("--indexed", action="store_true", help="Read only FFFC/FFFD/FFFF using nine fixed index-address writes; no target-register writes")
    preflight = sub.add_parser("preflight", help="Prepare an offline 4-KiB sector plan from two complete captures; never enables flashing")
    preflight.add_argument("first", type=Path)
    preflight.add_argument("second", type=Path)
    preflight.add_argument("output_directory", type=Path)
    preflight.add_argument("--stock", type=Path, default=Path(__file__).resolve().parent.parent / "firmware/original/GIGABYTE_M28U_F11.bin")
    simulation = sub.add_parser("simulate-update", help="Run the portable updater against in-memory flash only; no live option")
    simulation.add_argument("stock_f11", type=Path)
    simulation.add_argument("--candidate", action="store_true", help="Simulate the two-byte standby candidate instead of stock")
    writer = sub.add_parser("writer", help="Explicit experimental writer; default offline, --live preflights, --program permits programming")
    writer.add_argument("first", type=Path)
    writer.add_argument("second", type=Path)
    writer.add_argument("output_directory", type=Path)
    writer.add_argument("--stock", type=Path, default=Path(__file__).resolve().parent.parent / "firmware/original/GIGABYTE_M28U_F11.bin")
    writer.add_argument("--live", action="store_true")
    writer.add_argument("--program", action="store_true")
    target = writer.add_mutually_exclusive_group()
    target.add_argument("--stock-only", action="store_true", help="Write stock F11 rather than the two-byte candidate")
    target.add_argument("--sdr-cap540", type=Path, metavar="PINNED_IMAGE",
                        help="Select the exact unvalidated SDR cap540 research image; never an arbitrary firmware file")
    writer.add_argument("--device")
    sub.add_parser("flash", help="Legacy command always refuses; the explicit writer workflow is separate")
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            emit(image_report(read_exact_file(args.image, IMAGE_SIZE)))
        elif args.command == "candidate":
            image, manifest = make_candidate(read_exact_file(args.image, IMAGE_SIZE))
            args.output_directory.mkdir()  # Refuse existing directory/symlink.
            exclusive_write(args.output_directory / "M28U-standby-UNVALIDATED.candidate.bin", image)
            exclusive_write(args.output_directory / "manifest.json", (json.dumps(manifest, indent=2)+"\n").encode())
            emit(manifest)
        elif args.command == "verify-captures":
            first = read_exact_file(args.first, args.expected_bytes)
            second = read_exact_file(args.second, args.expected_bytes)
            stock = read_exact_file(args.stock, IMAGE_SIZE) if args.stock else None
            report = compare_captures(first, second, args.expected_bytes, stock)
            if args.output_directory:
                args.output_directory.mkdir()
                exclusive_write(args.output_directory / "capture.bin", first)
                exclusive_write(args.output_directory / "verification.json", (json.dumps(report, indent=2)+"\n").encode())
            emit(report)
        elif args.command == "packet":
            emit({"hardware_access": False, "get": get_request(args.query).hex(),
                  "readback": readback_request().hex()})
        elif args.command == "status":
            if not args.live:
                emit({"hardware_access": False, "message": "Add --live for exactly one GET. Reads may still disturb the display; close other monitor controllers first."})
            else:
                from .transport import status
                emit(status(args.query, args.device))
        elif args.command == "scaler-probe":
            if not args.live:
                emit({"hardware_access": False, "registers": ["0x6f", "0x60"], "mode_change": False})
            else:
                from .backup import probe_mode
                emit(probe_mode(args.device))
        elif args.command == "boot-state":
            if not args.live:
                emit({"hardware_access": False,
                      "registers": ["0x6f", "indexed FFFC/FFFD/FFFF" if args.indexed else "0xff", "0x6f"],
                      "firmware_gets": 1, "isp_or_reset_sent": False,
                      "indexed_address_select_writes": 9 if args.indexed else 0})
            else:
                from .diagnostics import boot_state
                emit(boot_state(args.device, indexed=args.indexed))
        elif args.command == "preflight":
            from .preflight import prepare_sector
            emit(prepare_sector(args.first, args.second, args.stock, args.output_directory))
        elif args.command == "simulate-update":
            from .update_sim import simulate_update
            emit(simulate_update(read_exact_file(args.stock_f11, IMAGE_SIZE), candidate=args.candidate))
        elif args.command == "writer":
            from .writer import run
            emit(run(args.first, args.second, args.stock, args.output_directory,
                     live=args.live, program=args.program, candidate=not args.stock_only,
                     sdr_cap540=args.sdr_cap540,
                     device=args.device, progress=lambda s: print(s, file=sys.stderr, flush=True)))
        elif args.command == "backup" and args.live and args.enter_isp and args.output_directory is not None:
            from .backup import run_backup
            emit(run_backup(args.stock, args.output_directory, device=args.device, probe_only=args.probe_only,
                            timeout_seconds=args.timeout_seconds,
                            vendor_isp_clock=args.vendor_isp_clock,
                            progress=lambda message: print(message, file=sys.stderr, flush=True)))
        elif args.command in ("readiness", "backup", "flash"):
            emit({"ready_to_flash": False, "hardware_access": False,
                  "experimental_spi_reader_implemented": True,
                  "backup_hardware_validated": False,
                  "backup_acquisition_available": "Experimental only: backup NEW_DIRECTORY --live --enter-isp; display/KVM interruption expected",
                  "blockers": ["This generic readiness response does not load or validate saved hardware evidence",
                               "Complete nonvolatile memory coverage not established",
                               "No complete device backup or independently verified recovery path",
                               "Standby candidate lacks hardware validation; USB retention unproven",
                               "Experimental writer has not passed real-device programming acceptance"],
                  "next_step": "Use preflight with two complete captures for an offline sector plan; establish boot mapping and physical recovery separately."})
            return 0 if args.command == "readiness" else 3
        return 0
    except KeyboardInterrupt:
        message = "Interrupted."
        if args.command == "backup" and args.live and args.enter_isp:
            message += " If the monitor stays blank, power-cycle it manually. No SPI erase/program command was sent."
        print(message, file=sys.stderr)
        return 130
    except (ValueError, OSError, KeyError) as error:
        print(f"Refused: {error}", file=sys.stderr)
        return 2
    except Exception as error:
        # Native helper errors are surfaced, never retried automatically.
        print(f"Stopped without retry: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
