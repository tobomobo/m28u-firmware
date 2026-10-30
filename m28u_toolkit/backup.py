"""Explicit ISP backup runner; never used by default/offline CLI commands."""
from pathlib import Path
from contextlib import ExitStack, contextmanager
import time

from .images import IMAGE_SIZE, identify_stock, read_exact_file
from .scaler import acquire, publish_after_normal_check, _private_json, ResetUnconfirmed
from .scaler_bus import live_lock, open_bus


@contextmanager
def _open_after_reset(device, progress):
    """Wait for USB enumeration only; never retry a monitor register/DDC query."""
    deadline = time.monotonic() + 30
    with ExitStack() as stack:
        for attempt in range(16):
            try:
                fresh = stack.enter_context(open_bus(device))
                break
            except OSError:
                if attempt == 15 or time.monotonic() >= deadline:
                    raise
                progress("Waiting for monitor USB to re-enumerate")
                time.sleep(2)
        yield fresh


def run_backup(stock_path, output_directory, *, device=None, probe_only=False, timeout_seconds=600, vendor_isp_clock=False, progress=lambda message: None):
    # Reject invalid bounds before opening any hardware.
    from .scaler import SpiReader
    SpiReader(None, timeout_seconds=timeout_seconds)
    if not isinstance(vendor_isp_clock, bool):
        raise ValueError("Vendor clock permission must be boolean")
    stock = read_exact_file(stock_path, IMAGE_SIZE)
    identify_stock(stock)
    output = Path(output_directory)
    if output.exists() or output.is_symlink():
        raise FileExistsError("Backup output must be a new directory")
    if not output.parent.is_dir():
        raise ValueError("Backup parent directory does not exist")
    with live_lock():
        failure = None
        report = None
        try:
            with open_bus(device, allow_vendor_clock=vendor_isp_clock) as bus:
                report = acquire(bus, stock, output, progress=progress, probe_only=probe_only, timeout_seconds=timeout_seconds)
        except BaseException as error:
            report = getattr(error, "m28u_report", None) or report
            if report is None or not report.get("isp_entry_attempted"):
                raise
            # Even an unsupported chip/failed capture deserves an independent
            # check that our owned ISP attempt has returned to normal operation.
            failure = error
        try:
            progress("Mode-exit cleanup attempted; checking fresh scaler responses")
            time.sleep(3)
            with _open_after_reset(device, progress) as fresh:
                if fresh.read(0x6F)[0] & 0x80:
                    raise ValueError("Scaler still reports ISP; captures remain partial. A manual monitor power cycle may be needed.")
                # Different selectors reject a stale pre-ISP firmware reply.
                source = fresh.source()
                version = fresh.firmware()
            if version != report["reference_firmware"]:
                raise ValueError("Normal firmware label changed unexpectedly; captures remain partial")
        except BaseException as error:
            report["normal_check_failure"] = f"{type(error).__name__}: {error}"
            progress("Monitor state is unconfirmed. If it stays blank, power-cycle it manually. No SPI erase/program commands were sent.")
            _private_json(output / "normal-check.json", report)
            if failure is not None and not isinstance(failure, Exception):
                raise failure from error
            raise
        report["normal_source_raw"] = source
        report["display_and_kvm_visually_confirmed"] = False
        report["reset_confirmed_by_fresh_responses"] = True
        if failure is not None and not isinstance(failure, ResetUnconfirmed):
            report["normal_operation_confirmed"] = True
            _private_json(output / "normal-check.json", report)
            progress("Normal scaler responses confirmed after the failed acquisition")
            raise failure
        return publish_after_normal_check(output, report, version)


def probe_mode(device=None):
    with live_lock():
        with open_bus(device) as bus:
            return {"mode_raw": bus.read(0x6F)[0], "spi_control_raw": bus.read(0x60)[0],
                    "mode_changed": False,
                    "interpretation": "Raw register reads only; not a validated flash identity or backup"}
