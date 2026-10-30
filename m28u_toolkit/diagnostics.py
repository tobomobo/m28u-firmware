"""Bounded normal-mode observations. No ISP, reset, setting or flash writes."""
from .scaler_bus import live_lock, open_bus


def boot_state(device=None, *, indexed=False):
    if not isinstance(indexed, bool):
        raise ValueError("Indexed observation permission must be boolean")
    with live_lock():
        with open_bus(device) as bus:
            before = bus.read(0x6F)[0]
            if before & 0x80:
                raise ValueError("Scaler is already in ISP; boot observation refused")
            bank = bus.boot_mapping() if indexed else bus.boot_bank()
            after = bus.read(0x6F)[0]
            if after & 0x80:
                raise ValueError("Scaler entered ISP externally; boot observation unconfirmed")
            version = bus.firmware()
    return {"kind": "Normal-mode boot-bank observation", "mode_before": before,
            "mode_after": after, "boot_registers_raw" if indexed else "boot_bank_raw": bank,
            "firmware": version, "hardware_access": True,
            "isp_or_reset_sent": False, "flash_write_sent": False,
            "indexed_address_select_writes": 9 if indexed else 0,
            "ready_to_flash": False,
            "interpretation": "Raw boot-register observation; correlate with captured boot code before inferring address mapping"}
