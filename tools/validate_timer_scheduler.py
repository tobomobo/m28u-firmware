"""Bind the offline emu8051 harness to exact public F11; no monitor access.

Build the helper with the public MIT-licensed emu8051 sources:
clang -O2 -I analysis/vendor/emu8051 tools/timer_scheduler_harness.c \
  analysis/vendor/emu8051/core.c analysis/vendor/emu8051/opcodes.c \
  analysis/vendor/emu8051/disasm.c -o tools/timer_scheduler_harness
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from m28u_toolkit.images import IMAGE_SIZE, identify_stock, read_exact_file


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    stock = read_exact_file(ROOT / "firmware/original/GIGABYTE_M28U_F11.bin", IMAGE_SIZE)
    if identify_stock(stock)[0] != "F11":
        raise ValueError("F11 is required")
    result = subprocess.run([str(ROOT / "tools/timer_scheduler_harness")],
                            input=stock[0x80000:0x90000], capture_output=True,
                            check=True, timeout=60)
    report = json.loads(result.stdout)
    if report.get("cases") != 393216 or report.get("delays") != [5000, 60000] or \
       report.get("all_16bit_counter_values") is not True or report.get("hardware_access") is not False:
        raise ValueError("Unexpected scheduler harness result")
    report["stock_f11_sha256"] = hashlib.sha256(stock).hexdigest()
    report["bank8_sha256"] = hashlib.sha256(stock[0x80000:0x90000]).hexdigest()
    report["emulator_sources"] = json.loads((ROOT / "analysis/vendor/emu8051/sources.json").read_text())
    report["scope"] = "Actual F11 bank-8 scheduler instructions in emu8051, frozen clock and three table states"
    report["limits"] = ["No interrupt interleavings or Realtek hardware modeled",
                        "No wall-clock unit, video-loss or USB retention validation",
                        "Not full firmware or recovery validation"]
    with args.output.open("x") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
