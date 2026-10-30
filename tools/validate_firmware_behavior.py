"""Attribute bounded KVM/brightness emulation to exact F11; no monitor access."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent
F11 = "1ff616f5adcebf5057bd33405709757a68918b3cbfc0fabcad109e8a0a8128d0"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("harness", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    image = (ROOT / "firmware/original/GIGABYTE_M28U_F11.bin").read_bytes()
    if hashlib.sha256(image).hexdigest() != F11:
        raise ValueError("Pinned stock F11 required")
    result = subprocess.run([str(args.harness.resolve())], input=image,
                            capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", "replace"))
    report = json.loads(result.stdout)
    if (report["kvm_cases"] != 6144 or report["brightness_cases"] != 101 or
            report["event9_gate_cases"] != 2304 or
            report["no_signal_event9_cases_without_switch"] != 384 or
            report["screen_dispatch_cases"] != 20 or report["hardware_access"]):
        raise ValueError("Unexpected harness output")
    report.update(image_sha256=F11, harness_sha256=hashlib.sha256(args.harness.read_bytes()).hexdigest(),
                  harness_source_sha256=hashlib.sha256((ROOT / "tools/firmware_behavior_harness.c").read_bytes()).hexdigest(),
                  limits=["Current physical D143 state is unknown; no hardware fault reproduced in emulator",
                          "Event9 and callback gates execute stock code with synthetic state inputs; physical key delivery is unverified",
                          "KVM hardware callees are stubbed, not validated",
                          "Brightness arithmetic is a driver input, not measured luminance or PWM duty",
                          "Neither maximum safe current nor SDR/HDR path selection is established"])
    with args.output.open("x") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
