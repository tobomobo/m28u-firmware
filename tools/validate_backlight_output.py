"""Pin stock F11 and attribute bounded offline backlight execution."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from m28u_toolkit.images import IMAGE_SIZE, read_exact_file
F11 = "1ff616f5adcebf5057bd33405709757a68918b3cbfc0fabcad109e8a0a8128d0"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("harness", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--experiment", type=Path,
                        help="Require exact reconstruction of the offline SDR-cap540 image")
    args = parser.parse_args()
    image = read_exact_file(ROOT / "firmware/original/GIGABYTE_M28U_F11.bin", IMAGE_SIZE)
    if hashlib.sha256(image).hexdigest() != F11:
        raise ValueError("Pinned stock F11 required")
    command = [str(args.harness.resolve())]
    if args.experiment:
        from build_sdr_experiment import build
        candidate, _ = build(image)
        if read_exact_file(args.experiment, IMAGE_SIZE) != candidate:
            raise ValueError("Supplied experiment does not match exact offline reconstruction")
        image = candidate
        command.append("--experimental-sdr540")
    result = subprocess.run(command, input=image,
                            capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", "replace"))
    report = json.loads(result.stdout)
    if (report["output_cases"] != 517120 or report["buffer_cases"] != 65536 or
            report["direct_argument_cases"] != 65536 or
            report["experiment"] != bool(args.experiment) or
            report["normal_max_bytes"] != ([135, 0] if args.experiment else [101, 1]) or
            report["boost_bytes"] != [160, 3] or report["hardware_access"]):
        raise ValueError("Unexpected harness output")
    mutations = []
    if args.experiment:
        from build_sdr_experiment import HOOK, STUB, stub_bytes
        stub = stub_bytes()

        def mutate(name, offset, before, after):
            if image[offset:offset+len(before)] != before or len(before) != len(after):
                raise ValueError("Mutation seam mismatch")
            broken = bytearray(image)
            broken[offset:offset+len(before)] = after
            result = subprocess.run(command, input=broken, capture_output=True, timeout=60)
            if result.returncode != 2 or b"mismatch" not in result.stderr.lower() and b"Unexpected output bytes" not in result.stderr:
                raise ValueError("Harness did not detect meaningful mutation: " + name)
            mutations.append({"name": name, "offset": hex(offset),
                              "detected": True, "failure": result.stderr.decode().strip()})

        mutate("removed SDR hook", HOOK, bytes.fromhex("12 c0 00"), bytes.fromhex("12 98 2c"))
        mutate("reversed layout guard", STUB+4, b"\x70", b"\x60")
        mutate("reversed saved-dimming guard", STUB+10, b"\x20", b"\x30")
        upper = stub.index(bytes.fromhex("94 96")) + 1
        mutate("accepted out-of-range argument406", STUB+upper, b"\x96", b"\x97")
        mult = stub.index(bytes.fromhex("7d a4")) + 1
        mutate("wrong gain numerator", STUB+mult, b"\xa4", b"\xa5")
    sources = ["tools/backlight_output_harness.c", "tools/validate_backlight_output.py",
               "tools/build_sdr_experiment.py",
               "m28u_toolkit/images.py", "analysis/vendor/emu8051/disasm.c",
               "analysis/vendor/emu8051/core.c", "analysis/vendor/emu8051/opcodes.c",
               "analysis/vendor/emu8051/emu8051.h"]
    report.update(stock_sha256=F11, image_sha256=hashlib.sha256(image).hexdigest(),
                  detected_mutations=mutations,
                  harness_sha256=hashlib.sha256(args.harness.read_bytes()).hexdigest(),
                  source_sha256={p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources},
                  limits=["Only selected stock routines execute; not a monitor emulator",
                          "Mode predicates and transport calls are stubbed; no hardware delivery, faults or callee clobbers modelled",
                          "Synthetic state combinations are not evidence of reachable monitor states",
                          "The AS382x-compatible register interpretation is not a physical chip identification",
                          "Control values and ratios are not nits; continuous operating limits and colour accuracy remain unmeasured"],
                  experimental_image=bool(args.experiment), ready_to_flash=False)
    with args.output.open("x") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
