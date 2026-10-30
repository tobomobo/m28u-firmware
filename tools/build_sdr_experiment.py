"""Build an offline-only F11 SDR gain experiment; never opens a transport.

540 is a control cap, NOT a measured nit target or certified safe setting.
The existing writer's accepted target policy is deliberately unchanged.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from m28u_toolkit.images import IMAGE_SIZE, make_candidate, read_exact_file

F11 = "1ff616f5adcebf5057bd33405709757a68918b3cbfc0fabcad109e8a0a8128d0"
HOOK = 0x148D8F
STUB = 0x14C000


def stub_bytes():
    code = bytearray()
    branches = []

    def emit(hex_bytes):
        code.extend(bytes.fromhex(hex_bytes))

    def exit_if(hex_bytes):
        emit(hex_bytes)
        branches.append(len(code))
        code.append(0)

    emit("90 d1 43 e0")  # MOVX A,D143: require the ordinary layout mode.
    exit_if("70")  # JNZ original packing helper.
    emit("90 d0 e9 e0")
    exit_if("20 e4")  # JB ACC.4: keep the saved SDR dimming mode unchanged.
    emit("90 c9 e1 e0 fe a3 e0 ff")  # Original argument -> R6:R7.
    emit("c3 ef 94 30 ee 94 00")
    exit_if("40")  # Argument <48: preserve original behavior.
    emit("c3 ef 94 96 ee 94 01")
    exit_if("50")  # Argument >=406: preserve original behavior.
    emit("c3 ef 94 30 ff ee 94 00 fe")  # R6:R7 -=48.
    emit("7c 00 7d a4 12 38 45")  # Actual common u16 multiply by164.
    emit("7c 00 7d 77 12 38 57")  # Actual common u16 divide by119.
    emit("ef 24 30 ff ee 34 00 fe")  # R6:R7 +=48.
    emit("90 c9 e1 ee f0 a3 ef f0")
    exit_pc = len(code)
    emit("02 98 2c")  # Tail to the original packing helper, then its RET.
    for index in branches:
        displacement = exit_pc - index - 1
        if not 0 <= displacement <= 127:
            raise ValueError("Stub branch escaped relative range")
        code[index] = displacement
    return bytes(code)


def build(stock):
    if len(stock) != IMAGE_SIZE or hashlib.sha256(stock).hexdigest() != F11:
        raise ValueError("Exact stock F11 required")
    if stock[HOOK:HOOK+3] != bytes.fromhex("12 98 2c"):
        raise ValueError("Original output call mismatch")
    # This is erased padding in the pinned file, not proof it is safe to execute
    # injected code on the physical banked CPU. That remains an acceptance gate.
    if stock[STUB:0x150000] != b"\xff" * (0x150000 - STUB):
        raise ValueError("Expected erased bank-14 padding is occupied")
    candidate, _ = make_candidate(stock)
    candidate = bytearray(candidate)
    stub = stub_bytes()
    candidate[HOOK:HOOK+3] = bytes.fromhex("12 c0 00")
    candidate[STUB:STUB+len(stub)] = stub
    candidate = bytes(candidate)
    allowed = {0x13a79e, 0x13a7a0, HOOK+1, HOOK+2} | set(range(STUB, STUB+len(stub)))
    actual = {i for i, (a, b) in enumerate(zip(stock, candidate)) if a != b}
    if not actual <= allowed or not {0x13a79e, 0x13a7a0, HOOK+1, HOOK+2} <= actual:
        raise ValueError("Experiment escaped exact byte whitelist")
    report = {
        "kind": "OFFLINE UNVALIDATED SDR control-cap-540 experiment plus standby timer",
        "stock_sha256": F11, "candidate_sha256": hashlib.sha256(candidate).hexdigest(),
        "hook_image_offset": hex(HOOK), "stub_image_offset": hex(STUB),
        "stub_bytes": len(stub), "stub_hex": stub.hex(" "),
        "changed_banks": sorted({i // 65536 for i in actual}),
        "changed_bytes": len(actual),
        "changes": [{"offset": hex(i), "before": f"{stock[i]:02x}", "after": f"{candidate[i]:02x}"}
                    for i in sorted(actual)],
        "applies_when": ["Existing mode predicate 2BC1 is false",
                         "Existing special-mode helper 2555 does not return1",
                         "D0E9.bit0 and bit4 are clear", "D143 is zero",
                         "Original driver argument is48..405"],
        "new_argument": "48 + floor((original_argument - 48) * 164 / 119)",
        "output_min": 48, "output_max": 540, "stock_boost_control_value": 643,
        "max_multiply_intermediate": 58548,
        "requested_luminance_nits": 400, "measured_luminance_nits": None,
        "cap_rationale": "540/405 is4/3, a research starting point assuming300-nit stock and a linear response; neither assumption is a measurement",
        "colour_pipeline_code_modified": False,
        "hardware_access": False, "ready_to_flash": False,
        "writer_policy_modified": False,
        "pending": ["Physical chip and mode attribution",
                    "Injected code and bank behavior on real hardware",
                    "Continuous electrical and thermal operating envelope",
                    "Luminance, black level, white balance, gamma and clipping measurements",
                    "MonitorControl/OSD brightness, HDR and KVM acceptance",
                    "Deliberate writer-policy update and review before any possible flash"],
    }
    return candidate, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory", type=Path)
    args = parser.parse_args()
    candidate, report = build(read_exact_file(ROOT / "firmware/original/GIGABYTE_M28U_F11.bin", IMAGE_SIZE))
    args.output_directory.mkdir(mode=0o700)  # Never replace existing artifacts.
    (args.output_directory / "M28U-SDR-cap540-OFFLINE-UNVALIDATED.research.bin").write_bytes(candidate)
    (args.output_directory / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "changes"}, indent=2))


if __name__ == "__main__":
    main()
