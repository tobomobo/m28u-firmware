"""Execute bounded OSD firmware cases and negative controls; no device APIs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from m28u_toolkit.images import IMAGE_SIZE, read_exact_file
from tools.build_kvm_experiment import build_coordinated
from tools.build_osd_experiment import HOOK, TIMER_HOOK, STUB, PADDING_END, build, stub_bytes

COUNTS = {"open_cases": 3072, "guard_cases": 45, "event_cases": 254,
          "timer_gate_cases": 16384,
          "capacity_cases": 210, "timer_sequences": 72, "navigation_cases": 6,
          "clock_cases": 21, "wake_sequences": 1}


def execute(harness, mode, image):
    return subprocess.run([str(Path(harness).resolve()), mode], input=image,
                          capture_output=True, timeout=60)


def passing(harness, mode, image):
    result = execute(harness, mode, image)
    if result.returncode:
        raise ValueError(mode + ": " + result.stderr.decode("utf-8", "replace"))
    report = json.loads(result.stdout)
    if report.get("hardware_access") is not False or not 0x5f <= report.get("peak_sp", 0) < 0xf0:
        raise ValueError("Incomplete offline harness report")
    return report


def padding_audit(directory):
    """Optional derived static map check, not a proof of all indirect targets."""
    directory = Path(directory)
    edges, instructions = directory / "edges.jsonl", directory / "instructions.jsonl"
    edge_count = instruction_count = other_bank_pointers = 0
    for line in edges.open():
        edge = json.loads(line)
        edge_count += 1
        if STUB % 65536 <= edge["target"][1] < PADDING_END % 65536:
            raise ValueError("Derived static map has an incoming padding edge")
    for line in instructions.open():
        instruction = json.loads(line)
        instruction_count += 1
        pc, bank, raw = instruction["pc"], instruction["bank"], instruction["bytes"]
        pointer = raw.startswith("90") and len(raw) == 6 and STUB % 65536 <= int(raw[2:], 16) < PADDING_END % 65536
        if bank == 19 and (STUB % 65536 <= pc < PADDING_END % 65536 or pointer):
            raise ValueError("Derived bank19 code/pointer occupies the padding")
        other_bank_pointers += bool(pointer and bank != 19)
    return {"edges_checked": edge_count, "instructions_checked": instruction_count,
            "incoming_static_edges": 0, "bank19_code_or_dptr_references": 0,
            "other_bank_dptr_references": other_bank_pointers,
            "map_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (edges, instructions)},
            "limit": "Recursive map is incomplete for indirect/computed references; other banks are unchanged"}


def validate(harness, kvm_harness, stock, firmware_map=None):
    candidate, manifest = build(stock)
    installed, _ = build_coordinated(stock)
    for name, control in (("stock", stock), ("installed-kvm", installed)):
        passing(harness, "--active-control", control)
        red = execute(harness, "--require-no-signal-menu", control)
        if red.returncode != 2 or b"OSD button did not open" not in red.stderr:
            raise ValueError(name + " did not reproduce the intended OSD failure")
    passing(harness, "--active-control", candidate)
    report = passing(harness, "--suite", candidate)
    if any(report.get(key) != value for key, value in COUNTS.items()) or not (
            report.get("rendering_stubbed") and report.get("physical_power_action_stubbed")):
        raise ValueError("OSD case count or interception disclosure mismatch")
    kvm = passing(kvm_harness, "--require-coordinated-switch", candidate)
    if kvm.get("coordinated_cases") != 38:
        raise ValueError("Incomplete retained KVM regression report")
    stub, _ = stub_bytes()

    def at(pattern, delta=0):
        value = bytes.fromhex(pattern)
        if stub.count(value) != 1:
            raise ValueError("Mutation site must be unique: " + pattern)
        return STUB + stub.index(value) + delta

    mutations = [
        ("event0 guard removed", at("90 d3 68 e0 70", 4), b"\0\0"),
        ("OSD lock guard removed", at("90 d1 1e e0 20 e5", 4), b"\0\0\0"),
        ("queued off guard removed", at("b4 01", 1), b"\xff"),
        ("two timer slots reduced to one", at("7e 02 90 d4 6d", 1), b"\x01"),
        ("stale standby message retained", at("14 24 fa", 5), b"\0\0"),
        ("stage5 cancellation lost", at("7f 05 12 2b f1", 2), b"\0\0\0"),
        ("wake replaced with standby", at("7f 02 12 2e 7f", 1), b"\x03"),
        ("normal post-key menu timeout bypassed", at("02 8d 33"), b"\x22\0\0"),
        ("timer deferral removed", TIMER_HOOK, bytes.fromhex("90 d1 43")),
        ("active menu timer identity wrong", at("e0 b4 08", 2), b"\x09"),
    ]
    detected = []
    for name, offset, replacement in mutations:
        broken = bytearray(candidate)
        broken[offset:offset+len(replacement)] = replacement
        result = execute(harness, "--suite", bytes(broken))
        if result.returncode != 2 or not result.stderr:
            raise ValueError("Mutation not caught: " + name)
        detected.append({"name": name, "offset": hex(offset), "detected": True})
    sources = ["tools/build_osd_experiment.py", "tools/osd_state_harness.c",
               "tools/validate_osd_state.py", "tools/kvm_state_harness.c",
               "analysis/vendor/emu8051/core.c", "analysis/vendor/emu8051/opcodes.c"]
    return {"hardware_access": False, "candidate": manifest, "osd": report, "kvm": kvm,
            "red_controls": ["stock", "installed-kvm"], "detected_mutations": detected,
            "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources},
            "padding_audit": padding_audit(firmware_map) if firmware_map else None,
            "limits": ["Rendering/mixer helpers and physical wake action intercepted",
                       "Callbacks start with supplied key event; full callers/scanner/main loop and interrupts not modeled",
                       "Menu opening, main-menu entry and quick-menu close execute; complete settings/input-picker navigation does not",
                       "Timer deliveries/order supplied, scheduling APIs and message handlers execute",
                       "Physical no-signal panel timing and visibility remain untested"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("harness", type=Path)
    parser.add_argument("kvm_harness", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--firmware-map", type=Path)
    args = parser.parse_args()
    stock = read_exact_file(ROOT / "firmware/original/GIGABYTE_M28U_F11.bin", IMAGE_SIZE)
    report = validate(args.harness, args.kvm_harness, stock, args.firmware_map)
    with args.output.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
