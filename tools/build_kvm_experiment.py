"""Build a no-signal KVM research candidate offline; no live transport support.

The current writer intentionally rejects this image. This is a test hypothesis,
not a diagnosed physical-button fix or a flash-ready target.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from m28u_toolkit.images import IMAGE_SIZE, SDR_CAP540_SHA256, read_exact_file
from tools.build_sdr_experiment import build as build_sdr

HOOK = 0x10E6FE
STUB = 0x10FF00


def stub_bytes():
    code = bytearray()
    fixups = []
    labels = {}

    def emit(value):
        code.extend(bytes.fromhex(value))

    def branch(value, label):
        emit(value)
        fixups.append((len(code), label))
        code.append(0)

    # Entered after the original system-mode==3 and KVM-enable checks.
    emit("90 d3 65 e0")
    branch("70", "original")  # Require full screen word 0x0026.
    emit("a3 e0")
    branch("b4 26", "original")
    emit("90 d1 43 e0")
    branch("70", "done")  # Keep original no-op for non-ordinary layouts.
    # Refuse the added path if the scheduler has no free/reusable slot.
    # Queue mutation remains through the original cancel/enqueue APIs.
    emit("90 d4 6d 7f 15")
    labels["slot"] = len(code)
    emit("e0")
    branch("60", "switch")
    branch("b4 06", "check7")
    branch("80", "switch")
    labels["check7"] = len(code)
    branch("b4 07", "next")
    branch("80", "switch")
    labels["next"] = len(code)
    emit("a3 a3 a3")
    branch("df", "slot")
    emit("22")
    labels["switch"] = len(code)
    emit("12 33 71")  # Original common gateway -> existing KVM selection.
    # In ordinary layout, both selection helpers explicitly return C=1 for a
    # request, C=0 for no destination; the gateway preserves PSW/carry.
    branch("50", "done")
    emit("7f 06 12 2b f1 7f 07 12 2b f1")  # Cancel old standby stages.
    emit("7d 06 7f 60 7e ea 12 2b f7")  # Fresh inherited 60000-count delay.
    labels["done"] = len(code)
    emit("22")
    labels["original"] = len(code)
    emit("90 d3 65 02 e7 01")  # Replay displaced MOV DPTR; original continuation.
    for offset, label in fixups:
        displacement = labels[label] - offset - 1
        if not -128 <= displacement <= 127:
            raise ValueError("KVM branch escaped relative range")
        code[offset] = displacement & 255
    return bytes(code)


def build(stock):
    base, _ = build_sdr(stock)  # Independently pins exact stock F11.
    if hashlib.sha256(base).hexdigest() != SDR_CAP540_SHA256:
        raise ValueError("Base is not the existing pinned standby+SDR image")
    if base[HOOK:HOOK+3] != bytes.fromhex("90 d3 65"):
        raise ValueError("Event-9 hook mismatch")
    stub = stub_bytes()
    if len(stub) > 0xf0 or base[STUB:0x110000] != b"\xff" * (0x110000-STUB):
        raise ValueError("Bank-10 tail padding mismatch")
    target = bytearray(base)
    target[HOOK:HOOK+3] = bytes.fromhex("02 ff 00")
    target[STUB:STUB+len(stub)] = stub
    target = bytes(target)
    changes = [i for i, (a, b) in enumerate(zip(base, target)) if a != b]
    allowed = set(range(HOOK, HOOK+3)) | set(range(STUB, STUB+len(stub)))
    if not changes or not set(changes) <= allowed:
        raise ValueError("KVM candidate escaped its byte whitelist")
    return target, {
        "kind": "OFFLINE KVM no-signal hypothesis, NOT FLASH READY",
        "base_sha256": SDR_CAP540_SHA256,
        "candidate_sha256": hashlib.sha256(target).hexdigest(),
        "hook": hex(HOOK), "stub": hex(STUB), "stub_bytes": len(stub),
        "changed_bytes_from_base": len(changes), "changed_banks_from_base": [16],
        "changes": [{"offset": hex(i), "before": f"{base[i]:02x}", "after": f"{target[i]:02x}"}
                    for i in changes],
        "hardware_access": False, "ready_to_flash": False,
        "writer_accepts_target": False,
        "limits": ["Synthetic state contract; physical event/state not measured",
                   "Bank-tail code placement requires independent review",
                   "Source delivery, USB mux, interrupts and fallback are not fully emulated",
                   "Timer reset behavior must be tested before any writer integration"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory", type=Path)
    args = parser.parse_args()
    target, report = build(read_exact_file(ROOT / "firmware/original/GIGABYTE_M28U_F11.bin", IMAGE_SIZE))
    args.output_directory.mkdir(mode=0o700)
    (args.output_directory / "M28U-KVM-OFFLINE-UNVALIDATED.research.bin").write_bytes(target)
    (args.output_directory / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "changes"}, indent=2))


if __name__ == "__main__":
    main()
