"""Build bounded KVM research candidates offline.

Only the exact coordinated candidate has a separate pinned writer selector.
Physical KVM behavior remains unvalidated; the older candidate stays rejected.
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

HOOK = 0x10E6E8
STUB = 0x10FF00
COORDINATED_HOOK = 0x138C9C
COORDINATED_STUB = 0x13FF00


def coordinated_stub_bytes():
    """Second, separate hypothesis: explicit no-signal request + power API.

    Hook the dispatcher before the mode-3-only event handler. Refused cases
    replay its displaced getter and continue through the original dispatcher.
    No runtime data is reserved and no global mode flag is forcibly cleared.
    """
    code, fixups, labels = bytearray(), [], {}

    def emit(value):
        code.extend(bytes.fromhex(value))

    def branch(value, label):
        emit(value)
        fixups.append((len(code), label))
        code.append(0)

    emit("90 d3 68 e0")
    branch("b4 09", "original")  # Explicit KVM event only.
    branch("20 50", "original")  # Preserve the stock VCP-requested standby latch.
    emit("90 d3 64 e0 54 0c")
    branch("70", "original")  # Keep alternate UI ownership.
    emit("90 d7 06 e0 54 07")
    branch("70", "original")  # Keep captured/vendor-event ownership.
    emit("90 d1 1e e0")
    branch("30 e7", "original")  # KVM enabled.
    emit("90 d1 43 e0")
    branch("70", "original")  # Ordinary layout only.
    # Mode3 can still be visible before a queued explicit-off request is
    # serviced. Preserve request1 and require actual power2/3 for added paths.
    emit("90 d8 d4 e0 54 0f")
    branch("b4 01", "power")
    branch("80", "original")
    labels["power"] = len(code)
    emit("12 0e b7 ef 24 fe")
    branch("60", "mode")
    emit("14")
    branch("70", "original")
    labels["mode"] = len(code)
    emit("12 2a 8f")
    branch("bf 03", "saving")
    emit("90 d3 65 e0")
    branch("70", "original")
    emit("a3 e0")
    branch("b4 26", "normal")
    branch("80", "capacity")
    labels["normal"] = len(code)
    branch("70", "original")  # Only screen0 or screen26.
    emit("7f 00 12 2b d9 ef 14")
    branch("60", "capacity")
    emit("14")
    branch("70", "original")  # Normal screen: source state1/2 only.
    branch("80", "capacity")
    labels["saving"] = len(code)
    branch("bf 04", "original")
    # Require settled mode4 and real power getter3 (power saving), not off or
    # a transition with its high nibble set. Standby cleanup cleared the screen.
    emit("90 d8 e0 e0")
    branch("b4 04", "original")
    emit("12 0e b7")
    branch("bf 03", "original")
    emit("90 d3 65 e0")
    branch("70", "original")
    emit("a3 e0")
    branch("60", "capacity")
    labels["original"] = len(code)
    emit("12 2a 8f 02 8c 9f")
    labels["capacity"] = len(code)
    emit("90 d4 6d 7f 15")
    labels["slot"] = len(code)
    emit("e0")
    branch("60", "switch")
    emit("c3 94 05")
    branch("40", "next")
    emit("c3 94 03")
    branch("40", "switch")  # Existing stage5/6/7 can be reused.
    labels["next"] = len(code)
    emit("a3 a3 a3")
    branch("df", "slot")
    emit("22")
    labels["switch"] = len(code)
    emit("12 33 71")  # Original binding selection and USB routing.
    branch("50", "done")
    # Retain the manually requested target if stock's absent-signal fallback
    # runs later. Keep its pending bit so successful-lock follow-ups still run.
    emit("7f 00 12 0e 45 90 d3 78 ef f0")
    emit("7f 05 12 2b f1 7f 06 12 2b f1 7f 07 12 2b f1")
    emit("7d 06 7f 60 7e ea 12 2b f7")
    # The stock VCP power-on path also uses request2. This replaces a pending
    # request3 and lets the stock power service clear its power-saving flag.
    emit("7f 02 12 2e 7f")
    labels["done"] = len(code)
    emit("22")
    for offset, label in fixups:
        displacement = labels[label] - offset - 1
        if not -128 <= displacement <= 127:
            raise ValueError("Coordinated KVM branch escaped relative range")
        code[offset] = displacement & 255
    return bytes(code)


def build_coordinated(stock):
    """Build from installed standby+SDR, never stack on the first KVM stub."""
    base, _ = build_sdr(stock)
    if hashlib.sha256(base).hexdigest() != SDR_CAP540_SHA256:
        raise ValueError("Base is not the existing pinned standby+SDR image")
    if base[COORDINATED_HOOK:COORDINATED_HOOK+3] != bytes.fromhex("12 2a 8f"):
        raise ValueError("Dispatcher hook mismatch")
    stub = coordinated_stub_bytes()
    if len(stub) > 256 or base[COORDINATED_STUB:0x140000] != b"\xff" * 256:
        raise ValueError("Bank-13 tail padding mismatch")
    target = bytearray(base)
    target[COORDINATED_HOOK:COORDINATED_HOOK+3] = bytes.fromhex("02 ff 00")
    target[COORDINATED_STUB:COORDINATED_STUB+len(stub)] = stub
    target = bytes(target)
    changes = [i for i, (a, b) in enumerate(zip(base, target)) if a != b]
    allowed = set(range(COORDINATED_HOOK, COORDINATED_HOOK+3)) | set(
        range(COORDINATED_STUB, COORDINATED_STUB+len(stub)))
    if not changes or not set(changes) <= allowed:
        raise ValueError("Coordinated KVM candidate escaped its byte whitelist")
    return target, {
        "kind": "Coordinated KVM/power research target; physical behavior unvalidated",
        "base_sha256": SDR_CAP540_SHA256,
        "candidate_sha256": hashlib.sha256(target).hexdigest(),
        "hook": hex(COORDINATED_HOOK), "stub": hex(COORDINATED_STUB),
        "stub_bytes": len(stub), "changed_bytes_from_base": len(changes),
        "changed_banks_from_base": [19], "hardware_access": False,
        "ready_to_flash": False, "writer_accepts_target": True,
        "limits": ["Physical event/state not measured",
                   "Original power API executes; physical wake action is not emulated",
                   "Full source loop, alternate UI and interrupts are not emulated",
                   "Separate candidate; existing bank-16 KVM stub is absent"],
    }


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
    branch("70", "original")  # Require a zero screen high byte.
    emit("a3 e0")
    branch("60", "normal")
    branch("b4 26", "original")
    branch("80", "layout")
    labels["normal"] = len(code)
    # Screen 0 normally requires source state 4. Add only states 1/2: the
    # original source/UI routine handles these by arming stage5 / message3.
    # Other states replay the original screen-0 code, including state4.
    emit("7f 00 12 2b d9 ef 14")
    branch("60", "layout")
    emit("14")
    branch("70", "original")
    labels["layout"] = len(code)
    emit("90 d1 43 e0")
    branch("70", "original")  # Preserve original paths for other layouts.
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
    emit("90 d3 65 02 e6 eb")  # Replay displaced MOV DPTR; original continuation.
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
    parser.add_argument("--coordinated", action="store_true", help="Build the separate dispatcher/power hypothesis")
    args = parser.parse_args()
    builder = build_coordinated if args.coordinated else build
    target, report = builder(read_exact_file(ROOT / "firmware/original/GIGABYTE_M28U_F11.bin", IMAGE_SIZE))
    args.output_directory.mkdir(mode=0o700)
    filename = "M28U-KVM-COORDINATED-OFFLINE-UNVALIDATED.research.bin" if args.coordinated else "M28U-KVM-OFFLINE-UNVALIDATED.research.bin"
    (args.output_directory / filename).write_bytes(target)
    (args.output_directory / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "changes"}, indent=2))


if __name__ == "__main__":
    main()
