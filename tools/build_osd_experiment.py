"""Build an offline-only OSD experiment from the exact coordinated KVM image."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from m28u_toolkit.images import IMAGE_SIZE, KVM_COORDINATED_SHA256, OSD_NO_SIGNAL_SHA256, read_exact_file
from tools.build_kvm_experiment import build_coordinated

HOOK = 0x138C9C
TIMER_HOOK = 0x13A7C3
STUB = 0x135582
PADDING_END = 0x135717


def stub_bytes():
    """Bank19-local extension in checked padding; original KVM stub stays intact."""
    code, fixups, labels = bytearray(), [], {}

    def emit(value):
        code.extend(bytes.fromhex(value))

    def branch(value, label):
        emit(value)
        fixups.append((len(code), label))
        code.append(0)

    def jump(address):
        code.extend(bytes((2, address >> 8, address & 255)))

    emit("90 d3 68 e0")
    branch("70", "original")  # Only explicit center/confirm event0.
    branch("20 50", "original")  # Preserve the VCP forced-standby latch.
    emit("90 d3 64 e0 54 0c")
    branch("70", "original")  # Alternate UI owns the keys.
    emit("90 d7 06 e0 54 07")
    branch("70", "original")  # Captured/vendor event ownership.
    emit("90 d1 43 e0")
    branch("70", "original")  # Ordinary layout only.
    emit("90 d1 1e e0")
    branch("20 e5", "original")  # Do not bypass the OSD-lock setting.
    emit("90 d8 d4 e0 54 0f")
    branch("b4 01", "power")
    branch("80", "original")  # A queued explicit off wins.
    labels["power"] = len(code)
    emit("12 0e b7 ef 24 fe")
    branch("60", "mode")
    emit("14")
    branch("70", "original")  # Actual power getter must be 2 or 3.
    labels["mode"] = len(code)
    emit("12 2a 8f")
    branch("bf 03", "saving")
    emit("90 d3 65 e0")
    branch("70", "original")
    emit("a3 e0")
    branch("b4 26", "normal")
    branch("80", "capacity")
    labels["normal"] = len(code)
    branch("70", "original")
    emit("7f 00 12 2b d9 ef 14")
    branch("60", "capacity")
    emit("14")
    branch("70", "original")  # Screen0 with source state1/2 only.
    branch("80", "capacity")
    labels["saving"] = len(code)
    branch("bf 04", "original")
    emit("90 d8 e0 e0")
    branch("b4 04", "original")  # No transient system mode.
    emit("12 0e b7")
    branch("bf 03", "original")
    emit("90 d3 65 e0")
    branch("70", "original")
    emit("a3 e0")
    branch("60", "capacity")
    labels["original"] = len(code)
    jump(0xFF00)  # Exact installed KVM stub handles all refused/other events.
    labels["capacity"] = len(code)
    # Two slots: inherited standby stage6 and the normal menu timeout stage8.
    # Entries 5..8 can be reused; stage8 is refreshed by stock post-key logic.
    emit("7e 02 90 d4 6d 7f 15")
    labels["slot"] = len(code)
    emit("e0")
    branch("60", "available")
    emit("c3 94 05")
    branch("40", "next")
    emit("c3 94 04")
    branch("50", "next")
    labels["available"] = len(code)
    branch("de", "next")
    branch("80", "open")
    labels["next"] = len(code)
    emit("a3 a3 a3")
    branch("df", "slot")
    jump(0xFF00)  # Preserve original behavior when capacity is insufficient.
    labels["open"] = len(code)
    # Drop only already-posted no-signal messages1..6. Other messages survive.
    emit("90 d3 67 e0 14 24 fa")
    branch("40", "message_done")
    emit("e4 f0")
    labels["message_done"] = len(code)
    emit("12 30 a7")  # Real stock quick-menu opener; no source/USB request.
    emit("7f 05 12 2b f1 7f 06 12 2b f1 7f 07 12 2b f1")
    emit("7d 06 7f 60 7e ea 12 2b f7 7f 02 12 2e 7f")
    jump(0x8D33)  # Keep stock menu-timeout scheduling and post-key cleanup.

    labels["timer"] = len(code)
    emit("12 2a 8f")
    branch("bf 03", "timer_original")
    emit("90 d1 43 e0")
    branch("70", "timer_original")
    emit("90 d3 65 e0")
    branch("70", "timer_original")
    emit("a3 e0 14 c3 94 24")
    branch("50", "timer_original")  # Only actual menu screens1..0x24.
    emit("7f 00 12 2b d9 ef 14")
    branch("60", "defer")
    emit("14")
    branch("70", "timer_original")  # Source state1/2, not an active picture.
    labels["defer"] = len(code)
    # A visible screen alone is not activity: stock timeout may leave a stale
    # screen in source-state2. Only protect menus with a live stage8 timeout.
    emit("90 d4 6d 7f 15")
    labels["menu_timer_slot"] = len(code)
    emit("e0")
    branch("b4 08", "menu_timer_next")
    branch("80", "defer_active")
    labels["menu_timer_next"] = len(code)
    emit("a3 a3 a3")
    branch("df", "menu_timer_slot")
    branch("80", "timer_original")
    labels["defer_active"] = len(code)
    emit("7f 06 12 2b f1 7d 06 7f 60 7e ea 12 2b f7")
    emit("02 a8 a4")  # Stock clear-message + RET; skip cleanup/power-save arm.
    labels["timer_original"] = len(code)
    emit("90 d1 43 02 a7 c6")  # Replay displaced instruction exactly.

    for offset, label in fixups:
        displacement = labels[label] - offset - 1
        if not -128 <= displacement <= 127:
            raise ValueError("OSD branch escaped relative range: " + label)
        code[offset] = displacement & 255
    return bytes(code), STUB + labels["timer"]


def build(stock):
    base, _ = build_coordinated(stock)
    if hashlib.sha256(base).hexdigest() != KVM_COORDINATED_SHA256:
        raise ValueError("OSD base must be the exact coordinated KVM image")
    if base[HOOK:HOOK+3] != bytes.fromhex("02 ff 00"):
        raise ValueError("Installed dispatcher hook mismatch")
    if base[TIMER_HOOK:TIMER_HOOK+3] != bytes.fromhex("90 d1 43"):
        raise ValueError("Standby handler hook mismatch")
    if base[STUB:PADDING_END] != b"\xff"*(PADDING_END-STUB):
        raise ValueError("Bank19 padding mismatch")
    stub, timer = stub_bytes()
    if len(stub) > PADDING_END-STUB:
        raise ValueError("OSD extension escaped checked bank19 padding")
    target = bytearray(base)
    for location,destination in ((HOOK,STUB),(TIMER_HOOK,timer)):
        target[location:location+3] = bytes((2,(destination>>8)&255,destination&255))
    target[STUB:STUB+len(stub)] = stub
    target=bytes(target)
    if hashlib.sha256(target).hexdigest() != OSD_NO_SIGNAL_SHA256:
        raise ValueError("OSD builder output differs from its immutable writer target")
    changes=[i for i,(a,b) in enumerate(zip(base,target)) if a!=b]
    allowed=set(range(HOOK,HOOK+3))|set(range(TIMER_HOOK,TIMER_HOOK+3))|set(range(STUB,STUB+len(stub)))
    if not changes or not set(changes)<=allowed:
        raise ValueError("OSD candidate escaped its byte whitelist")
    return target, {"kind":"OFFLINE OSD hypothesis; no hardware acceptance",
        "base_sha256":KVM_COORDINATED_SHA256,"candidate_sha256":hashlib.sha256(target).hexdigest(),
        "stub":hex(STUB),"timer_stub":hex(timer),"stub_bytes":len(stub),
        "changed_bytes_from_base":len(changes),"changed_banks_from_base":[19],
        "ready_to_flash":False,"writer_accepts_target":True,"hardware_access":False,
        "limits":["Physical OSD rendering and signal-less panel timing not validated",
                  "Whole main loop, earlier caller reachability and interrupts not emulated",
                  "Bank19-local code uses checked FF padding in the replicated common-address region"]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory",type=Path)
    args=parser.parse_args()
    image,report=build(read_exact_file(ROOT/"firmware/original/GIGABYTE_M28U_F11.bin",IMAGE_SIZE))
    args.output_directory.mkdir()
    with (args.output_directory/"M28U-OSD-OFFLINE-UNVALIDATED.research.bin").open("xb") as output:
        output.write(image)
    with (args.output_directory/"manifest.json").open("x") as output:
        json.dump(report,output,indent=2);output.write("\n")
    print(json.dumps(report,indent=2))


if __name__=="__main__":main()
