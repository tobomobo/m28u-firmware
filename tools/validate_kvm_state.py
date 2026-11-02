"""Rebuild and exercise the no-signal KVM hypothesis; no device access."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from m28u_toolkit.images import IMAGE_SIZE, make_candidate, read_exact_file
from tools.build_sdr_experiment import build as build_sdr
from tools.build_kvm_experiment import HOOK, STUB, build, stub_bytes
from tools.build_kvm_experiment import (COORDINATED_HOOK, COORDINATED_STUB,
                                       build_coordinated, coordinated_stub_bytes)

COUNTS = {"scanner_cases": 32, "gate_cases": 8640, "timer_handoff_cases": 216, "timer_capacity_cases": 189,
          "binding_cases": 18432, "scanner_dispatch_chain_cases": 4,
          "screen_word_cases": 65536, "enable_layout_cases": 65536,
          "source_route_cases": 1920, "fallback_cases": 1536,
          "scanner_pacing_cases": 12, "wake_edge_cases": 16,
          "upstream_dispatch_cases": 172032, "caller_gate_cases": 4096,
          "source_loop_cases": 64, "normal_state_cases": 65536, "sequence_cases": 2}

STACK_FAMILIES = {"scanner", "scanner_dispatch", "pacing", "wake", "upstream", "caller",
                  "source_loop", "gate", "timer_handoff", "capacity", "binding",
                  "source_route", "fallback", "normal_state", "screen", "enable_layout", "sequence"}


def validate_coordinated(harness, stock, previous):
    image, manifest = build_coordinated(stock)
    command = [str(Path(harness).resolve()), "--require-coordinated-switch"]
    result = subprocess.run(command, input=image, capture_output=True, timeout=60)
    if result.returncode:
        raise ValueError("Coordinated candidate: " + result.stderr.decode("utf-8", "replace"))
    report = json.loads(result.stdout)
    if (report.get("coordinated_cases") != 38 or report.get("hardware_access") is not False or
            report.get("power_api_executed") is not True or
            report.get("physical_power_action_stubbed") is not True or
            not 0x5f <= report.get("peak_sp", 0) < 0xf0):
        raise ValueError("Incomplete coordinated harness result")
    for name, control in (("stock", stock), ("previous candidate", previous)):
        red = subprocess.run(command, input=control, capture_output=True, timeout=60)
        if red.returncode != 2 or b"Manual destination" not in red.stderr:
            raise ValueError(name + " did not reproduce the retained-destination failure")
    stub = coordinated_stub_bytes()
    def at(value):
        needle = bytes.fromhex(value)
        if stub.count(needle) != 1:
            raise ValueError("Ambiguous coordinated mutation: " + value)
        return COORDINATED_STUB + stub.index(needle)
    mutations = [
        ("removed dispatcher hook", COORDINATED_HOOK, bytes.fromhex("12 2a 8f")),
        ("lost explicit-key guard", at("b4 09"), b"\x00\x00\x00"),
        ("VCP standby latch bypassed", at("20 50"), b"\x00\x00\x00"),
        ("alternate UI ownership bypassed", at("54 0c")+1, b"\x00"),
        ("captured-event ownership bypassed", at("54 07")+1, b"\x00"),
        ("KVM enable guard bypassed", at("30 e7"), b"\x00\x00\x00"),
        ("wrong no-signal screen", at("b4 26")+1, b"\x25"),
        ("lost normal state2", at("ef 14 60")+1, b"\x00"),
        ("saver mode changed", at("bf 04")+1, b"\x05"),
        ("transient mode accepted", at("b4 04"), b"\x00\x00\x00"),
        ("queued off overridden", at("90 d8 d4 e0 54 0f")+9, b"\x00\x00"),
        ("completed off overridden", at("ef 24 fe 60")+6, b"\x00\x00"),
        ("mode4 accepted without power saving", at("90 d8 e0 e0 b4 04")+10, b"\x00\x00\x00"),
        ("stale stage5 cannot be reused", at("c3 94 05")+2, b"\x06"),
        ("rejected selector treated as accepted", at("12 33 71 50")+3, b"\x00\x00"),
        ("new target snapshot dropped", at("90 d3 78 ef f0")+4, b"\x00"),
        ("stale stage5 cancellation dropped", at("7f 05 12 2b f1")+2, b"\x00\x00\x00"),
        ("wrong fresh standby delay", at("7f 60 7e ea")+1, b"\x61"),
        ("wake request lost", at("7f 02 12 2e 7f")+2, b"\x00\x00\x00"),
        ("stock wake consumption lost", 0x00aac3, b"\x54\xff"),
        ("source assignment dropped", 0x04eef6, b"\x00"),
        ("USB GPIO write dropped", 0x14775a, b"\x00"),
    ]
    detected = []
    for name, offset, replacement in mutations:
        broken = bytearray(image)
        broken[offset:offset+len(replacement)] = replacement
        result = subprocess.run(command, input=broken, capture_output=True, timeout=60)
        if result.returncode != 2 or not result.stderr:
            raise ValueError("Coordinated mutation not detected: " + name)
        detected.append({"name": name, "offset": hex(offset), "detected": True})
    return {"candidate": manifest, "run": report, "detected_mutations": detected,
            "stock_and_previous_candidate_fail": True,
            "limits": ["Caller boundary is the dispatcher, not the full main loop",
                       "Physical wake action11 is intercepted; public request/getter and service flag changes execute",
                       "Source/USB transport results are injected; asynchronous link lock and power services are not reproduced",
                       "No physical failed-state observation, interrupts, general OSD recovery or writer integration"]}


def validate(harness, stock):
    candidate, manifest = build(stock)
    images = {"stock": stock, "standby": make_candidate(stock)[0],
              "sdr": build_sdr(stock)[0], "kvm": candidate}
    commands = [str(Path(harness).resolve())]
    results = {}
    for name, image in images.items():
        command = commands + (["--require-no-signal-switch"] if name == "kvm" else [])
        completed = subprocess.run(command, input=image, capture_output=True, timeout=60)
        if completed.returncode:
            raise ValueError(f"{name}: {completed.stderr.decode('utf-8', 'replace').strip()}")
        report = json.loads(completed.stdout)
        expected_switches = 6 if name == "kvm" else 0
        if (any(report.get(k) != v for k, v in COUNTS.items()) or
                report.get("hardware_access") is not False or
                report.get("original_bank_gateways_executed") is not True or
                report.get("no_signal_switched") != expected_switches or
                report.get("no_signal_blocked") != 6 - expected_switches or
                report.get("route_early_returns") != (480 if name == "kvm" else 0) or
                report.get("route_completions") != (288 if name == "kvm" else 0) or
                report.get("fallback_requests") != 256 or report.get("fallback_searches") != 256 or
                report.get("sequential_split_routes") != (2 if name == "kvm" else 0) or
                report.get("post_sleep_requests") != (2 if name == "kvm" else 0) or
                report.get("route_transport_stubbed") is not True or
                report.get("candidate_expected") != (name == "kvm")):
            raise ValueError(f"Unexpected {name} harness result")
        peaks = report.get("stack_peaks", {})
        if (set(peaks) != STACK_FAMILIES or any(not 0x5f <= p < 0xf0 for p in peaks.values()) or
                report.get("peak_sp") != max(peaks.values()) or
                report.get("gate_peak_sp") != peaks["gate"]):
            raise ValueError(f"Incomplete {name} stack coverage")
        results[name] = report
    if results["stock"] != results["standby"] or results["stock"] != results["sdr"]:
        raise ValueError("Existing standby/SDR patches changed the tested KVM path")

    # Mutation checks make the proposed behaviour red-capable, rather than
    # merely accepting whichever bytes happen to execute without a crash.
    stub = stub_bytes()
    seam = stub.index(bytes.fromhex("90 d1 43 e0 70")) + 4
    mutations = [("removed hook", HOOK, bytes.fromhex("90 d3 65")),
                 ("wrong no-signal screen", STUB + stub.index(bytes.fromhex("b4 26")) + 1, b"\x24"),
                 ("reversed layout guard", STUB + seam, b"\x60"),
                 ("stale-message success shortcut", STUB + stub.index(bytes.fromhex("12 33 71 50")) + 3, b"\x00\x00"),
                 ("capacity guard bypass", STUB + stub.index(bytes.fromhex("90 d4 6d")),
                  bytes((2, 255, stub.index(bytes.fromhex("12 33 71"))))),
                 ("wrong standby delay", STUB + stub.index(bytes.fromhex("7f 60 7e ea")) + 1, b"\x61"),
                 ("cancelled wrong first timer", STUB + stub.index(bytes.fromhex("7f 06 12 2b f1")) + 1, b"\x05"),
                 ("cancelled wrong final timer", STUB + stub.index(bytes.fromhex("7f 07 12 2b f1")) + 1, b"\x05"),
                 ("source assignment dropped", 0x04eef6, b"\x00"),
                 ("route GPIO write dropped", 0x14775a, b"\x00"),
                 ("route error ignored", 0x1477fb, b"\x80"),
                 ("fallback snapshot address wrong", 0x138b12, b"\x00"),
                 ("scanner release callback lost", 0x1467ca, b"\x44\x00"),
                 ("wake input changed to KVM", 0x0bfe26, b"\xe7"),
                 ("alternate UI bit2 gate changed", 0x138ccc, b"\xe1"),
                 ("no-signal key callback changed", 0x135717 + 0x26*18 + 2, b"\xfe"),
                 ("caller bit2 gate changed", 0x138c05, b"\xe1"),
                 ("caller ignores prefilter carry", 0x138bf7, b"\x80"),
                 ("prefilter bit1 test changed", 0x08d96b, b"\xe1"),
                 ("prefilter stage5 enqueue removed", 0x08d97a, b"\x00\x00\x00"),
                 ("prefilter stage7 changed", 0x08d97e, b"\x06"),
                 ("source-loop change flag changed", 0x04f75d, b"\xe5"),
                 ("normal-screen state guard changed", STUB + stub.index(bytes.fromhex("ef 14 60")) + 1, b"\x00"),
                 ("normal-screen state2 support removed", STUB + stub.index(bytes.fromhex("14 70")), b"\x00"),
                 ("stage6 callback posts wrong message", 0x1467e3, b"\x06"),
                 ("stage7 requests wrong power mode", 0x13a802, b"\x02"),
                 ("cleanup leaves no-signal screen low byte", 0x10e081, b"\x00"),
                 ("power3 branch keeps system-mode3", 0x0894cc, b"\x03")]
    detected = []
    for name, offset, replacement in mutations:
        broken = bytearray(candidate)
        broken[offset:offset+len(replacement)] = replacement
        completed = subprocess.run(commands + ["--require-no-signal-switch"],
                                   input=bytes(broken), capture_output=True, timeout=60)
        if completed.returncode != 2 or not completed.stderr:
            raise ValueError("Mutation not detected: " + name)
        detected.append({"name": name, "offset": hex(offset), "detected": True})
    # The desired-behaviour check must fail on stock, not only on mutated output.
    red = subprocess.run(commands + ["--require-no-signal-switch"],
                         input=stock, capture_output=True, timeout=60)
    if red.returncode != 2:
        raise ValueError("Stock unexpectedly satisfies the proposed no-signal contract")
    coordinated = validate_coordinated(harness, stock, candidate)
    return {"hardware_access": False, "ready_to_flash": False,
            "writer_accepts_target": False, "candidate": manifest,
            "runs": results, "stock_desired_behaviour_check_failed": True,
            "detected_mutations": detected,
            "coordinated": coordinated,
            "limits": ["FE37 electrical button attribution and live state/event not measured",
                       "Deep cases execute source bookkeeping and USB route orchestration, with transport ACK/poll results injected",
                       "Source cleanup, automatic-search and display follow-up calls remain intercepted",
                       "Fallback cases enter a conditional branch after the external signal/status check; they do not model its delivery",
                       "Key scanning and dispatch share state across a controlled main-loop boundary",
                       "Scanner release executes the real event-2 callback, with delivery manually injected",
                       "Upstream D364 tests intercept alternate UI handlers, screen callbacks and display cleanup; diversion is not proof of a lock",
                       "No runtime state was captured during the corrected DP-unplug reproduction",
                       "Caller cases begin after external source checks and exclude the D706.bit0 display/power path",
                       "Source-loop cases start at 13:894d with injected source flags/states and intercept four source follow-ups",
                       "Sequential tests retain state through manual switch, supplied absent-destination fallback and stage6/7 handlers; they characterize unresolved failures, not a fix",
                       "Stage6/7 callbacks and message dispatch execute with ordered delivery supplied; real scheduler, display cleanup dependencies and power-request effects are intercepted",
                       "Power-mode3 branch executes the real guarded system-mode4 setter with clear flags; the physical transition and full power service are not modeled",
                       "No interrupts, asynchronous signal changes or full fallback engine modeled",
                       "Stack peaks cover all bounded case families, not interrupts or whole-program execution"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("harness", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    stock = read_exact_file(ROOT / "firmware/original/GIGABYTE_M28U_F11.bin", IMAGE_SIZE)
    report = validate(args.harness, stock)
    sources = ["tools/kvm_state_harness.c", "tools/build_kvm_experiment.py",
               "tools/validate_kvm_state.py", "tools/build_sdr_experiment.py",
               "m28u_toolkit/images.py"]
    sources += ["analysis/vendor/emu8051/" + name for name in
                ("emu8051.h", "core.c", "opcodes.c", "disasm.c")]
    report["source_sha256"] = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources}
    report["harness_sha256"] = hashlib.sha256(args.harness.read_bytes()).hexdigest()
    with args.output.open("x") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps({"hardware_access": False, "ready_to_flash": False,
                      "candidate_sha256": report["candidate"]["candidate_sha256"],
                      "cases_per_image": sum(COUNTS.values()),
                      "images": len(report["runs"]),
                      "detected_mutations": len(report["detected_mutations"]),
                      "coordinated_candidate_sha256": report["coordinated"]["candidate"]["candidate_sha256"],
                      "coordinated_cases": report["coordinated"]["run"]["coordinated_cases"],
                      "coordinated_detected_mutations": len(report["coordinated"]["detected_mutations"])}, indent=2))


if __name__ == "__main__":
    main()
