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

COUNTS = {"scanner_cases": 32, "gate_cases": 8640, "timer_handoff_cases": 72, "timer_capacity_cases": 63,
          "binding_cases": 18432, "scanner_dispatch_chain_cases": 4,
          "screen_word_cases": 65536, "enable_layout_cases": 65536,
          "source_route_cases": 1920, "fallback_cases": 1536}


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
                report.get("route_transport_stubbed") is not True or
                report.get("candidate_expected") != (name == "kvm")):
            raise ValueError(f"Unexpected {name} harness result")
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
                 ("fallback snapshot address wrong", 0x138b12, b"\x00")]
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
    return {"hardware_access": False, "ready_to_flash": False,
            "writer_accepts_target": False, "candidate": manifest,
            "runs": results, "stock_desired_behaviour_check_failed": True,
            "detected_mutations": detected,
            "limits": ["FE37 electrical button attribution and live state/event not measured",
                       "Deep cases execute source bookkeeping and USB route orchestration, with transport ACK/poll results injected",
                       "Source cleanup, automatic-search and display follow-up calls remain intercepted",
                       "Fallback cases enter a conditional branch after the external signal/status check; they do not model its delivery",
                       "Key scanning and dispatch share state across a controlled main-loop boundary",
                       "No interrupts, asynchronous signal changes or full fallback engine modeled",
                       "Timer enqueue/cancel/rebase instructions execute; timer delivery remains outside scope"]}


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
                      "detected_mutations": len(report["detected_mutations"])}, indent=2))


if __name__ == "__main__":
    main()
