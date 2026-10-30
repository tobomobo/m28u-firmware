# No-signal KVM experiment (offline only)

This branch investigates the disconnected-host KVM-button problem. No monitor
commands or flash writes were sent. The image is deliberately **not accepted
by the live writer**. This is a candidate behaviour, not a confirmed physical
fault diagnosis or a recommendation to flash.

## Evidence and proposed behaviour

Stock F11's event-9 handler at `10:e6c3` requires system-mode getter 3 and
`D11E.bit7` enabled. It has no switching action for screen `0x0026`, the screen
written by the no-signal handler. The scanner reads a candidate active-low input
at `FE37`, translates its raw bit `0x80` to event 9, and passes it through debounce.
The electrical identification of that input is unconfirmed.

The new harness executes those instructions, the main event dispatcher, original
bank gateways, actual mode/per-port getters, KVM binding selection, timer cancel
and timer enqueue/rebase. It retains the scanned event across a controlled
main-loop call boundary. Source-request delivery and USB-mux calls are stubs.
This establishes a software gate, not the state reached by a physical press.

The candidate starts from the existing standby+SDR image. A three-byte jump at
`0x10e6fe` redirects to a 72-byte stub in checked erased padding at `0x10ff00`:

- Keep the existing system-mode and KVM-enable gates.
- Add explicit switching only for the exact screen word `0x0026` and ordinary
  layout (`D143 == 0`). Use the original shared KVM selector and stored bindings.
- Refuse this added path if all 21 timer slots are occupied and none is stage6/7.
- Use the original selector's per-call carry result, preserved by the gateway,
  to distinguish a new request from an old message. After a successful request,
  cancel stages6/7 and request a fresh 60000-count stage6.
- Other screens continue at the original instructions; nonzero layouts retain
  the no-op. No saved setting, Auto Switch flag or backlight code is changed.

The hook and stub change 75 bytes from the installed SDR target, only file
bank 16. Existing standby bank19, SDR bank20 and the AA55 marker remain identical.
The image SHA-256 is:

```text
3cc4a98e4c81a7134de0109076b3eabc7b5ab683be9d19a6d5d88a63bb10b252
```

## Reproduction

With the official pinned F11 file present:

```sh
make test-kvm
python3 tools/build_kvm_experiment.py artifacts/kvm-candidate
```

The output directory must be new. `make test-kvm` never builds or opens a live
transport. It runs 158,315 bounded cases per image against stock, standby, SDR
and the candidate. Coverage includes every 16-bit screen word, every enable-byte
and layout-byte combination, 18,432 binding/pending-message cases, scanner/debounce cases and 72
timer-handoff cases including wrap boundaries and a full timer table with and
without standby entries. Another 63 cases test each of the 21 slots as the sole
free/stage6/stage7 capacity. Stock fails
the proposed no-signal-switch assertion; the candidate passes. Eight deliberately
broken variants must fail. Optimized and ASan/UBSan runs passed; no monitor was contacted.

The final `make check` run passed 134 of 135 tests, with one expected skip for
an excluded vendor trace. The source review used `autoreview --mode local`
(Codex, high reasoning). Its first pass found the stale-message and full-table
bugs described above; both were reproduced, fixed and covered by regressions.
The re-review returned no actionable findings. This is source review and bounded
firmware execution, not hardware acceptance.

These are test cases, not unique real-world states. Synthetic inputs are not
proof that a state is reachable on the monitor. Peak stack in the gate matrix
was 114 in both images; this is not an interrupt-stack or whole-program proof.
The pre-existing standby and SDR images produce identical results to stock in
this bounded KVM test, so it supplies no evidence that those patches caused the
original issue.

## Before a flash decision

Still unresolved:

1. Whether the real disconnected-host button delivers event9 with system mode3,
   KVM enabled and screen26; the stuck case may involve another gate or sleep.
2. The complete asynchronous source-detection/fallback loop and physical USB
   routing, including pending messages and interrupt/timer-delivery interleavings.
3. Deliberate writer integration if the experiment is justified, including the
   additional changed bank and complete-image verification. The present
   writer refuses it before opening a device; changing hashes alone is insufficient.
4. USB-only failed-boot recovery remains unproven, as for the existing patches.

Gigabyte's manual describes falling back when the selected destination has no
signal. This candidate does not remove that fallback or enable Auto Switch.
A live acceptance test would need both directions, destination present/absent,
short/held presses, OSD lock/menu states, standby expiry and return to video.
No successful flash is claimed here.
