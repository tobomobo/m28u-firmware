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
main-loop call boundary. Most gate cases stub source requests and USB routing;
the deeper cases below execute their bookkeeping and routing orchestration,
intercepting the lower-level transport and named follow-up calls.
This establishes a software gate, not the state reached by a physical press.

### Corrected physical observation (2026-10-30)

The owner manually selected Linux DisplayPort from Mac USB-C, then disconnected
the selected DisplayPort cable. Neither switching back with KVM nor opening the
OSD worked. Mac USB-C was still connected at the initial failure; subsequently
disconnecting it did not restore OSD access. Whether the Mac was awake is unknown.
Auto Switch was disabled. This supersedes the earlier answer that the monitor
was already in standby: the power/system state when the failure started is not
established. No runtime flags, key events or USB traffic were captured.

The owner subsequently clarified recovery: restarting the PC connected through
DisplayPort restored operation. Reconnecting/removing the Mac cable had not
resolved it. The owner reports that manual switching requires a live reachable
source. The reboot restored usability, but it does not tell us which firmware
flag, link-training state or other PC/USB state changed.

The follow-up timing answer was initially "both windows" (first 10 seconds and
60–75 seconds after disconnecting selected DP with the Mac awake). The owner
immediately qualified this as a belief, not a certain result. The timing of
the physical failure therefore remains unconfirmed; it must not be used to
attribute the failure to either the pre-standby or power-saving path.

The intended behaviour is explicit: keep the selected input through a reboot
or video gap while Auto Switch remains disabled, and accept a manual KVM-button
request even when that selected input has no signal. Loss of signal alone must
not be treated as a manual request. USB routing must follow an accepted manual
request. This is a behaviour requirement, not an assertion that it is achieved.

The candidate only adds a KVM action. It does not restore the ordinary
OSD actions described below, and is not a demonstrated fix for this observation.

The candidate starts from the existing standby+SDR image. A three-byte jump at
`0x10e6e8` redirects to an 88-byte stub in checked erased padding at `0x10ff00`:

- Keep the existing system-mode and KVM-enable gates.
- Add explicit switching only for the exact screen word `0x0026` and ordinary
  layout (`D143 == 0`). Use the original shared KVM selector and stored bindings.
- Also allow the exact normal screen word `0x0000` in ordinary layout when the
  original per-port getter returns 1 or 2. The source/UI routine arms stage5 for
  state1 and posts message3 for state2. These paths are not proof of their
  physical reachability during the owner's failure. All other normal-screen
  states retain the original handler; state4's existing action stays intact.
- Refuse this added path if all 21 timer slots are occupied and none is stage6/7.
- Use the original selector's per-call carry result, preserved by the gateway,
  to distinguish a new request from an old message. After a successful request,
  cancel stages6/7 and request a fresh 60000-count stage6.
- Other screens and layouts continue at the original instructions. No saved
  setting, source-search setting or backlight code is changed.

The hook and stub change 91 bytes from the installed SDR target, only file
bank 16. Existing standby bank19, SDR bank20 and the AA55 marker remain identical.
The image SHA-256 is:

```text
0efa1e75e9a1ecd5f4d12623fac64d018f75ea40579db1046b630fecce0bc64f
```

## Reproduction

With the official pinned F11 file present:

```sh
make test-kvm
python3 tools/build_kvm_experiment.py artifacts/kvm-candidate
```

The output directory must be new. `make test-kvm` never builds or opens a live
transport. It runs 403,799 bounded cases per image against stock, standby, SDR
and the candidate. Coverage includes every 16-bit screen word, every enable-byte
and layout-byte combination, all 65,536 normal-screen source-state/layout pairs,
18,432 binding/pending-message cases, scanner/debounce cases and 216
timer-handoff cases including wrap boundaries and a full timer table with and
without standby entries. Another 189 cases test each of the 21 slots as the sole
free/stage6/stage7 capacity. Stock fails
the proposed no-signal-switch assertion; the candidate passes. Twenty-eight deliberately
broken variants must fail. Optimized and ASan/UBSan runs passed; no monitor was contacted.

The final `make check` run passed 134 of 135 tests, with one expected skip for
an excluded vendor trace. The source review used `autoreview --mode local`
(Codex, high reasoning). Its first pass found the stale-message and full-table
bugs described above; both were reproduced, fixed and covered by regressions.
The re-review returned no actionable findings. This is source review and bounded
firmware execution, not hardware acceptance.

These are test cases, not unique real-world states. Synthetic inputs are not
proof that a state is reachable on the monitor. The earlier gate-only peak was 114 in both images. Per-family reporting now
includes the deeper source/USB paths; see the review follow-up below. Neither
measurement is an interrupt-stack or whole-program proof.
The pre-existing standby and SDR images produce identical results to stock in
this bounded KVM test, so it supplies no evidence that those patches caused the
original issue.

## Source and USB handoff follow-up

Another 1,920 cases execute the original source request (`04:ea2f`), source
assignment (`04:eed8`), source-map lookup/getter and USB routing (`14:7743`).
They cover both directions with the owner's binding byte `0x12`, all 24
permutations of a synthetic four-input map, both values of `D151.bit0` and
`FE2C`, both previous USB routes, and success/failure at each of the two
transport writes and two completion polls. These synthetic tables are not a
capture of the monitor's runtime table.

The tests assert the requested source and its getter result, cleared per-port
state, preserved old-source snapshot, exact route-register writes, transport
arguments/payloads, early-return behaviour and standby handoff. In the candidate,
480 cases take the stock already-routed early return; 288 complete both writes
and polls. The other 1,152 stop at an injected transport failure. No traffic is
sent to a monitor.

The selector's carry result means **a source request was made**. The original
helpers set carry after the USB routine even if that routine failed; the patch
does not turn that result into a hardware acknowledgement or add retries.

Another 1,536 cases enter the stock conditional fallback branch at `13:8adf`
after its external signal/status test. All four images produce the same result:
256 post a request for the saved previous source, 256 call the automatic-search
follow-up, and the rest do neither. The direct return-to-previous-source branch
at `13:8b0b` does not itself call USB routing. Later processing may still do so;
this does not prove that picture and peripherals recover together.

The deeper tests intercept source cleanup (`04:c9a3`), automatic search
(`04:febb`), source follow-ups (`28c1`, `28cd`, `28d3`, `1325`), transport writes
(`043a`) and completion polls (`2e97`). They do not execute a complete monitor
main loop or generate the external status event that reaches fallback. Four
additional mutations drop source assignment, drop a route-register write,
ignore a route error, or misaddress the fallback snapshot; each must fail.

This follow-up does not change the candidate bytes, builder or writer. It
reduces the earlier stub boundary; it does not establish physical acceptance.
The optimized and ASan/UBSan reports agree on all four runs and record matching
source hashes. A separate `autoreview --mode local` of this three-file test
extension returned no actionable findings.

## Shared key path follow-up

The corrected observation prompted another 172,060 bounded cases per image:

- **172,032 dispatcher cases:** all 16 system-mode nibbles, all 256 `D364`
  bytes, six synthetic per-port states and events 0..5/9, with screen `0x0026`.
  Original instructions from `13:8c9c` through return execute. `D364.bit2`
  diverts to `305f`; otherwise bit3 diverts to `3065` when per-port state is
  not 4. These are alternate UI handlers, not established physical lock flags.
  Their bodies and final display cleanup remain intercepted. Modes 0/1/2/5
  skip this dispatcher. The KVM candidate preserves those decisions.
- **Ordinary keys:** whenever normal dispatch is reached on screen26, all six
  callback selections point to `13:feff`, a single `RET`. The harness checks the
  selected address and that opcode, without executing the callback body. This
  is present in stock, standby, SDR and the research KVM candidate. In the
  selected state, menu keys can do nothing even if scanning itself works.
- **12 scanner sequences:** the one-scan suppression bit clears and does not
  itself persist. With the pacing flag initially clear, four consecutive scans
  remain blocked until event2 is delivered. The original callback dispatcher
  `14:6731` with argument2 sets `D369.bit0`, after which the actual scanner
  resumes. Callback delivery is manually injected; the real timer scheduler,
  elapsed time and event-loss behaviour are not modeled. This does not show a
  missing timer on hardware.
- **16 wake-helper cases:** at `0b:fe1b`, only a rising raw `0x02` in injected
  power-getter mode1 requests mode2 through `2e7f`. Raw `0x80` does not take
  that wake path. Neither the physical identity of raw02 nor a physical standby
  mapping for mode1 is proven here; the request's side effects are intercepted.

Four additional mutations remove the release callback, change the wake-input
bit, change a diversion flag bit or redirect a no-signal menu callback. Each
must fail. These are tests of the new seams, not additional firmware patches.

This narrows three distinct possibilities: an intentionally inactive no-signal
menu, delayed scanner release, or a diversion before the KVM handler. It does
not identify which state occurred after physical DisplayPort removal. In
particular, the harness does not model the full signal-processing transitions.
The timer/message chain shows how the standby change prolongs screen26: stage6
is armed for 60000 counts rather than 5000, then its message clears the screen
word and arms stage7 for another 1000 counts before requesting power mode3.
The six screen26 menu callbacks remain inactive during that first phase.
Whether the owner's physical failure occupied that phase has not been established. Do not bypass the gates based on these
synthetic cases alone. Candidate bytes and live writer policy are unchanged.

### Earlier caller gates

A further 4,096 cases enter two conditional callers at `13:8a84` and `13:8bf4`,
after their external source checks. They execute the original `3041` helper
(`08:d92c`) and its timer enqueues, the caller's next flag test, and any subsequent
dispatch. They vary all 128 `D706` bytes with bit0 clear, normal/no-signal screens
and events 0..5/8/9. The per-port state is injected as 2, system mode as 3.

- With bit1 set, `3041` returns carry set and the caller returns before key
  dispatch. If bit2 is clear, that helper also enqueues immediate stages5/7.
- With bit1 clear and bit2 set, `3041` returns carry clear, but the caller's
  separate bit2 test still skips key dispatch.
- With both bits clear, dispatch is reached. Event8 makes no KVM request; the
  candidate's no-signal event9 path can make the request. All four images keep
  `D706` and `D11F` unchanged in these cases. This does not establish which saved
  field corresponds to the physical Auto Switch setting.

The blocked cases check the enqueue count, exact stage5/7 identifiers and
deadlines equal to the current synthetic counter. Other blocked combinations
must leave the empty timer table empty. Five added mutations change a caller
flag operand, ignore the helper's carry, change the helper's flag operand,
remove a stage5 enqueue or change stage7 to stage6. Each must fail. Bit0's separate display/
power-handling branch, the external conditions selecting these callers and
the full signal-loss/recovery sequence remain outside this seam.

This establishes another reason the candidate is insufficient for an
unconditional manual-switch promise: some caller states do not reach its hook
at all. It does not establish that these flags caused the observed failure,
and none of the flags is bypassed by a new firmware patch.

### Source/UI entry and the normal-screen gap

The original experiment handled only screen26. A new test first failed against
that image (`3cc4a98e...`) with `Source-loop manual-only request / USB handoff
mismatch`: on normal screen0, source states1/2 still rejected a scanned event9.
The current candidate moves the hook earlier within the same event9 handler,
after its existing mode/enable checks, and adds just these two states. It does
not bypass the earlier caller or alternate-UI gates.

Another 64 cases now run the actual scanner and retain its event into entry
`13:894d`, before the real `302f` helper selects its branch. They vary the
injected source bit6, source state1/2, both DP/USB-C directions, press/no press,
normal/no-signal screen and both values of `D11F.bit1`. They execute the source
count/state getters, caller branches, dispatcher, selector, source assignment
and USB route orchestration. All three added action paths also run the timer
handoff/capacity checks above.

The patched cases require a request and both USB writes/polls only with a
scanned press, in both screens and both directions; a source flag change alone
must leave the selected input and USB route untouched. `D11F` and `D706` must
remain unchanged. This validates a bounded manual-only path without establishing
which bit is the physical Auto Switch setting.

External source detection and four named follow-ups (`2e91`, `2beb`, `3035`,
`3047`) are intercepted, as are the already documented display/USB transport
dependencies. In particular, this does not execute the source-settings
persistence behind `3047`, a whole firmware loop or a physical unplug event.
`D706` is supplied as zero; earlier tests still exercise its blocking values.

Static tracing gives a separate origin for those flags: `08:6d18` accepts a
`CEBF=C0`, `CEC0=63` command and dispatches selector `CEC2=AA` to `08:6e4c` /
`08:d9e3`. Parameter `CEC4=1/2` sets `D706.bit2` and bit1; value1 also sets bit0.
This is evidence of a vendor-command path, not a complete inventory of writers,
an attribution to Auto Switch, or proof that the flags were clear on hardware.
It gives no justification for globally clearing or bypassing them.

Three added mutations change the source bit6 test, the normal-screen state
guard, or remove state2 support. Each must fail. The candidate remains offline;
ordinary no-signal OSD callbacks and standby wake behaviour are still unchanged.

The earlier optimized and ASan/UBSan validations agree on all 403,797 cases per
image, all 24 detected mutations and the recorded source hashes. `make check`
passes 134 of 135 tests, with the optional vendor trace skipped. A scoped
`autoreview --mode local` of the four changed source/documentation files found
no actionable correctness or security defect, including in the moved hook and
its original continuation. These are offline checks, not device acceptance;
the live writer still refuses this candidate before opening a transport.

## Broad implications review and sequential follow-up

An independent Opus 5.5 review (high effort) decoded the entire 88-byte stub and
checked it against the adjacent derived assembly. It found no code blocker in
the hook, register use or original continuation. It did not rerun the suites
or contact hardware. It identified important gaps in the single-pass evidence.
The firmware candidate and writer remain unchanged while those gaps are studied.

Two new continuous sequences, one per switching direction, now retain XRAM
through a scanned press, a supplied destination-state1 result, the original
fallback branch, ordered stage6/7 delivery, and another scanned press. They
execute the real callback dispatcher, message dispatcher, no-signal screen
cleanup and timer cancel/enqueue instructions. All 21 timer slots are checked
for active identifiers/deadlines, including an unrelated already-due sentinel
whose delivery is withheld. Empty-slot deadline bytes have no scheduler meaning.
The scheduler's actual delivery, external signal readiness, named display-cleanup
dependencies and the physical effects of the power request remain intercepted.

The sequences characterize two unresolved behaviours of this candidate:

- **Absent destination:** the selector records the previous source in `D378`
  and sets `D377.bit2`. When the supplied destination state becomes1, the
  original fallback requests the previous input without another USB route call.
  The model ends with the input selection back at its origin and the USB-route
  state still on the destination, in both directions. Later unmodeled firmware
  work might reconcile them. The tests do not establish a lasting physical split.
- **After timeout:** stage6 posts message5; `10:e062` clears the screen word and
  message5 arms stage7 for 1000 counts. Stage7 posts message6 and requests power3.
  Before the power service runs, `D8E0` remains 3: a second manual press can
  request an input but does not retract the captured power3 request or ask to
  wake. Separately, `08:9496` selects `08:94c1` for power getter 3; that branch
  invokes the real guarded mode setter `08:dfac` with 4. With its flags clear,
  the test reaches system-mode4, where a subsequent scanned KVM press makes no
  request. The mode setter can refuse with other flags. This is a conditional
  code path, not a measurement of the monitor's state after shutdown.

The other `D8E0` writers do not establish a general wake fix: `04:fa61` changes
only its high nibble, while `00:dab7` sets its low nibble to 5 during a larger
initialization path. `08:dfac` sets the low nibble only when the high nibble and
four pending flags allow it. Bypassing the handler's mode3 guard would therefore
be unjustified; source switching and waking require a policy at the power/UI
boundary, rather than just another accepted screen number.

The existing 64 source-loop cases now check the entire active timer table.
State1's stage5 survives an accepted switch, with its original 2000-count deadline;
state2 posts message3 which the selector overwrites with 0x0a in the same pass.
The fresh stage6 is intentional in that path. Whether a subsequent physical
signal lock cancels all relevant timers is still untested. The binding cases
also assert that a rejected destination can leave `D375.bit0`, the snapshot and
the stock pending flag set even though carry is clear. No new policy clears
these flags or removes stock fallback.

Stack peaks are now recorded for every case family. Screen25 additionally
asserts its original cleanup continuation. Four new mutations corrupt stage6's
message, stage7's power argument, cleanup of the screen low byte or the power3
branch's mode argument. Each must fail. The sequential assertions deliberately
preserve evidence of the candidate's shortcomings; a green run does not mean
those behaviours are fixed.

The follow-up optimized report (`artifacts/kvm-validation-1793376677.json`) and
ASan/UBSan report
(`artifacts/kvm-investigation/validation-broad-review-sanitized.json`) agree on
all source hashes, all run dictionaries, the unchanged candidate identity and
all 28 rejected mutations: 403,799 cases per image across four images. The
bounded peak SP is 122 for the candidate (source-loop, source-route and
sequential families), versus 114 across the tested stock families. Stock does
not execute the same deep route from screen26, so this is not a measured
8-byte increase for equivalent production call paths. The gate-only peak stays
114. `make check` ran 135 tests: 134 passed and the optional vendor trace was
skipped. No monitor command or flash was sent.

## Second candidate: coordinate manual selection and power (2026-10-30)

The first candidate above is retained as a control. A separate second candidate
starts from the installed standby+SDR image, without the bank16 hook. Its
three-byte hook at `13:8c9c` redirects to 197 bytes of checked padding at
`13:ff00`. It changes 200 bytes, all in bank19; the existing standby timer
change in that bank and the SDR change in bank20 remain intact. SHA-256:

```text
be7c06f2399f57060f86e53828c6ee079141551ea48b1e2f982f8465689cc5ef
```

This is still an offline hypothesis. It does not establish which state the
physical failure occupied, restore general OSD operation, or bypass earlier
source/UI callers. The dispatcher must actually be reached with event9.

The added path accepts ordinary-layout, enabled KVM on screen26 or screen0
with source state1/2 in system-mode3. It also accepts screen0 in settled
system-mode4 when the original power getter returns3. That last case is the
specific power-saving path, not arbitrary modes or explicit power-off. It
preserves alternate-UI flags `D364.bit2/3`, captured/vendor flags `D706.bit0/1/2`
and bit-address50, which the stock VCP standby command sets. Rejected cases
replay the displaced getter and run the original dispatcher. Every added path
also refuses queued power request1 and requires actual power getter2/3. This
catches explicit off before the system has left mode3, as well as already-off
hardware. The original active-picture handler remains unchanged.

After the existing selector accepts a request, the second candidate:

1. Replaces the old fallback snapshot at `D378` with the newly selected source.
   The pending flag remains, so the successful-lock follow-up through `f660`
   still runs. If the tested absent-signal fallback occurs, it requests the
   same new target; picture selection and the existing USB route stay together.
2. Cancels stages5/6/7 and arms a fresh 60000-count stage6, after first checking
   the queue has a free slot or a reusable stage5/6/7. An unrelated full queue
   refuses without a switch. The original timer code performs any rebasing.
3. Uses the original power-request API `2e7f` with2. The stock VCP power-on path
   also uses this request (`00:5b40`). It replaces pending request3. The stock
   service at `00:aa5a` then clears saving flag `D8D5.bit5` and calls action11.
   The actual public getter returns2 afterwards in the bounded test. The
   source setter itself requests its original mode4 transition via `04:fa61`;
   the stub does not force a system-mode value or clear transition flags.

`make test-kvm` includes 38 focused cases for this candidate, in addition to the
first candidate's tests. The focused loop executes scanner, dispatcher, binding
selection, source bookkeeping, USB orchestration, request API and the relevant
stock power-service branch. It covers both directions, screen26, screen0
states1/2, power saving, absent-destination fallback, no press, the original
active-picture action and refusal controls. A full table with only a stage5
slot reusable is covered. Twenty-two mutations must fail; stock and candidate1
must fail the new retained-destination assertion. Its bounded peak SP is120.

Transport ACKs/polls and physical power action11 are intercepted. Source
detection, the remaining power/system service, interrupts and the full main
loop are not reproduced. Consequently the test proves the request and flag
handling at these boundaries, not that a physical monitor wakes successfully.
In particular, USB routing runs before the wake request is serviced; access to
the USB controller while the physical monitor is saving power is unproven.
No hardware command, flash, writer permission or saved setting was changed.

The source review found an explicit-off gap in the initial second candidate:
its mode3 paths could replace request1 with wake2. A new regression failed on
that candidate, then passed after adding the common power guards. It covers
`D8D4=21` (off queued while hardware is active), `11` (off requested/current)
and `1f` (off with no pending request) in each added mode3 screen/state path.
This is an in-scope preservation fix; it does not enable additional states.

Build separately, offline:

```sh
python3 tools/build_kvm_experiment.py --coordinated artifacts/kvm-coordinated-candidate
```

At this offline checkpoint both research images were rejected by the writer.
The bounded candidate2 integration below supersedes that boundary; candidate1
remains unsupported. Neither physical KVM behavior nor USB-only failed-boot
recovery is established by the offline tests.

Validation of the explicit-off correction is recorded in
`artifacts/kvm-validation-1793378548.json` and
`artifacts/kvm-investigation/validation-coordinated-off-guard-sanitized.json`.
The optimized and ASan/UBSan focused runs agree on source hashes, candidate,
all 38 cases and all 22 rejected mutations. The first candidate remains
unchanged and its existing four-image suite passes. `make check` ran 136 tests:
135 passed and the optional vendor trace was skipped. The build artifact is
`artifacts/kvm-coordinated-off-guard-candidate/`.
The focused Codex source re-review reported no accepted/actionable findings
after the explicit-off correction. This review did not access hardware and
does not establish physical wake, routing or failed-boot recovery.

## Before a flash decision

Still unresolved:

1. Whether the real disconnected-host button delivers event9 with system mode3,
   KVM enabled and screen26 or normal screen0/state1/2; the stuck case may
   involve another gate or sleep.
2. The complete asynchronous source-detection/fallback loop and physical USB
   routing, including pending messages and interrupt/timer-delivery interleavings.
3. Writer integration must retain exact target pins, installed-image identity,
   bank16 rejection of candidate1, full byte verification and rollback support.
   The bounded integration below implements these requirements.
4. USB-only failed-boot recovery remains unproven, as for the existing patches.

Gigabyte's manual describes falling back when the selected destination has no
signal. Candidate2 keeps the pending flag and lock follow-up, but updates the
fallback snapshot to the explicitly selected destination so the request sticks.
It does not enable Auto Switch.
A live acceptance test would need both directions, destination present/absent,
short/held presses, OSD lock/menu states, standby expiry and return to video.
The later programming result is recorded below; physical KVM acceptance is separate.


## Bounded writer integration (2026-10-30)

Only candidate2 SHA-256
`be7c06f2399f57060f86e53828c6ee079141551ea48b1e2f982f8465689cc5ef`
is selected by `writer --kvm-coordinated PINNED_IMAGE`. Stock-only and SDR
selectors are mutually exclusive with it. The loader checks the full image
hash, unchanged bytes outside banks19/20 and the exact two changed bank hashes.
No injected firmware byte changed for writer integration.

Before any nonvolatile write, the live preflight reads complete banks16/19/20
and ten saved-array samples. Bank16 must match stock, rejecting candidate1 and
stacked stubs. Only stock, standby, SDR-cap540 and coordinated-KVM bank pairs
are recognized; coordinated bank19 paired with stock bank20 is refused. This
is bounded installed-image recognition, not a complete live-image backup.
The original two matching 4 MiB backups remain mandatory.

Synthetic runner tests exercise installation from SDR and rollback from KVM to
SDR, standby and stock through Fake, Linux and native dry-run transports. They
assert full target byte equality, unchanged factory/trailing regions, original
protection restoration, marker-last commit, reset and normal-mode checks.
Unknown bank pairs and either obsolete/stacked bank16 stub must stop before
arming or writing, then reset. The existing erase/program transport and its
post-SETUP checks are unchanged. A live flash remains a hardware experiment.


## First coordinated programming result

On 2026-10-30 the exact pinned candidate2 was programmed on the research M28U
in 1716.28 seconds. All image bytes were verified, AA55 committed last, original
protection restored, and a fresh normal-mode connection returned F11. The saved
full image independently matches the target hash. See [findings.md](findings.md).
The user confirmed automatic picture and keyboard/mouse recovery without a
manual power cycle. No physical KVM switching acceptance result is available yet.
Test explicit switching with
Auto Switch off in both directions, first during the no-signal window and again
after 75 seconds, with the destination awake and connected. Separately test a
sleeping/missing destination and later return of video; do not infer those cases
from a successful switch to an already active destination.
