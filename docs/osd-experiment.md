# No-signal OSD experiment

Status: **offline preparation only; no OSD flash or device commands**. This is
partial reverse engineering of exact F11, not Gigabyte firmware source.

## Cause and proposed behavior

The ordinary joystick/confirm key is event0. On the no-signal screen `0x26`,
its callback is a bare `RET`. Replacing that table entry alone does not fix
the issue: the normal opener also rejects a source without an active picture.
Both failures are reproducible by executing the original 8051 instructions.
The installed coordinated KVM image fails the same OSD control.

The candidate adds a narrow path before the original key dispatcher. An explicit
event0 may open the stock quick menu on screen26, or screen0 with source state1/2
in system-mode3. It also handles settled saving mode4/screen0 when the public
power getter reports3. The ordinary main-menu callback remains reachable.

OSD lock, alternate UI/event ownership, forced standby, explicit off, nonordinary
layout and transient system modes keep their original paths. Other keys pass
through the existing KVM stub. Opening the menu requests power2 through the
original power API; it neither selects a source nor routes USB nor saves settings.
It clears only already-posted no-signal messages1..6, cancels stale stages5..7
and rearms the inherited stage6 delay for 60000 counts. Two reusable timer slots
are required before opening: standby6 and ordinary menu timeout8. The stock
post-key continuation still schedules/refreshes the menu timeout.

A second hook prevents stage6 from closing an actively timed menu. It defers
only in mode3, ordinary layout, screen1..0x24, source1/2, with stage8 present.
Without that last condition, stock's timeout behavior for source2 could leave a
stale menu that kept delaying standby indefinitely. Once stage8 is gone, the
ordinary stage6/7 chain can close that stale screen and request saving again.
This is not a promise that the complete stock timeout/input-selection behavior
is ideal; only the new indefinite-deferral interaction is avoided.

## Exact changes

Base: coordinated KVM + SDR-cap540 + standby, SHA-256
`be7c06f2399f57060f86e53828c6ee079141551ea48b1e2f982f8465689cc5ef`.

Candidate SHA-256:
`35cc2389ad919154fa12b31ebc70711b2e8184aeee03c06fc4f212b05923ebad`.

- Dispatcher `13:8c9c`: jump to `13:5582` instead of existing KVM entry `13:ff00`.
- Stage6 message handler `13:a7c3`: jump to helper `13:564c`; refused cases
  replay the displaced `MOV DPTR,D143` and continue at `13:a7c6`.
- 281 bytes in checked erased padding `13:5582..5716`; table starts at 5717.
  284 bytes differ from the coordinated base, exclusively in bank19.
- The existing 197-byte KVM stub, SDR bank20, marker and all other banks remain
  byte-identical to that base.

The padding lies in a common **address range**, but is bank19-local. Other
banks at those addresses are not patched. Original bank gateways return to
bank19; the harness checks bank restoration and stack boundaries. The derived
recursive map contains no incoming static edge to that interval and no mapped
bank19 code/DPTR reference there. Other banks have 25 DPTR references into the
same numeric range. This is bounded static evidence, not a proof that every
indirect/computed reference has been found.

## Reproduce offline

Obtain the pinned public F11 as described in the root README; no firmware or
device captures are distributed in Git.

```sh
make test-osd
python3 tools/build_osd_experiment.py artifacts/osd-candidate
make check
```

The validator first confirms an active-source menu opens on stock and the
installed KVM image, while their no-signal menu checks fail. It then executes
the candidate and rejects deliberately broken event/lock/off/capacity/message/
cancel/wake/continuation/timer variants. The retained 38-case coordinated KVM
suite must also pass.

The harness executes original menu openers, callback selection, main-menu
entry, close-key callback, timer APIs and stage6/7 message handlers. It checks
screen state, deadlines, unrelated timer preservation, source/USB/settings
write boundaries, bank restoration and bounded stack use. Rendering/mixer
helpers and the physical wake action are intercepted. Timer delivery order
and initial key events are supplied. Complete main-loop/interrupt execution,
full input-picker navigation and a visible signal-less panel are untested.
Optimized and ASan/UBSan runs are separate from physical acceptance.

## Prepared writer boundary

`writer --osd-no-signal PINNED_IMAGE` selects only the exact full-image and
bank19 hashes, paired with the existing SDR bank20 and stock bank16. Unknown
targets are refused before opening a transport. Installed identity checks use
complete banks16/19/20 and the existing ten saved-array samples; they are not
a new full-device capture. Synthetic installs and rollback to coordinated
KVM, SDR, standby and stock must pass through Fake, Linux and native dry-run.
The erase/program protocol, protection restoration and marker-last commit are
unchanged. Default writer invocation stays offline.

No live preflight or programming was run for this candidate. A future hardware
session would need explicit authorization, source-free menu visibility and
input selection checks before/after saving, and return of picture/KVM.
USB-only recovery after a failed boot remains unproven. Builder metadata stays
`ready_to_flash:false`: source review and a generated file cannot certify a monitor.
