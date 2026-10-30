# Findings and evidence

## Why these changes

The M28U dropped into standby during short video gaps, disrupting boot and
monitor-connected peripherals. Its OSD has no suitable delay setting. SDR also
has a lower maximum backlight control than an existing HDR/factory path.
We investigated narrow patches instead of replacing the firmware or changing
the whole display pipeline. The reverse engineering is partial.

## No-signal standby

In exact F11, the setup at bank `13:a79b` contains:

```text
Image offset    Stock    Patched
0x13A79E        88       60
0x13A7A0        13       EA
```

Together these instruction operands change 5000 (`0x1388`) to 60000 (`0xea60`).
The original scheduler instructions were exercised offline across all 16-bit
counter values and three table states: 393,216 cases. That checks arithmetic,
not real-time units or interrupt behaviour. The owner observed a wait well
beyond five seconds after disconnecting USB-C; a timed 60-second test is absent.

A display delay does not guarantee USB host retention. Disconnecting USB-C
removes the Mac's USB data link. Peripheral lights show power/activity, not
proof of a working upstream connection. The disconnected-host KVM button
behaviour was inconsistent; its stock baseline is unknown and auto-input
switching was disabled. We have not established or fixed that issue.

## SDR backlight

The ordinary path feeds a 10-bit value into an AS382x-compatible backlight
register sequence. The [AS3820 datasheet](https://www.mouser.com/datasheet/2/713/as3820_datasheet-1816156.pdf)
identifies registers 0x0c/0x0d as VDAC_H/L and describes a proportional DAC output.
The physical driver variant is not confirmed. This attribution is supported by
instruction traces, packing and stock mode values, not a symbol named “brightness”.

Stock ordinary SDR uses **48–405**. An HDR + Local Dimming / factory path uses
**643**. Timing values suggest the ordinary PWM is already at full duty, so
raising the current-control DAC is the plausible remaining lever. Higher stock
values support that interpretation, but do not establish a safe continuous SDR limit.

The patch changes `LCALL 982c` at `0x148d8f` to `LCALL c000` and places an
81-byte routine in erased padding at `0x14c000`. It uses the existing multiply,
divide and output-packing helpers:

```text
if ordinary mode, ordinary layout, saved dimming off, and argument in 48..405:
    argument = 48 + floor((argument - 48) * 164 / 119)
continue through the original output helper
```

Existing mode predicates and stub guards preserve HDR, strobe, saved Local
Dimming and nonzero-layout paths. The stored slider and colour-processing
instructions are unchanged. This avoids the broader effects of changing the
shared brightness formula. It does not prove optical colour accuracy is identical.

At slider 100, 405 becomes 540: **+33.3% in control value**. The choice was
`405 × 400/300`, assuming proportional output and a 300-nit starting point.
[Reviewed.com](https://www.reviewed.com/gaming/content/gigabyte-m28u-review)
reported 286.2-nit SDR and 453-nit HDR; using that SDR baseline gives 381.6 nits.
Thus **about 380–400 nits is calculated, not measured on this monitor**.
No colorimeter, LED-current measurement or thermal endurance result is available.
DisplayHDR 400 support does not certify this modified continuous operating mode.

The [community brightness workaround](https://github.com/seerge/m28u_brightness)
and [discussion](https://www.reddit.com/r/Monitors/comments/10veh76/guide_500_nits_on_gigabyte_m28u/)
report roughly 500–520-nit SDR through old-firmware/settings transitions, often
with a disabled slider and dynamic dimming. A plausible mechanism is a stale
preset field: F03 uses 31 with divisor 31, later versions use 7 with divisor 7.
Stale 31 under the later calculation gives `(405*31/7)&1023 = 769`.
We verified the arithmetic and relevant profile paths offline, not those users'
actual migrations. Factory VCP commands were investigated but are not offered
as a shortcut: their exit/persistence effects are unresolved.

## USB writer

The Windows utility revealed vendor HID packets that bridge to scaler I²C
registers and SPI flash operations. The observed chip ID is `c8 40 16`.
The writer permits only the F11 update region `0x200000..0x3affff` and known
image hashes. Lower factory firmware and trailing storage are outside its
write range. Status/GPIO protection is restored; the AA55 boot marker is
committed last after verification. This ordering reduces exposure, but is not
a proven factory-fallback or recovery mechanism.

A hardware finding mattered: burst register reads repeat the selected register;
0x64, 0x65 and 0x66 must be read separately. The 0x70 data FIFO does advance.
Both Python/Linux and native macOS guards implement this distinction. Before
unlocking write protection, the programming path checks CRC, status, marker and
a full unchanged bank after the vendor's volatile SETUP writes.

On a possible write failure, the runner holds ISP instead of blindly resetting.
There is no implemented resume path. Keep power stable and do not interrupt a
programming session. USB-only recovery after a failed boot remains unproven.

## Recorded acceptance

On 2026-10-30, one M28U completed the SDR + standby flash from macOS:

- Full 1,769,472-byte update-region readback matched the pinned SDR image.
- 28 bank-verification events, marker commit and protection restoration completed.
- Fresh normal/source/F11 responses followed reset. Its USB acknowledgement
  errored, but fresh responses and user observation confirmed normal return.
- Picture, keyboard and mouse returned automatically without a power cycle.
- Total session: 1696.872 seconds; programming/verification after preflight:
  1634.549 seconds. Readback throughput was about 2.67 KiB/s.
- Owner confirmed SDR at slider 100 and tentatively reported a brighter picture.

This is one-device acceptance, not a compatibility or lifetime claim. Factory
and trailing storage were sampled before flashing, not fully recaptured afterward.
The greyed-out OSD “Display Mode” observation remains uninvestigated.

Before that session, 132 offline Python tests passed with firmware/native inputs
present. Bounded original-instruction harnesses checked 517,120 output cases,
65,536 direct arguments and 65,536 buffer cases; separate banked-call checks
covered 80,080 cases per image. Reviews and synthetic fault models found and
corrected CRC-mode, address-readback, buffer-ordering and post-SETUP gaps.
These are bounded checks, not a complete monitor emulator or electrical proof.
Raw captures and host-specific review logs remain outside this repository.

## Reproducible image identity

All images are 1,769,472 bytes. Bank numbers above are hexadecimal when used
with an address (`14:c000`); file bank indices are decimal (bank 20).

```text
Stock F11
1ff616f5adcebf5057bd33405709757a68918b3cbfc0fabcad109e8a0a8128d0
Standby-only (two bytes changed)
232e6c0395c77b7332e6f2f1fbf46680be325205937e94e2f74a879745de7f28
Standby + SDR (82 bytes changed from stock; 80 from standby)
abe1e110fcb0feed0aa47841b55c23540d49b24117441eb1f302089257430204
SDR image bank 20
994a4f137178bc0923e52ae8240e09fde3c62532f002c5d1c73b9f2117462df0
```

Builders retain historical `UNVALIDATED` filenames and conservative
`ready_to_flash: false` metadata: building a file cannot certify a connected
monitor. The device result above is separate evidence. No offsets or acceptance
claims should be generalized to another model or firmware version.
