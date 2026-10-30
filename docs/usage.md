# Reproduction and device workflow

Run commands from the repository root. Core code uses Python 3.9+ and the
standard library. `make build` builds macOS IOKit workers with clang. Linux
live access needs read/write permission on the monitor's hidraw device; pass
`--device /dev/hidrawN` after identifying the correct device. Do not grant access
to every hidraw node. macOS normally auto-selects the matching HID interface.

## Offline checks

```sh
make check
mkdir -p artifacts firmware/original
# Place the official extracted F11 file in firmware/original/ first.
python3 -m m28u_toolkit inspect firmware/original/GIGABYTE_M28U_F11.bin
python3 tools/build_sdr_experiment.py artifacts/sdr
python3 -m m28u_toolkit simulate-update firmware/original/GIGABYTE_M28U_F11.bin --candidate
python3 tools/validate_writer_worker.py artifacts/native-replay.json --fixed-register-reads
```

The final command needs the macOS native worker. It uses simulated USB/SPI,
never a device. F10-specific tests additionally require the official file at
`firmware/original/GIGABYTE_M28U_F10.bin`. One optional trace-comparison test
requires an excluded research trace, so skips in a fresh clone are expected.
No command automatically downloads vendor firmware.

## Backup and programming

These are explicit device operations, **not part of `make check`**. Close all
monitor controllers (MonitorControl, BetterDisplay, Lunar) in every user session.
Route the monitor's USB upstream to this computer. Use stable power and prevent
sleep. Expect picture and monitor-connected peripherals to disappear in ISP.
Have controls available independently of the monitor's USB hub.

The reader initially requires stock-reference anchors. Take a backup before
modifying stock F11; it is not a general backup utility for arbitrary patched
images. The following reads two complete 4 MiB main-array captures, resets and
checks fresh normal-mode responses before publishing them. It can take about
50 minutes and does not cover OTP or other nonvolatile devices.

```sh
python3 -m m28u_toolkit backup artifacts/backup --live --enter-isp --timeout-seconds 3600
```

Successful output files are:

```text
artifacts/backup/verified/spi-main-array-pass1.bin
artifacts/backup/verified/spi-main-array-pass2.bin
```

Keep both somewhere safe. The writer requires matching captures whose update
region is exact stock F11. Its later preflight permits the known stock,
standby-only or standby+SDR bank pairs, plus unchanged reference samples.
Changed saved settings may cause refusal. Do not bypass checks or substitute
a synthetic capture to get past a refusal.

This example prepares the pinned SDR job **offline**; it opens no device:

```sh
python3 -m m28u_toolkit writer \
  artifacts/backup/verified/spi-main-array-pass1.bin \
  artifacts/backup/verified/spi-main-array-pass2.bin \
  artifacts/session \
  --sdr-cap540 artifacts/sdr/M28U-SDR-cap540-OFFLINE-UNVALIDATED.research.bin
```

Add `--live` for a read-only hardware preflight, which temporarily enters ISP
and resets. For actual programming, use a **new** output directory and add both
`--live --program`. On macOS, prefix that command with `caffeinate -dimsu`.
Allow about 40 minutes; one session took 28m17s. Do not close its terminal,
interrupt it or disconnect power/USB. The engine has a one-hour deadline;
expiry after writes may leave a partial image held in ISP.

Omit `--sdr-cap540` to select standby-only. Use `--stock-only` for stock F11.
These are whole update-region rewrites, even if few image bytes differ. A
software rollback requires a working USB/ISP route; it is not failed-boot recovery.

After success, check the picture and peripherals yourself. A fresh F11 response
alone cannot establish visual/KVM operation. If a write fails, preserve the
journal/result and diagnose before reset or power cycling: some failures leave
ISP held intentionally, and no automatic resume/recovery is implemented.

## Original-instruction harnesses

These run selected firmware routines in the bundled MIT emu8051 emulator.
Mode predicates, transport and hardware are partly stubbed. They do not emulate
the entire monitor or establish current/thermal limits. Build each harness:

```sh
mkdir -p build
for name in backlight_output firmware_behavior timer_scheduler; do
  clang -O2 -I analysis/vendor/emu8051 "tools/${name}_harness.c" \
    analysis/vendor/emu8051/core.c analysis/vendor/emu8051/opcodes.c \
    analysis/vendor/emu8051/disasm.c -o "build/${name}_harness"
done
python3 tools/validate_backlight_output.py build/backlight_output_harness artifacts/backlight-stock.json
python3 tools/validate_backlight_output.py build/backlight_output_harness artifacts/backlight-sdr.json \
  --experiment artifacts/sdr/M28U-SDR-cap540-OFFLINE-UNVALIDATED.research.bin
python3 tools/validate_firmware_behavior.py build/firmware_behavior_harness artifacts/behaviour.json
```

The timer wrapper expects `tools/timer_scheduler_harness`; build it to that
path instead of `build/` and run
`python3 tools/validate_timer_scheduler.py artifacts/timer.json`.
JSON output paths must not exist. `tools/benchmark_isp_clock.py --help` exposes
the optional clock comparison; it is not required for normal reproduction.
