# M28U firmware toolkit

Experimental Gigabyte M28U firmware patches and a macOS/Linux USB updater.
Built to give a computer longer to regain video during boot, and to raise the
ordinary SDR backlight ceiling without enabling HDR or Local Dimming.

This is reverse engineering of compiled firmware and the Windows updater,
not Gigabyte source code or a full firmware decompilation. No Windows runtime
is needed. Firmware downloads and device captures are not distributed here.

## What changed

- **Standby:** a two-byte patch changes a no-signal timer argument from 5,000
  to 60,000. A substantially longer wait was observed; exact timing is unmeasured.
- **SDR:** an 81-byte routine maps the ordinary backlight control range from
  48–405 to 48–540. The brightness slider remains usable. **540 is a control
  value, not nits.** About 380–400 nits is a conditional estimate, not a measurement.
- **Updater:** a bounded USB HID → scaler ISP → SPI writer, with exact-image
  checks, byte/CRC verification and the boot marker committed last.

Both patches were flashed on one M28U. On 2026-10-30, the complete SDR image
readback matched its target, and picture/keyboard/mouse returned automatically.
The owner tentatively reported brighter SDR at 100%. The session took **28m17s**.
KVM behaviour with a disconnected host remains unresolved.

**Flashing can leave the monitor unusable.** Failed-boot recovery over USB and
long-term electrical/thermal reliability have not been established. Backups
are not a proven recovery route. MIT provides the software “AS IS”, without
warranty or liability; see [LICENSE](LICENSE).

## Start offline

Python 3.9+; no Python dependencies. macOS live access also needs Apple's clang.
Linux uses hidraw; macOS uses small IOKit workers.

```sh
make check                         # builds workers and runs offline tests
python3 -m m28u_toolkit --help
```

Obtain F11 from [Gigabyte support](https://www.gigabyte.com/Monitor/M28U/support#support-dl-firmware)
or the [official F11 archive](https://download.gigabyte.com/FileList/Firmware/GIGABYTE_M28U_F11.zip).
Put the extracted file at `firmware/original/GIGABYTE_M28U_F11.bin`.
Its required SHA-256 is:

```text
1ff616f5adcebf5057bd33405709757a68918b3cbfc0fabcad109e8a0a8128d0
```

```sh
mkdir -p artifacts
python3 -m m28u_toolkit inspect firmware/original/GIGABYTE_M28U_F11.bin
python3 -m m28u_toolkit candidate firmware/original/GIGABYTE_M28U_F11.bin artifacts/standby
python3 tools/build_sdr_experiment.py artifacts/sdr
```

Create `artifacts/` first; each output directory must be new. Commands above
never contact hardware. Optional firmware/native tests are skipped when their
inputs are absent; test success alone does not establish hardware compatibility.

[Findings and evidence](docs/findings.md) · [Device workflow and reproduction](docs/usage.md) · [Making other patches](docs/development.md)

## Layout and licence

`m28u_toolkit/` contains protocol, image checks, backup and writer code;
`tools/` contains patch/emulation tools and macOS workers; `tests/` uses fake
USB/SPI devices, including the real native parser in dry-run mode.

Project code: MIT, copyright 2026 tobomobo. The included
[emu8051](https://github.com/jarikomppa/emu8051) sources retain Jari Komppa's
MIT notices; source URLs and hashes are in
[`analysis/vendor/emu8051/sources.json`](analysis/vendor/emu8051/sources.json).
Gigabyte firmware remains proprietary to Gigabyte and its respective rights
holders; the MIT licence does not apply to it. Users obtain it directly from
Gigabyte and apply patches locally. See [NOTICE](NOTICE).
