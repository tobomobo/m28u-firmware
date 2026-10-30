# Making other firmware changes

There is no vendor source tree to rebuild. The tools take an exact official
binary, check its hash and original instructions, then replace selected bytes
or insert a small 8051 routine. Users build the resulting image locally.
The USB writer is separate from the patch builder.

## Existing examples

- `m28u_toolkit/images.py:make_candidate` changes two instruction operands:
  a timer argument of 5000 becomes 60000. It checks the input hash and signature
  and verifies that exactly the intended two bytes changed.
- `tools/build_sdr_experiment.py:build` redirects one existing call to an
  81-byte routine in unused padding. `stub_bytes` constructs the instructions,
  checks branch displacements and returns through the original output helper.
  Mode guards restrict where the new arithmetic runs.

The SDR builder is deliberately fixed to one result. Changing its constants
will create a different image that the current writer refuses.

## Investigation to acceptance

1. **Pick one observable behaviour.** Record the stock baseline and what should
   change. For KVM, distinguish input selection, USB routing, loss of signal and
   automatic switching; changing one timer does not define all of them.
2. **Find the relevant instructions.** Disassemble the exact firmware with an
   8051-capable tool, follow callers and callees, and compare stock versions.
   This is banked firmware: a CPU address alone does not identify a file offset.
   Check bank selection, shared helpers, XRAM state and mode-dependent paths.
   Decompiled pseudocode and guessed register names are hypotheses to verify.
3. **Build a narrow offline patch.** Require the stock SHA-256, assert original
   bytes and any unused space, and restrict the exact changed offsets/banks.
   Record the output hash and before/after bytes. For injected code, account for
   register clobbers, stack, bank switching, branches and interrupt interactions.
4. **Test the behaviour.** Extend the original-instruction harnesses and synthetic
   tests with normal, boundary, excluded-mode and failure cases. Mutate/remove
   the patch to show the checks detect a wrong result. `make check` is offline;
   it does not automatically validate a new patch's intended behaviour.
5. **Review writer integration separately.** The current writer accepts only
   stock, standby and one pinned SDR target. A new target needs an explicit
   selector, immutable image/bank hashes, a justified write range, live installed-
   image recognition and refusal/rollback simulations. Review the relevant
   image policy and preflight logic in `images.py` and `writer.py`, plus both
   transport guards (`flash_bus.py` and `m28u_flash_macos.c`) if the required
   operation/range changes. Keep marker-last and verification rules intact;
   changing a hash alone is not evidence that an image is suitable to flash.
6. **Accept on hardware as a separate step.** Preserve a stock backup, establish
   recovery options, run the read-only preflight and then a monitored session.
   Check the actual behaviour and affected modes, not just a matching readback.
   USB-only failed-boot recovery is still unproven for this project.

For a contribution, include the reason, exact base/output hashes, changed
regions, reproducible builder, focused checks and observed-versus-inferred
results. Submit source and research notes, not vendor or patched firmware,
updater executables, device captures or machine-specific logs.

## Official firmware and rights

Get the archive from [Gigabyte's M28U firmware page](https://www.gigabyte.com/Monitor/M28U/support#support-dl-firmware)
or [Gigabyte's F11 download](https://download.gigabyte.com/FileList/Firmware/GIGABYTE_M28U_F11.zip).
Extract `GIGABYTE_M28U_F11.bin` to `firmware/original/` and run:

```sh
python3 -m m28u_toolkit inspect firmware/original/GIGABYTE_M28U_F11.bin
```

The expected BIN hash is in the README and checked by the code; it is not the
ZIP hash. If Gigabyte changes/removes the file, do not substitute another
version or remove the hash check. The existing offsets are version-specific.
The direct archive was retrieved and its extracted BIN matched the pinned
hash on 2026-10-30. Download availability can change.

Our MIT licence covers the project code, not Gigabyte's firmware. Applying a
patch locally does not make the resulting firmware MIT-licensed. The [NOTICE](../NOTICE)
clarifies ownership and non-affiliation; it does not determine whether a
particular modification or redistribution is permitted by applicable law or
vendor terms. Nor can a disclaimer guarantee immunity from liability.
