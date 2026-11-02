PYTHON ?= python3

.PHONY: build test check
build:
	@if [ "$$(uname -s)" = Darwin ]; then \
		clang -Wall -Wextra -Werror -framework IOKit -framework CoreFoundation tools/m28u_probe_macos.c -o tools/m28u_probe_macos && \
		clang -Wall -Wextra -Werror -framework IOKit -framework CoreFoundation tools/m28u_scaler_macos.c -o tools/m28u_scaler_macos && \
		clang -Wall -Wextra -Werror -framework IOKit -framework CoreFoundation tools/m28u_flash_macos.c -o tools/m28u_flash_macos; \
	else \
		$(PYTHON) -c 'import m28u_toolkit.transport; print("Python transport loaded; no hardware accessed")'; \
	fi

test:
	$(PYTHON) -m unittest discover -s tests -v

check: build test
	$(PYTHON) -m m28u_toolkit readiness

# Offline firmware execution; requires the official pinned F11 input.
.PHONY: test-kvm
test-kvm:
	mkdir -p build artifacts
	clang -fsyntax-only -Wall -Wextra -Werror -I analysis/vendor/emu8051 tools/kvm_state_harness.c
	clang -O2 -I analysis/vendor/emu8051 tools/kvm_state_harness.c analysis/vendor/emu8051/core.c analysis/vendor/emu8051/opcodes.c analysis/vendor/emu8051/disasm.c -o build/kvm_state_harness
	$(PYTHON) tools/validate_kvm_state.py build/kvm_state_harness artifacts/kvm-validation-$$(date +%s).json

.PHONY: test-osd
test-osd:
	mkdir -p build artifacts
	clang -fsyntax-only -Wall -Wextra -Werror -I analysis/vendor/emu8051 tools/osd_state_harness.c
	clang -O2 -I analysis/vendor/emu8051 tools/osd_state_harness.c analysis/vendor/emu8051/core.c analysis/vendor/emu8051/opcodes.c analysis/vendor/emu8051/disasm.c -o build/osd_state_harness
	clang -O2 -I analysis/vendor/emu8051 tools/kvm_state_harness.c analysis/vendor/emu8051/core.c analysis/vendor/emu8051/opcodes.c analysis/vendor/emu8051/disasm.c -o build/kvm_state_harness
	$(PYTHON) tools/validate_osd_state.py build/osd_state_harness build/kvm_state_harness artifacts/osd-validation-$$(date +%s).json
