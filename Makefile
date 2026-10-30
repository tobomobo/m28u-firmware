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
