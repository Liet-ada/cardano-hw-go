# SPDX-License-Identifier: Apache-2.0

GO ?= go
TREZOR_EMULATOR ?= 127.0.0.1:21324

.PHONY: check fmt vet test emulator build

check: fmt vet test

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

test:
	$(GO) test -race ./...

# Tests against the Trezor emulator, started with the "all all ..." seed
# (emu.py --slip0014); not part of check. One package at a time, as they
# share the emulator.
emulator:
	TREZOR_EMULATOR=$(TREZOR_EMULATOR) $(GO) test -p 1 -count=1 -run Emulator -v ./...

build:
	$(GO) build -o bin/ ./cmd/...
