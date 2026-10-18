# SPDX-License-Identifier: Apache-2.0

GO ?= go
TREZOR_EMULATOR ?= 127.0.0.1:21324
FUZZTIME ?= 1m

.PHONY: check fmt vet test emulator fuzz build

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

# Fuzzing, each target for FUZZTIME; not part of check, which runs their
# seeds. test/cbor-oracle, which compares internal/cbor with
# fxamacker/cbor, is a module of its own.
fuzz:
	$(GO) test -run '^$$' -fuzz '^FuzzDecode$$' -fuzztime $(FUZZTIME) ./internal/cbor
	$(GO) test -run '^$$' -fuzz '^FuzzTransaction$$' -fuzztime $(FUZZTIME) ./internal/tx
	$(GO) test -run '^$$' -fuzz '^FuzzUnmarshal$$' -fuzztime $(FUZZTIME) ./internal/trezor/pb
	cd test/cbor-oracle && $(GO) vet . && $(GO) test -run '^$$' -fuzz '^FuzzAgainstFxamacker$$' -fuzztime $(FUZZTIME) .

build:
	$(GO) build -o bin/ ./cmd/...
