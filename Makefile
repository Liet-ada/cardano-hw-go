# SPDX-License-Identifier: Apache-2.0

GO ?= go
TREZOR_EMULATOR ?= 127.0.0.1:21324
FUZZTIME ?= 1m

.PHONY: check fmt vet test emulator fuzz build build-emulators

check: fmt vet test

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

# Linux builds other files, without cgo: vet them too, so that its build
# does not break unseen.
vet:
	$(GO) vet ./...
	$(GO) vet -tags emulators ./...
	GOOS=linux GOARCH=amd64 $(GO) vet ./...
	GOOS=linux GOARCH=arm64 $(GO) vet -tags emulators ./...

test:
	$(GO) test -race ./...

# Tests against the Trezor emulator, started with the "all all ..." seed
# (emu.py --slip0014); not part of check. One package at a time, as they
# share the emulator.
emulator:
	TREZOR_EMULATOR=$(TREZOR_EMULATOR) $(GO) test -tags emulators -p 1 -count=1 -run Emulator -v ./...

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

# A build that also opens the emulators the environment points to, for
# tests against cardano-hw-cli; never one to sign with.
build-emulators:
	$(GO) build -tags emulators -o bin/emulators/ ./cmd/...
