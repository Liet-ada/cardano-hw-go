// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build emulators

package device

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/Liet-ada/cardano-hw-go/internal/hw"
	hwtrezor "github.com/Liet-ada/cardano-hw-go/internal/hw/trezor"
	"github.com/Liet-ada/cardano-hw-go/internal/ledger"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/debuglink"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/thp"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/wire"
)

// The emulators are only reachable in builds with the emulators tag, so
// that no environment variable can point the binary of a person at a
// device that is not theirs.
const (
	// EnvTrezorEmulator points to the Trezor emulator (host:port) instead
	// of a USB device.
	EnvTrezorEmulator = "CARDANO_HW_GO_TREZOR_EMULATOR"
	// EnvDebugLink, set to 1 with the emulator, answers for the person
	// through its debug link: pairing code and confirmations.
	EnvDebugLink = "CARDANO_HW_GO_DEBUGLINK"
	// EnvLedgerSpeculos points to the APDU port (host:port) of the
	// Speculos emulator, or of a simulator speaking its protocol, instead
	// of a USB Ledger.
	EnvLedgerSpeculos = "CARDANO_HW_GO_LEDGER_SPECULOS"
)

// openEmulator opens the emulator the environment points to, if any.
func (o *Opener) openEmulator() (hw.Provider, bool, error) {
	if addr := os.Getenv(EnvTrezorEmulator); addr != "" {
		p, err := o.openTrezorEmulator(addr)
		return p, true, err
	}
	if addr := os.Getenv(EnvLedgerSpeculos); addr != "" {
		t, err := ledger.DialSpeculos(addr)
		if err != nil {
			return nil, true, fmt.Errorf("no Ledger emulator at %s: %w", addr, err)
		}
		return openLedger(t), true, nil
	}
	return nil, false, nil
}

func (o *Opener) openTrezorEmulator(addr string) (hw.Provider, error) {
	link, err := wire.DialUDP(addr)
	if err != nil {
		return nil, err
	}
	if !link.Ping() {
		link.Close()
		return nil, fmt.Errorf("no Trezor emulator at %s", addr)
	}
	var ui trezor.UI = &TerminalUI{Messages: o.Messages}
	if os.Getenv(EnvDebugLink) == "1" {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
		d, err := debuglink.Dial(net.JoinHostPort(host, strconv.Itoa(p+1)))
		if err != nil {
			return nil, err
		}
		ui = &DebugUI{Debug: d}
	}
	opts, err := o.trezorOptions(ui)
	if err != nil {
		return nil, err
	}
	c, err := trezor.Connect(link, opts)
	if err != nil {
		link.Close()
		return nil, err
	}
	return &closer{Provider: hwtrezor.New(c), link: link}, nil
}

// DebugUI answers for the person through the emulator's debug link.
type DebugUI struct {
	Debug *debuglink.Debug
}

// PairingCode asks the emulator for the code it shows.
func (u *DebugUI) PairingCode(info thp.PairingInfo) (string, error) {
	return u.Debug.PairingCode(info)
}

// ButtonRequest presses yes on the emulator.
func (u *DebugUI) ButtonRequest(uint32, string) {
	go u.Debug.PressYesSoon()
}
