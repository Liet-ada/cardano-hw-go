// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package device finds the connected hardware wallet and opens it as a
// provider.
package device

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/Liet-ada/cardano-hw-go/internal/hw"
	hwtrezor "github.com/Liet-ada/cardano-hw-go/internal/hw/trezor"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/debuglink"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/wire"
)

// Environment variables.
const (
	// EnvTrezorEmulator points to the Trezor emulator (host:port) instead
	// of a USB device.
	EnvTrezorEmulator = "CARDANO_HW_GO_TREZOR_EMULATOR"
	// EnvDebugLink, set to 1 with the emulator, answers for the person
	// through its debug link: pairing code and confirmations.
	EnvDebugLink = "CARDANO_HW_GO_DEBUGLINK"
	// EnvStore overrides where THP credentials are kept.
	EnvStore = "CARDANO_HW_GO_THP_STORE"
	// EnvHostName overrides the host name the Trezor shows when pairing.
	EnvHostName = "CARDANO_HW_GO_HOST_NAME"

	// defaultHostName is the host name the Trezor shows and keeps among its
	// paired hosts. It is not the computer's, which may hold the name of
	// its owner.
	defaultHostName = "cardano-hw-go"
)

// ErrNoDevice is cardano-hw-cli's error when it finds no hardware wallet.
var ErrNoDevice = errors.New("Error occurred while trying to find hw transport, make sure Ledger or Trezor or Keystone is connected to your computer")

// actionTimeout bounds each wait for the device, which may wait for the
// person to confirm.
const actionTimeout = 5 * time.Minute

// Opener opens the hardware wallet the environment points to.
type Opener struct {
	Messages io.Writer // where to tell the person what to do
}

func (o *Opener) trezorOptions(ui trezor.UI) (trezor.Options, error) {
	path := os.Getenv(EnvStore)
	if path == "" {
		p, err := DefaultStorePath()
		if err != nil {
			return trezor.Options{}, err
		}
		path = p
	}
	host := os.Getenv(EnvHostName)
	if host == "" {
		host = defaultHostName
	}
	return trezor.Options{
		UI: ui, Store: &FileStore{Path: path}, HostName: host, AppName: "cardano-hw-go",
		Timeout: actionTimeout,
	}, nil
}

// Open finds the device and connects to it.
func (o *Opener) Open() (hw.Provider, error) {
	if addr := os.Getenv(EnvTrezorEmulator); addr != "" {
		return o.openEmulator(addr)
	}
	if addr := os.Getenv(EnvLedgerSpeculos); addr != "" {
		return o.openSpeculos(addr)
	}
	return o.openUSB()
}

func (o *Opener) openEmulator(addr string) (hw.Provider, error) {
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

// closer closes the link with the provider.
type closer struct {
	hw.Provider
	link wire.Link
}

func (c *closer) Close() error {
	c.Provider.Close()
	return c.link.Close()
}
