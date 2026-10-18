// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package device finds the connected hardware wallet and opens it as a
// provider.
package device

import (
	"errors"
	"io"
	"os"
	"time"

	"github.com/Liet-ada/cardano-hw-go/internal/hw"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/thp"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/wire"
)

// Environment variables.
const (
	// EnvStore names a file to keep THP credentials in, instead of the
	// keychain on macOS or a file in the user config directory elsewhere.
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
	var store thp.Store = &FileStore{Path: os.Getenv(EnvStore)}
	if os.Getenv(EnvStore) == "" {
		s, err := defaultStore()
		if err != nil {
			return trezor.Options{}, err
		}
		store = s
	}
	host := os.Getenv(EnvHostName)
	if host == "" {
		host = defaultHostName
	}
	return trezor.Options{
		UI: ui, Store: store, HostName: host, AppName: "cardano-hw-go",
		Timeout: actionTimeout,
	}, nil
}

// Open finds the device and connects to it.
func (o *Opener) Open() (hw.Provider, error) {
	if p, ok, err := o.openEmulator(); ok {
		return p, err
	}
	return o.openUSB()
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
