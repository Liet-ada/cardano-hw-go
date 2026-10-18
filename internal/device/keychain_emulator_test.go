// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build darwin && cgo && emulators

package device

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/debuglink"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/thp"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/wire"
)

// noPairing presses yes through the debug link but fails if pairing is
// asked again.
type noPairing struct{ *DebugUI }

func (noPairing) PairingCode(thp.PairingInfo) (string, error) {
	return "", errors.New("pairing asked again")
}

// TestEmulatorKeychainPairing pairs with the Trezor emulator, keeping the
// credential in the keychain under a service of its own, and connects
// again without pairing. It runs with TREZOR_EMULATOR (host:port) and
// CARDANO_HW_GO_KEYCHAIN_TEST=1.
func TestEmulatorKeychainPairing(t *testing.T) {
	addr := os.Getenv("TREZOR_EMULATOR")
	if addr == "" || os.Getenv("CARDANO_HW_GO_KEYCHAIN_TEST") != "1" {
		t.Skip("TREZOR_EMULATOR and CARDANO_HW_GO_KEYCHAIN_TEST not set")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	d, err := debuglink.Dial(net.JoinHostPort(host, strconv.Itoa(p+1)))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	suffix := make([]byte, 8)
	rand.Read(suffix)
	store := &KeychainStore{Service: "cardano-hw-go test " + hex.EncodeToString(suffix)}
	t.Cleanup(func() {
		creds, err := store.Credentials()
		if err != nil {
			t.Error(err)
		}
		for _, c := range creds {
			if err := store.remove(c.TrezorStaticPublicKey); err != nil {
				t.Error(err)
			}
		}
	})
	connect := func(ui trezor.UI) error {
		link, err := wire.DialUDP(addr)
		if err != nil {
			return err
		}
		defer link.Close()
		_, err = trezor.Connect(link, trezor.Options{UI: ui, Store: store, HostName: defaultHostName, AppName: "cardano-hw-go test", Timeout: time.Minute})
		return err
	}
	if err := connect(&DebugUI{Debug: d}); err != nil {
		t.Fatalf("pairing: %v", err)
	}
	creds, err := store.Credentials()
	if err != nil || len(creds) != 1 {
		t.Fatalf("after pairing: %d credentials, %v", len(creds), err)
	}
	if err := connect(noPairing{&DebugUI{Debug: d}}); err != nil {
		t.Fatalf("connecting again: %v", err)
	}
}
