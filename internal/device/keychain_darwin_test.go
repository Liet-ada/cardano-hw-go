// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build darwin && cgo

package device

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor/thp"
)

// TestKeychainStore saves, replaces and reads credentials in the login
// keychain, under a service of its own that it removes. It only runs with
// CARDANO_HW_GO_KEYCHAIN_TEST=1, so as not to touch the keychain of
// whoever runs the tests.
func TestKeychainStore(t *testing.T) {
	if os.Getenv("CARDANO_HW_GO_KEYCHAIN_TEST") != "1" {
		t.Skip("CARDANO_HW_GO_KEYCHAIN_TEST not set")
	}
	suffix := make([]byte, 8)
	rand.Read(suffix)
	s := &KeychainStore{Service: "cardano-hw-go test " + hex.EncodeToString(suffix)}
	cred := func(trezor, host, c byte) thp.Credential {
		return thp.Credential{
			TrezorStaticPublicKey: bytes.Repeat([]byte{trezor}, 32),
			HostStaticPrivateKey:  bytes.Repeat([]byte{host}, 32),
			Credential:            bytes.Repeat([]byte{c}, 40),
		}
	}
	a, b, a2 := cred(1, 2, 3), cred(4, 5, 6), cred(1, 7, 8)
	t.Cleanup(func() {
		for _, c := range []thp.Credential{a, b} {
			if err := s.remove(c.TrezorStaticPublicKey); err != nil {
				t.Error(err)
			}
		}
	})

	if got, err := s.Credentials(); err != nil || len(got) != 0 {
		t.Fatalf("empty store: %v, %v", got, err)
	}
	for _, c := range []thp.Credential{a, b, a2} {
		if err := s.Save(c); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]thp.Credential{hex.EncodeToString(a2.TrezorStaticPublicKey): a2, hex.EncodeToString(b.TrezorStaticPublicKey): b}
	if len(got) != len(want) {
		t.Fatalf("%d credentials, want %d", len(got), len(want))
	}
	for _, c := range got {
		w, ok := want[hex.EncodeToString(c.TrezorStaticPublicKey)]
		if !ok || !bytes.Equal(c.HostStaticPrivateKey, w.HostStaticPrivateKey) || !bytes.Equal(c.Credential, w.Credential) {
			t.Errorf("credential %x: %x %x", c.TrezorStaticPublicKey, c.HostStaticPrivateKey, c.Credential)
		}
	}
}
