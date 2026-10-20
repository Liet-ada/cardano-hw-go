// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package device

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor/thp"
)

func testCredential(trezor, host, c byte) thp.Credential {
	return thp.Credential{
		TrezorStaticPublicKey: bytes.Repeat([]byte{trezor}, 32),
		HostStaticPrivateKey:  bytes.Repeat([]byte{host}, 32),
		Credential:            bytes.Repeat([]byte{c}, 40),
	}
}

// TestFileStore saves, replaces and reads credentials, in a file only its
// owner can read.
func TestFileStore(t *testing.T) {
	s := &FileStore{Path: filepath.Join(t.TempDir(), "cardano-hw-go", "thp-credentials.json")}
	if got, err := s.Credentials(); err != nil || len(got) != 0 {
		t.Fatalf("empty store: %v, %v", got, err)
	}
	a, b, a2 := testCredential(1, 2, 3), testCredential(4, 5, 6), testCredential(1, 7, 8)
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

	for path, mode := range map[string]os.FileMode{s.Path: 0o600, filepath.Dir(s.Path): 0o700 | os.ModeDir} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode() != mode {
			t.Errorf("%s: mode %v, want %v", path, fi.Mode(), mode)
		}
	}
}
