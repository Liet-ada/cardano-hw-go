// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package device

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
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

// A malformed entry is skipped instead of hiding the other credentials, and
// a damaged file is reported with its path.
func TestFileStoreDamaged(t *testing.T) {
	s := &FileStore{Path: filepath.Join(t.TempDir(), "thp-credentials.json")}
	good := testCredential(1, 2, 3)
	if err := s.Save(good); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	bad := `{"trezor_static_public_key": "zz", "host_static_private_key": "00", "credential": ""},` + "\n"
	short := `{"trezor_static_public_key": "0101", "host_static_private_key": "0202", "credential": "03"},` + "\n"
	data = bytes.Replace(data, []byte("[\n"), []byte("[\n"+bad+short), 1)
	if err := os.WriteFile(s.Path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.Credentials()
	if err != nil || len(got) != 1 || !bytes.Equal(got[0].Credential, good.Credential) {
		t.Fatalf("got %v, %v; want only the good credential", got, err)
	}

	if err := os.WriteFile(s.Path, []byte("[{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Credentials(); err == nil || !strings.Contains(err.Error(), s.Path) {
		t.Fatalf("damaged file: %v", err)
	}
}

// Save tightens a directory that was already there and does not write
// through a file planted next to the credentials.
func TestFileStoreDirectoryAndTemporary(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cardano-hw-go")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &FileStore{Path: filepath.Join(dir, "thp-credentials.json")}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, s.Path+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(testCredential(1, 2, 3)); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory: %v, %v", fi.Mode(), err)
	}
	if data, err := os.ReadFile(outside); err != nil || len(data) != 0 {
		t.Fatalf("wrote %d bytes through the planted link (%v)", len(data), err)
	}
	if fi, err := os.Lstat(s.Path); err != nil || fi.Mode() != 0o600 {
		t.Fatalf("file: %v, %v", fi.Mode(), err)
	}
}
