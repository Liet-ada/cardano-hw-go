// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package device

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor/thp"
)

// FileStore keeps THP credentials in a file only its owner can read. A
// credential lets this host reopen a channel without the pairing code; it
// is not a key of the wallet, and every action still needs the person on
// the Trezor.
type FileStore struct {
	Path string
	mu   sync.Mutex
}

type storedCredential struct {
	TrezorStaticPublicKey string `json:"trezor_static_public_key"`
	HostStaticPrivateKey  string `json:"host_static_private_key"`
	Credential            string `json:"credential"`
}

// DefaultStorePath is where the credentials are kept by default.
func DefaultStorePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "cardano-hw-go", "thp-credentials.json"), nil
}

func (s *FileStore) load() ([]storedCredential, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var creds []storedCredential
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}
	return creds, nil
}

// Credentials returns the stored credentials.
func (s *FileStore) Credentials() ([]thp.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.load()
	if err != nil {
		return nil, err
	}
	var out []thp.Credential
	for _, c := range stored {
		ts, err1 := hex.DecodeString(c.TrezorStaticPublicKey)
		hs, err2 := hex.DecodeString(c.HostStaticPrivateKey)
		cr, err3 := hex.DecodeString(c.Credential)
		if err := errors.Join(err1, err2, err3); err != nil {
			return nil, err
		}
		out = append(out, thp.Credential{TrezorStaticPublicKey: ts, HostStaticPrivateKey: hs, Credential: cr})
	}
	return out, nil
}

// Save adds a credential, replacing any for the same Trezor.
func (s *FileStore) Save(c thp.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.load()
	if err != nil {
		return err
	}
	key := hex.EncodeToString(c.TrezorStaticPublicKey)
	kept := stored[:0]
	for _, x := range stored {
		if x.TrezorStaticPublicKey != key {
			kept = append(kept, x)
		}
	}
	kept = append(kept, storedCredential{key, hex.EncodeToString(c.HostStaticPrivateKey), hex.EncodeToString(c.Credential)})
	data, err := json.MarshalIndent(kept, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}
