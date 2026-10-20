// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build darwin && cgo

package device

import (
	"path/filepath"
	"testing"
)

// TestFileStoreBackup checks that Time Machine leaves the credentials out,
// also once a credential replaces the file.
func TestFileStoreBackup(t *testing.T) {
	s := &FileStore{Path: filepath.Join(t.TempDir(), "thp-credentials.json")}
	for _, c := range []byte{1, 2} {
		if err := s.Save(testCredential(c, c, c)); err != nil {
			t.Fatal(err)
		}
		if !excludedFromBackup(s.Path) {
			t.Fatalf("save %d: Time Machine does not leave the file out", c)
		}
	}
	if excludedFromBackup(filepath.Dir(s.Path)) {
		t.Error("the directory of the file is left out too")
	}
}
