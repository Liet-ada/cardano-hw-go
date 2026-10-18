// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !(darwin && cgo)

package device

import "github.com/Liet-ada/cardano-hw-go/internal/trezor/thp"

// defaultStore is a file in the user config directory, until the Secret
// Service of Linux is supported.
func defaultStore() (thp.Store, error) {
	path, err := DefaultStorePath()
	if err != nil {
		return nil, err
	}
	return &FileStore{Path: path}, nil
}
