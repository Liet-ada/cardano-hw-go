// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !emulators

package device

import "github.com/Liet-ada/cardano-hw-go/internal/hw"

// openEmulator opens no emulator: only builds with the emulators tag can
// reach one.
func (o *Opener) openEmulator() (hw.Provider, bool, error) { return nil, false, nil }
