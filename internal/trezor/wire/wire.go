// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package wire defines how the Trezor protocols reach a device: as fixed-size
// packets over USB or, for the emulator, UDP.
package wire

import (
	"errors"
	"time"
)

// PacketSize is the size of a Trezor USB packet.
const PacketSize = 64

// ErrTimeout reports that no packet arrived in time.
var ErrTimeout = errors.New("wire: timeout reading from the device")

// Link exchanges packets of PacketSize bytes with a device.
type Link interface {
	// Write sends one packet.
	Write(packet []byte) error
	// Read returns the next packet, waiting up to timeout; a zero timeout
	// waits without limit.
	Read(timeout time.Duration) ([]byte, error)
	Close() error
}
