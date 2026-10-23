// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package v1

import (
	"errors"
	"testing"
	"time"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor/wire"
)

// floodLink answers every read at once with a packet that starts no
// message.
type floodLink struct{}

func (floodLink) Write([]byte) error                 { return nil }
func (floodLink) Read(time.Duration) ([]byte, error) { return make([]byte, wire.PacketSize), nil }
func (floodLink) Close() error                       { return nil }

// Packets that are not a message do not keep Read waiting past its
// timeout.
func TestReadFloodTimesOut(t *testing.T) {
	start := time.Now()
	_, _, err := (&Conn{Link: floodLink{}}).Read(200 * time.Millisecond)
	if !errors.Is(err, wire.ErrTimeout) || time.Since(start) > 5*time.Second {
		t.Fatalf("Read = %v after %v", err, time.Since(start))
	}
}
