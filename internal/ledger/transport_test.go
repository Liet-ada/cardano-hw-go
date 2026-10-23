// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ledger

import (
	"errors"
	"testing"
	"time"
)

// floodHID answers every read at once with a report of another channel.
type floodHID struct{}

func (floodHID) Write([]byte) error { return nil }
func (floodHID) Read(time.Duration) ([]byte, error) {
	return append([]byte{0x02, 0x02, hidTagAPDU, 0, 0}, make([]byte, 59)...), nil
}
func (floodHID) Close() error { return nil }

// Reports of other channels do not keep a response waiting past its
// timeout.
func TestReadFloodTimesOut(t *testing.T) {
	defer func(d time.Duration) { readTimeout = d }(readTimeout)
	readTimeout = 200 * time.Millisecond
	start := time.Now()
	_, err := NewHIDTransport(floodHID{}).read()
	if !errors.Is(err, errReadTimeout) || time.Since(start) > 5*time.Second {
		t.Fatalf("read = %v after %v", err, time.Since(start))
	}
}
