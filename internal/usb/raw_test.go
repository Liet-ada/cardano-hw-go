// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package usb

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// TestRawReadSignals checks that signals do not end a pending read of a
// connected Trezor, when USB_TREZOR=1. The Go runtime signals its own
// threads, and IOKit aborts a synchronous transfer whose thread takes one.
// It also checks that AbortPipe ends the read when its timeout runs out.
func TestRawReadSignals(t *testing.T) {
	if os.Getenv("USB_TREZOR") != "1" {
		t.Skip("USB_TREZOR not set")
	}
	infos, err := ListRaw(Matcher{0x1209, 0x53c1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 {
		t.Fatalf("%d Trezors connected, want 1", len(infos))
	}
	d, err := OpenRaw(infos[0])
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for { // drop stale packets
		if _, err := d.Read(100 * time.Millisecond); errors.Is(err, ErrTimeout) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	kill := exec.Command("/bin/sh", "-c", `while kill -URG "$1"; do :; done`, "sh", strconv.Itoa(os.Getpid()))
	if err := kill.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		kill.Process.Kill()
		kill.Wait()
	}()
	start := time.Now()
	if _, err := d.Read(3 * time.Second); !errors.Is(err, ErrTimeout) {
		t.Fatalf("read: %v, want a timeout", err)
	}
	if took := time.Since(start); took > 4*time.Second {
		t.Fatalf("the read took %v to time out after 3s", took)
	}
}
