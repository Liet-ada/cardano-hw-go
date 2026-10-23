// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build linux

package usb

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ListHID lists the HID interfaces of devices that match m.
func ListHID(m Matcher) ([]Info, error) { return listHIDRaw(m) }

// hidDevice is a hidraw node, which takes and gives one report per write
// and read.
type hidDevice struct {
	mu     sync.Mutex
	f      *os.File
	closed atomic.Bool // os.File takes a Close during a read
}

// OpenHID opens a listed HID interface.
func OpenHID(info Info) (Device, error) {
	f, err := os.OpenFile(info.Path, os.O_RDWR, 0)
	if err != nil {
		return nil, openError(err)
	}
	return &hidDevice{f: f}, nil
}

func hidError(op string, err error) error {
	if errors.Is(err, syscall.EIO) || errors.Is(err, syscall.ENODEV) {
		return errors.New("usb: device disconnected")
	}
	return fmt.Errorf("usb: %s: %w", op, err)
}

// Write sends an output report. hidraw takes the report id first: 0, for
// devices without report ids, is not sent.
func (d *hidDevice) Write(p []byte) error {
	if d.closed.Load() {
		return ErrClosed
	}
	if _, err := d.f.Write(append([]byte{0}, p...)); err != nil {
		return hidError("write", err)
	}
	return nil
}

func (d *hidDevice) Read(timeout time.Duration) ([]byte, error) {
	if d.closed.Load() {
		return nil, ErrClosed
	}
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if err := d.f.SetReadDeadline(deadline); err != nil {
		return nil, hidError("read", err)
	}
	buf := make([]byte, 128)
	n, err := d.f.Read(buf)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, ErrTimeout
	}
	if err != nil {
		return nil, hidError("read", err)
	}
	return buf[:n], nil
}

func (d *hidDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed.Load() {
		return nil
	}
	d.closed.Store(true)
	return d.f.Close()
}
