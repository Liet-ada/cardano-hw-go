// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package usb reaches hardware wallets over USB: raw (vendor class)
// interfaces for Trezor, and HID interfaces for Ledger and Keystone. On
// macOS it calls IOKit through cgo; on Linux it uses usbfs and hidraw
// without cgo.
package usb

import (
	"errors"
	"time"
)

// Info describes a USB interface of a connected device.
type Info struct {
	VendorID  uint16
	ProductID uint16
	Interface int
	// Path identifies the device to Open; its form depends on the system.
	Path    string
	Product string
	Serial  string
	// UsagePage is the HID usage page (HID devices only).
	UsagePage uint16
}

// Device is an open interface that exchanges reports or packets.
type Device interface {
	Write(p []byte) error
	// Read returns the next packet, waiting up to timeout (zero waits
	// without limit).
	Read(timeout time.Duration) ([]byte, error)
	Close() error
}

// Errors.
var (
	ErrTimeout = errors.New("usb: timeout")
	ErrBusy    = errors.New("usb: the device is in use by another program (close Trezor Suite, Ledger Live or any wallet using it, and try again)")
	ErrClosed  = errors.New("usb: device closed")
)

// Matcher selects devices by vendor and product id; a zero product id
// matches any.
type Matcher struct {
	VendorID, ProductID uint16
}

func (m Matcher) matches(vid, pid uint16) bool {
	return m.VendorID == vid && (m.ProductID == 0 || m.ProductID == pid)
}
