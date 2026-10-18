// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !(darwin && cgo) && !linux

package usb

import "errors"

var errUnsupported = errors.New("usb: not supported on this system")

// ListRaw lists the devices that match m.
func ListRaw(m Matcher, iface int) ([]Info, error) { return nil, errUnsupported }

// OpenRaw opens the raw interface of a listed device.
func OpenRaw(info Info) (Device, error) { return nil, errUnsupported }

// ListHID lists the HID interfaces of devices that match m.
func ListHID(m Matcher) ([]Info, error) { return nil, errUnsupported }

// OpenHID opens a listed HID interface.
func OpenHID(info Info) (Device, error) { return nil, errUnsupported }
