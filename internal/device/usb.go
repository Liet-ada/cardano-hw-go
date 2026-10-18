// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package device

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Liet-ada/cardano-hw-go/internal/hw"
	hwtrezor "github.com/Liet-ada/cardano-hw-go/internal/hw/trezor"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/wire"
	"github.com/Liet-ada/cardano-hw-go/internal/usb"
)

// EnvDevice chooses the kind of device when several are connected:
// trezor, ledger or keystone.
const EnvDevice = "CARDANO_HW_GO_DEVICE"

// USB ids.
var (
	trezorFirmware   = usb.Matcher{VendorID: 0x1209, ProductID: 0x53c1}
	trezorBootloader = usb.Matcher{VendorID: 0x1209, ProductID: 0x53c0}
	trezorOne        = usb.Matcher{VendorID: 0x534c, ProductID: 0x0001}
)

// found is a connected device of a kind.
type found struct {
	kind string
	info usb.Info
}

func (o *Opener) openUSB() (hw.Provider, error) {
	var devices []found
	trezors, err := usb.ListRaw(trezorFirmware, 0)
	if err != nil {
		return nil, err
	}
	for _, i := range trezors {
		devices = append(devices, found{"trezor", i})
	}
	more, err := o.listOthers()
	if err != nil {
		return nil, err
	}
	devices = append(devices, more...)

	if want := os.Getenv(EnvDevice); want != "" {
		var kept []found
		for _, d := range devices {
			if d.kind == strings.ToLower(want) {
				kept = append(kept, d)
			}
		}
		devices = kept
	}
	switch len(devices) {
	case 0:
		if b, _ := usb.ListRaw(trezorBootloader, 0); len(b) > 0 {
			return nil, errors.New("the Trezor is in bootloader mode; restart it normally")
		}
		if t1, _ := usb.ListRaw(trezorOne, 0); len(t1) > 0 {
			return nil, errors.New("the Trezor Model One does not support Cardano")
		}
		return nil, ErrNoDevice
	case 1:
	default:
		var names []string
		for _, d := range devices {
			names = append(names, fmt.Sprintf("%s (%s)", d.kind, d.info.Product))
		}
		return nil, fmt.Errorf("several hardware wallets are connected: %s; disconnect the others or set %s", strings.Join(names, ", "), EnvDevice)
	}
	d := devices[0]
	switch d.kind {
	case "trezor":
		return o.openTrezorUSB(d.info)
	}
	return o.openOther(d)
}

// usbLink adapts a USB device to a wire link.
type usbLink struct{ usb.Device }

func (l usbLink) Read(timeout time.Duration) ([]byte, error) {
	p, err := l.Device.Read(timeout)
	if errors.Is(err, usb.ErrTimeout) {
		return nil, wire.ErrTimeout
	}
	return p, err
}

func (o *Opener) openTrezorUSB(info usb.Info) (hw.Provider, error) {
	dev, err := usb.OpenRaw(info)
	if err != nil {
		return nil, fmt.Errorf("opening the Trezor: %w", err)
	}
	link := usbLink{dev}
	opts, err := o.trezorOptions(&TerminalUI{Messages: o.Messages})
	if err != nil {
		link.Close()
		return nil, err
	}
	c, err := trezor.Connect(link, opts)
	if err != nil {
		link.Close()
		return nil, err
	}
	return &closer{Provider: hwtrezor.New(c), link: link}, nil
}
