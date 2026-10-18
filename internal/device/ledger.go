// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package device

import (
	"fmt"
	"runtime"

	"github.com/Liet-ada/cardano-hw-go/internal/hw"
	hwledger "github.com/Liet-ada/cardano-hw-go/internal/hw/ledger"
	"github.com/Liet-ada/cardano-hw-go/internal/ledger"
	"github.com/Liet-ada/cardano-hw-go/internal/usb"
)

// Ledger devices: one vendor id for all models; the APDU interface is the
// HID interface of usage page 0xffa0 (interface 0 on Linux, as Ledger's
// own transport chooses it).
var ledgerVendor = usb.Matcher{VendorID: 0x2c97}

const ledgerUsagePage = 0xffa0

func listLedgers() ([]found, error) {
	infos, err := usb.ListHID(ledgerVendor)
	if err != nil {
		return nil, err
	}
	var out []found
	for _, i := range infos {
		if runtime.GOOS == "linux" && i.Interface != 0 || runtime.GOOS != "linux" && i.UsagePage != ledgerUsagePage {
			continue
		}
		out = append(out, found{"ledger", i})
	}
	return out, nil
}

// listOthers lists the Ledger devices connected (Keystone is not
// supported yet).
func (o *Opener) listOthers() ([]found, error) { return listLedgers() }

func (o *Opener) openOther(d found) (hw.Provider, error) {
	if d.kind != "ledger" {
		return nil, fmt.Errorf("not supported yet: %s", d.kind)
	}
	dev, err := usb.OpenHID(d.info)
	if err != nil {
		return nil, fmt.Errorf("opening the Ledger: %w", err)
	}
	return openLedger(ledger.NewHIDTransport(dev)), nil
}

func openLedger(x ledger.Exchanger) hw.Provider {
	return &ledgerCloser{Provider: hwledger.New(ledger.New(x)), x: x}
}

// ledgerCloser closes the transport with the provider.
type ledgerCloser struct {
	hw.Provider
	x ledger.Exchanger
}

func (c *ledgerCloser) Close() error {
	c.Provider.Close()
	return c.x.Close()
}
