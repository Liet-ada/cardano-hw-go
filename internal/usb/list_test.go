// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package usb

import (
	"os"
	"testing"
)

// TestListDevices lists the Trezor, Keystone and Ledger devices connected,
// when USB_LIST=1.
func TestListDevices(t *testing.T) {
	if os.Getenv("USB_LIST") != "1" {
		t.Skip("USB_LIST not set")
	}
	for _, m := range []Matcher{{0x1209, 0}, {0x2c97, 0}, {0x534c, 0}} {
		infos, err := ListRaw(m, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range infos {
			t.Logf("%04x:%04x %q serial %q at %s", i.VendorID, i.ProductID, i.Product, i.Serial, i.Path)
		}
	}
}
