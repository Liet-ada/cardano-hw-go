// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package usb

import (
	"testing"
	"unsafe"
)

// TestUSBFSLayout checks struct usbdevfs_urb and the ioctl requests
// against the values of Linux on 64-bit systems.
func TestUSBFSLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("the values are those of 64-bit systems")
	}
	var u urb
	for name, c := range map[string]struct{ got, want uintptr }{
		"size":          {unsafe.Sizeof(u), 56},
		"status":        {unsafe.Offsetof(u.status), 4},
		"buffer":        {unsafe.Offsetof(u.buffer), 16},
		"actual_length": {unsafe.Offsetof(u.actualLength), 28},
		"usercontext":   {unsafe.Offsetof(u.usercontext), 48},

		"USBDEVFS_SUBMITURB":        {ioctlSubmitURB, 0x8038550a},
		"USBDEVFS_DISCARDURB":       {ioctlDiscardURB, 0x550b},
		"USBDEVFS_REAPURBNDELAY":    {ioctlReapURBNDelay, 0x4008550d},
		"USBDEVFS_CLAIMINTERFACE":   {ioctlClaimInterface, 0x8004550f},
		"USBDEVFS_RELEASEINTERFACE": {ioctlReleaseInterface, 0x80045510},
	} {
		if c.got != c.want {
			t.Errorf("%s: %#x, want %#x", name, c.got, c.want)
		}
	}
}
