// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package usb

// The usbfs interface of Linux (include/uapi/linux/usbdevice_fs.h). It has
// no build tag so that its layout is checked on any system.

import "unsafe"

// urb is struct usbdevfs_urb, without the descriptors of isochronous
// packets.
type urb struct {
	typ          uint8
	endpoint     uint8
	status       int32
	flags        uint32
	buffer       unsafe.Pointer
	bufferLength int32
	actualLength int32
	startFrame   int32
	packets      int32 // number_of_packets or stream_id
	errorCount   int32
	signr        uint32
	usercontext  unsafe.Pointer
}

// URB types.
const (
	urbInterrupt = 1
	urbBulk      = 3
)

// The ioctl requests, numbered as in asm-generic/ioctl.h (amd64, arm64,
// arm, 386, riscv64): direction << 30 | size << 16 | type << 8 | number,
// with 1 for _IOW and 2 for _IOR.
const (
	ioctlSubmitURB        = 2<<30 | unsafe.Sizeof(urb{})<<16 | 'U'<<8 | 10      // _IOR('U', 10, struct usbdevfs_urb)
	ioctlDiscardURB       = 'U'<<8 | 11                                         // _IO('U', 11)
	ioctlReapURBNDelay    = 1<<30 | unsafe.Sizeof(uintptr(0))<<16 | 'U'<<8 | 13 // _IOW('U', 13, void *)
	ioctlClaimInterface   = 2<<30 | unsafe.Sizeof(uint32(0))<<16 | 'U'<<8 | 15  // _IOR('U', 15, unsigned int)
	ioctlReleaseInterface = 2<<30 | unsafe.Sizeof(uint32(0))<<16 | 'U'<<8 | 16  // _IOR('U', 16, unsigned int)
)
