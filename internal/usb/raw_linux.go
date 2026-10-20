// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build linux

package usb

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ListRaw lists the devices that match m, with the raw interface iface.
func ListRaw(m Matcher, iface int) ([]Info, error) { return listUSB(m, iface) }

// openError explains the usual reason a device node cannot be opened.
func openError(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("usb: %w (install the udev rules of Trezor and Ledger, see the README)", err)
	}
	return fmt.Errorf("usb: %w", err)
}

// rawDevice is an interface claimed through usbfs. Transfers are URBs, as
// libusb does them, so that interrupt endpoints work and a timeout cancels
// cleanly; one is in flight at a time.
type rawDevice struct {
	mu      sync.Mutex
	f       *os.File
	rc      syscall.RawConn
	iface   uint32
	in, out endpoint
	urb     urb
	closed  bool
}

// OpenRaw opens the raw interface of a listed device.
func OpenRaw(info Info) (Device, error) {
	f, err := os.OpenFile(info.Path, os.O_RDWR, 0)
	if err != nil {
		return nil, openError(err)
	}
	d, err := claim(f, info.Interface)
	if err != nil {
		f.Close()
		if errors.Is(err, ErrBusy) {
			return nil, err
		}
		return nil, fmt.Errorf("usb: opening interface %d of %s: %w", info.Interface, info.Path, err)
	}
	return d, nil
}

// claim finds the endpoints of interface iface of the open device and
// claims it.
func claim(f *os.File, iface int) (*rawDevice, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	d := &rawDevice{f: f, rc: rc, iface: uint32(iface)}
	// Reading a usbfs node gives the descriptors of the device. They are
	// read past the runtime's poller: while no URB is pending usbfs
	// reports EPOLLERR, and the poller then fails reads as not pollable.
	var desc []byte
	var rerr error
	if err := rc.Control(func(fd uintptr) { desc, rerr = readAll(int(fd)) }); err != nil {
		return nil, err
	}
	if rerr != nil {
		return nil, rerr
	}
	if d.in, d.out, err = findEndpoints(desc, iface); err != nil {
		return nil, err
	}
	if err := d.ioctl(ioctlClaimInterface, unsafe.Pointer(&d.iface)); errors.Is(err, syscall.EBUSY) {
		return nil, ErrBusy
	} else if err != nil {
		return nil, err
	}
	return d, nil
}

func readAll(fd int) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := syscall.Read(fd, buf)
		switch {
		case err == syscall.EINTR:
		case err != nil:
			return nil, err
		case n == 0:
			return out, nil
		default:
			out = append(out, buf[:n]...)
		}
	}
}

func (d *rawDevice) ioctl(req uintptr, arg unsafe.Pointer) error {
	var errno syscall.Errno
	if err := d.rc.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg))
	}); err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}
	return nil
}

// reap waits, up to deadline (zero: without limit), for the kernel to hand
// back the URB in flight. usbfs shows a completed URB as writability, so
// the runtime's poller does the waiting.
func (d *rawDevice) reap(deadline time.Time) error {
	if err := d.f.SetWriteDeadline(deadline); err != nil {
		return err
	}
	var got uintptr
	var errno syscall.Errno
	if err := d.rc.Write(func(fd uintptr) bool {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlReapURBNDelay, uintptr(unsafe.Pointer(&got)))
		return errno != syscall.EAGAIN
	}); err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}
	if got != uintptr(unsafe.Pointer(&d.urb)) {
		return errors.New("the kernel handed back another transfer")
	}
	return nil
}

// transfer sends buf to ep, or fills it from ep, waiting up to timeout
// (zero: without limit); it returns how many bytes moved. The kernel reads
// buf when the URB is submitted and fills it when the URB is reaped.
func (d *rawDevice) transfer(op string, ep endpoint, buf []byte, timeout time.Duration) (int, error) {
	typ := uint8(urbInterrupt)
	if ep.attributes&3 == transferBulk {
		typ = urbBulk
	}
	d.urb = urb{typ: typ, endpoint: ep.address, buffer: unsafe.Pointer(unsafe.SliceData(buf)), bufferLength: int32(len(buf))}
	if err := d.ioctl(ioctlSubmitURB, unsafe.Pointer(&d.urb)); err != nil {
		return 0, transferError(op, err)
	}
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	err := d.reap(deadline)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		// cancel it and take it back; it may have completed meanwhile
		d.ioctl(ioctlDiscardURB, unsafe.Pointer(&d.urb))
		if err = d.reap(time.Time{}); err == nil && d.urb.status != 0 {
			return 0, ErrTimeout
		}
	}
	if err != nil {
		return 0, transferError(op, err)
	}
	if d.urb.status != 0 {
		return 0, transferError(op, syscall.Errno(-d.urb.status))
	}
	return int(d.urb.actualLength), nil
}

func transferError(op string, err error) error {
	if errors.Is(err, syscall.ENODEV) || errors.Is(err, syscall.ESHUTDOWN) {
		return fmt.Errorf("usb: %s: device disconnected", op)
	}
	return fmt.Errorf("usb: %s: %w", op, err)
}

func (d *rawDevice) Write(p []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	_, err := d.transfer("write", d.out, p, 0)
	return err
}

func (d *rawDevice) Read(timeout time.Duration) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, ErrClosed
	}
	size := d.in.maxPacket
	if size == 0 {
		size = 64
	}
	buf := make([]byte, size)
	n, err := d.transfer("read", d.in, buf, timeout)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (d *rawDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	d.ioctl(ioctlReleaseInterface, unsafe.Pointer(&d.iface))
	return d.f.Close()
}
