// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build darwin && cgo

package usb

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/IOUSBLib.h>
#include <CoreFoundation/CoreFoundation.h>

typedef struct {
	IOUSBDeviceInterface320 **dev;
	IOUSBInterfaceInterface300 **intf;
	UInt8 pipeIn, pipeOut;
	UInt16 packetSize;
} hw_raw;

static int prop_u32(io_service_t s, CFStringRef key, UInt32 *out) {
	CFTypeRef v = IORegistryEntrySearchCFProperty(s, kIOServicePlane, key, kCFAllocatorDefault, 0);
	if (!v) return 0;
	int ok = 0;
	if (CFGetTypeID(v) == CFNumberGetTypeID()) {
		ok = CFNumberGetValue((CFNumberRef)v, kCFNumberSInt32Type, out);
	}
	CFRelease(v);
	return ok;
}

static void prop_str(io_service_t s, CFStringRef key, char *buf, int len) {
	buf[0] = 0;
	CFTypeRef v = IORegistryEntrySearchCFProperty(s, kIOServicePlane, key, kCFAllocatorDefault, 0);
	if (!v) return;
	// the buffer's content is unspecified when the string does not fit
	if (CFGetTypeID(v) != CFStringGetTypeID() || !CFStringGetCString((CFStringRef)v, buf, len, kCFStringEncodingUTF8)) {
		buf[0] = 0;
	}
	CFRelease(v);
}

// devices iterates over the USB devices; *ok is 0 on error. A zero
// iterator with *ok set means there are none.
static io_iterator_t devices(int *ok) {
	io_iterator_t it = 0;
	*ok = 1;
	if (IOServiceGetMatchingServices(MACH_PORT_NULL, IOServiceMatching("IOUSBHostDevice"), &it) == KERN_SUCCESS) {
		return it;
	}
	if (IOServiceGetMatchingServices(MACH_PORT_NULL, IOServiceMatching(kIOUSBDeviceClassName), &it) == KERN_SUCCESS) {
		return it;
	}
	*ok = 0;
	return 0;
}

typedef struct {
	UInt32 vid, pid, location;
	char product[128], serial[128];
} hw_raw_info;

// hw_raw_list fills up to max entries for devices of vendor vid and product
// pid (0: any) and returns how many there are.
static int hw_raw_list(UInt32 vid, UInt32 pid, hw_raw_info *out, int max) {
	int ok;
	io_iterator_t it = devices(&ok);
	if (!ok) return -1;
	if (!it) return 0;
	int n = 0;
	io_service_t s;
	while ((s = IOIteratorNext(it))) {
		UInt32 v = 0, p = 0, loc = 0;
		if (prop_u32(s, CFSTR("idVendor"), &v) && prop_u32(s, CFSTR("idProduct"), &p) &&
		    v == vid && (pid == 0 || p == pid) && prop_u32(s, CFSTR("locationID"), &loc)) {
			if (n < max) {
				out[n].vid = v; out[n].pid = p; out[n].location = loc;
				prop_str(s, CFSTR("USB Product Name"), out[n].product, sizeof out[n].product);
				prop_str(s, CFSTR("USB Serial Number"), out[n].serial, sizeof out[n].serial);
			}
			n++;
		}
		IOObjectRelease(s);
	}
	IOObjectRelease(it);
	return n;
}

static IOReturn open_interface(IOUSBDeviceInterface320 **dev, UInt8 number, hw_raw *h) {
	IOUSBFindInterfaceRequest req;
	req.bInterfaceClass = kIOUSBFindInterfaceDontCare;
	req.bInterfaceSubClass = kIOUSBFindInterfaceDontCare;
	req.bInterfaceProtocol = kIOUSBFindInterfaceDontCare;
	req.bAlternateSetting = kIOUSBFindInterfaceDontCare;
	io_iterator_t it = 0;
	IOReturn r = (*dev)->CreateInterfaceIterator(dev, &req, &it);
	if (r != kIOReturnSuccess) return r;
	io_service_t s;
	r = kIOReturnNotFound;
	while ((s = IOIteratorNext(it))) {
		IOCFPlugInInterface **plugin = NULL;
		SInt32 score;
		IOReturn pr = IOCreatePlugInInterfaceForService(s, kIOUSBInterfaceUserClientTypeID, kIOCFPlugInInterfaceID, &plugin, &score);
		IOObjectRelease(s);
		if (pr != kIOReturnSuccess || !plugin) continue;
		IOUSBInterfaceInterface300 **intf = NULL;
		(*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID300), (LPVOID *)&intf);
		IODestroyPlugInInterface(plugin);
		if (!intf) continue;
		UInt8 num = 0;
		(*intf)->GetInterfaceNumber(intf, &num);
		if (num != number) {
			(*intf)->Release(intf);
			continue;
		}
		r = (*intf)->USBInterfaceOpen(intf);
		if (r != kIOReturnSuccess) {
			(*intf)->Release(intf);
			break;
		}
		UInt8 eps = 0;
		(*intf)->GetNumEndpoints(intf, &eps);
		for (UInt8 pipe = 1; pipe <= eps; pipe++) {
			UInt8 dir, epnum, type, interval;
			UInt16 size;
			if ((*intf)->GetPipeProperties(intf, pipe, &dir, &epnum, &type, &size, &interval) != kIOReturnSuccess) continue;
			if (type != kUSBInterrupt && type != kUSBBulk) continue;
			if (dir == kUSBIn && !h->pipeIn) { h->pipeIn = pipe; h->packetSize = size; }
			if (dir == kUSBOut && !h->pipeOut) h->pipeOut = pipe;
		}
		if (!h->pipeIn || !h->pipeOut) {
			// a retry after configuring the device starts afresh
			h->pipeIn = h->pipeOut = 0;
			h->packetSize = 0;
			(*intf)->USBInterfaceClose(intf);
			(*intf)->Release(intf);
			r = kIOReturnNotFound;
			break;
		}
		h->intf = intf;
		r = kIOReturnSuccess;
		break;
	}
	IOObjectRelease(it);
	return r;
}

// hw_raw_open opens interface number of the device at location.
static IOReturn hw_raw_open(UInt32 location, UInt8 number, hw_raw **out) {
	int ok;
	io_iterator_t it = devices(&ok);
	if (!ok) return kIOReturnError;
	if (!it) return kIOReturnNoDevice;
	io_service_t s, found = 0;
	while ((s = IOIteratorNext(it))) {
		UInt32 loc = 0;
		if (!found && prop_u32(s, CFSTR("locationID"), &loc) && loc == location) {
			found = s;
			continue;
		}
		IOObjectRelease(s);
	}
	IOObjectRelease(it);
	if (!found) return kIOReturnNoDevice;

	IOCFPlugInInterface **plugin = NULL;
	SInt32 score;
	IOReturn r = IOCreatePlugInInterfaceForService(found, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &plugin, &score);
	IOObjectRelease(found);
	if (r != kIOReturnSuccess || !plugin) return r ? r : kIOReturnError;
	IOUSBDeviceInterface320 **dev = NULL;
	(*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID320), (LPVOID *)&dev);
	IODestroyPlugInInterface(plugin);
	if (!dev) return kIOReturnError;

	hw_raw *h = calloc(1, sizeof *h);
	if (!h) {
		(*dev)->Release(dev);
		return kIOReturnNoMemory;
	}
	h->dev = dev;
	r = open_interface(dev, number, h);
	if (r == kIOReturnNotFound) {
		// an unconfigured device: open it and select its first configuration
		if ((*dev)->USBDeviceOpen(dev) == kIOReturnSuccess) {
			IOUSBConfigurationDescriptorPtr conf;
			if ((*dev)->GetConfigurationDescriptorPtr(dev, 0, &conf) == kIOReturnSuccess) {
				(*dev)->SetConfiguration(dev, conf->bConfigurationValue);
			}
			(*dev)->USBDeviceClose(dev);
			r = open_interface(dev, number, h);
		}
	}
	if (r != kIOReturnSuccess) {
		(*dev)->Release(dev);
		free(h);
		return r;
	}
	*out = h;
	return kIOReturnSuccess;
}

// A synchronous transfer ends with kIOReturnAborted when its thread takes
// a signal, and the Go runtime signals its threads: block them meanwhile.
static IOReturn hw_raw_write(hw_raw *h, void *buf, UInt32 len) {
	sigset_t all, old;
	sigfillset(&all);
	pthread_sigmask(SIG_BLOCK, &all, &old);
	IOReturn r = (*h->intf)->WritePipe(h->intf, h->pipeOut, buf, len);
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	return r;
}

static IOReturn hw_raw_read(hw_raw *h, void *buf, UInt32 *len) {
	sigset_t all, old;
	sigfillset(&all);
	pthread_sigmask(SIG_BLOCK, &all, &old);
	IOReturn r = (*h->intf)->ReadPipe(h->intf, h->pipeIn, buf, len);
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	return r;
}

static IOReturn hw_raw_abort(hw_raw *h) {
	return (*h->intf)->AbortPipe(h->intf, h->pipeIn);
}

static void hw_raw_close(hw_raw *h) {
	(*h->intf)->USBInterfaceClose(h->intf);
	(*h->intf)->Release(h->intf);
	(*h->dev)->Release(h->dev);
	free(h);
}
*/
import "C"

import (
	"fmt"
	"strconv"
	"sync"
	"time"
)

// ListRaw lists the devices that match m, with the raw interface iface.
func ListRaw(m Matcher, iface int) ([]Info, error) {
	const max = 16
	var infos [max]C.hw_raw_info
	n := int(C.hw_raw_list(C.UInt32(m.VendorID), C.UInt32(m.ProductID), &infos[0], max))
	if n < 0 {
		return nil, fmt.Errorf("usb: cannot list USB devices")
	}
	var out []Info
	for i := 0; i < n && i < max; i++ {
		out = append(out, Info{
			VendorID:  uint16(infos[i].vid),
			ProductID: uint16(infos[i].pid),
			Interface: iface,
			Path:      strconv.FormatUint(uint64(infos[i].location), 16),
			Product:   C.GoString(&infos[i].product[0]),
			Serial:    C.GoString(&infos[i].serial[0]),
		})
	}
	return out, nil
}

type rawDevice struct {
	mu     sync.Mutex // serializes transfers and Close, which frees h
	h      *C.hw_raw
	size   int
	closed bool
}

const (
	ioReturnExclusiveAccess = 0xe00002c5
	ioReturnAborted         = 0xe00002eb
	ioReturnNoDevice        = 0xe00002c0
)

func ioErr(op string, r C.IOReturn) error {
	switch uint32(r) {
	case ioReturnExclusiveAccess:
		return ErrBusy
	case ioReturnNoDevice:
		return fmt.Errorf("usb: %s: device disconnected", op)
	}
	return fmt.Errorf("usb: %s: IOKit error %#x", op, uint32(r))
}

// OpenRaw opens the raw interface of a listed device.
func OpenRaw(info Info) (Device, error) {
	loc, err := strconv.ParseUint(info.Path, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("usb: invalid path %q", info.Path)
	}
	var h *C.hw_raw
	if r := C.hw_raw_open(C.UInt32(loc), C.UInt8(info.Interface), &h); r != C.kIOReturnSuccess {
		return nil, ioErr("open", r)
	}
	size := int(h.packetSize)
	if size == 0 {
		size = 64
	}
	return &rawDevice{h: h, size: size}, nil
}

func (d *rawDevice) Write(p []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	buf := C.CBytes(p)
	defer C.free(buf)
	if r := C.hw_raw_write(d.h, buf, C.UInt32(len(p))); r != C.kIOReturnSuccess {
		return ioErr("write", r)
	}
	return nil
}

type readResult struct {
	data []byte
	r    C.IOReturn
}

// Read blocks in IOKit; a timeout aborts the pending read.
func (d *rawDevice) Read(timeout time.Duration) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, ErrClosed
	}
	done := make(chan readResult, 1)
	go func() {
		buf := C.malloc(C.size_t(d.size))
		defer C.free(buf)
		n := C.UInt32(d.size)
		r := C.hw_raw_read(d.h, buf, &n)
		var data []byte
		if r == C.kIOReturnSuccess {
			data = C.GoBytes(buf, C.int(n))
		}
		done <- readResult{data, r}
	}()
	var timer <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		timer = t.C
	}
	select {
	case res := <-done:
		if res.r != C.kIOReturnSuccess {
			return nil, ioErr("read", res.r)
		}
		return res.data, nil
	case <-timer:
		C.hw_raw_abort(d.h)
		res := <-done
		if res.r == C.kIOReturnSuccess && len(res.data) > 0 {
			return res.data, nil // the data won the race
		}
		return nil, ErrTimeout
	}
}

func (d *rawDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		C.hw_raw_close(d.h)
	}
	return nil
}
