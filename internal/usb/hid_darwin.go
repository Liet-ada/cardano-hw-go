// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build darwin && cgo

package usb

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/hid/IOHIDManager.h>
#include <IOKit/hid/IOHIDDevice.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <CoreFoundation/CoreFoundation.h>

#define HW_HID_QUEUE 64
#define HW_HID_REPORT 128

typedef struct {
	UInt32 vid, pid, usagePage;
	UInt64 id;
	char product[128], serial[128];
} hw_hid_info;

static UInt32 hid_u32(IOHIDDeviceRef d, CFStringRef key) {
	CFTypeRef v = IOHIDDeviceGetProperty(d, key);
	UInt32 out = 0;
	if (v && CFGetTypeID(v) == CFNumberGetTypeID()) CFNumberGetValue((CFNumberRef)v, kCFNumberSInt32Type, &out);
	return out;
}

static void hid_str(IOHIDDeviceRef d, CFStringRef key, char *buf, int len) {
	buf[0] = 0;
	CFTypeRef v = IOHIDDeviceGetProperty(d, key);
	if (v && CFGetTypeID(v) == CFStringGetTypeID()) CFStringGetCString((CFStringRef)v, buf, len, kCFStringEncodingUTF8);
}

// hw_hid_list fills up to max entries for HID interfaces of vendor vid and
// product pid (0: any) and returns how many there are.
static int hw_hid_list(UInt32 vid, UInt32 pid, hw_hid_info *out, int max) {
	IOHIDManagerRef m = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
	if (!m) return -1;
	IOHIDManagerSetDeviceMatching(m, NULL);
	CFSetRef set = IOHIDManagerCopyDevices(m);
	int n = 0;
	if (set) {
		CFIndex count = CFSetGetCount(set);
		IOHIDDeviceRef *devs = calloc(count ? count : 1, sizeof *devs);
		CFSetGetValues(set, (const void **)devs);
		for (CFIndex i = 0; i < count; i++) {
			IOHIDDeviceRef d = devs[i];
			UInt32 v = hid_u32(d, CFSTR(kIOHIDVendorIDKey)), p = hid_u32(d, CFSTR(kIOHIDProductIDKey));
			if (v != vid || (pid && p != pid)) continue;
			if (n < max) {
				out[n].vid = v; out[n].pid = p;
				out[n].usagePage = hid_u32(d, CFSTR(kIOHIDPrimaryUsagePageKey));
				out[n].id = 0;
				IORegistryEntryGetRegistryEntryID(IOHIDDeviceGetService(d), &out[n].id);
				hid_str(d, CFSTR(kIOHIDProductKey), out[n].product, sizeof out[n].product);
				hid_str(d, CFSTR(kIOHIDSerialNumberKey), out[n].serial, sizeof out[n].serial);
			}
			n++;
		}
		free(devs);
		CFRelease(set);
	}
	CFRelease(m);
	return n;
}

typedef struct {
	IOHIDDeviceRef dev;
	pthread_t thread;
	CFRunLoopRef loop;
	pthread_mutex_t mu;
	pthread_cond_t cond;
	int ready, closed, removed;
	unsigned char in[HW_HID_REPORT];
	unsigned char queue[HW_HID_QUEUE][HW_HID_REPORT];
	int lens[HW_HID_QUEUE];
	int head, count;
} hw_hid;

static void hid_report(void *ctx, IOReturn result, void *sender, IOHIDReportType type, uint32_t id, uint8_t *report, CFIndex len) {
	hw_hid *h = ctx;
	pthread_mutex_lock(&h->mu);
	if (h->count < HW_HID_QUEUE) {
		int slot = (h->head + h->count) % HW_HID_QUEUE;
		if (len > HW_HID_REPORT) len = HW_HID_REPORT;
		memcpy(h->queue[slot], report, len);
		h->lens[slot] = (int)len;
		h->count++;
		pthread_cond_signal(&h->cond);
	}
	pthread_mutex_unlock(&h->mu);
}

static void hid_removed(void *ctx, IOReturn result, void *sender) {
	hw_hid *h = ctx;
	pthread_mutex_lock(&h->mu);
	h->removed = 1;
	pthread_cond_broadcast(&h->cond);
	pthread_mutex_unlock(&h->mu);
}

static void *hid_thread(void *arg) {
	hw_hid *h = arg;
	h->loop = CFRunLoopGetCurrent();
	IOHIDDeviceScheduleWithRunLoop(h->dev, h->loop, kCFRunLoopDefaultMode);
	pthread_mutex_lock(&h->mu);
	h->ready = 1;
	pthread_cond_broadcast(&h->cond);
	pthread_mutex_unlock(&h->mu);
	CFRunLoopRun();
	IOHIDDeviceUnscheduleFromRunLoop(h->dev, h->loop, kCFRunLoopDefaultMode);
	return NULL;
}

// hw_hid_open opens the HID interface with registry entry id.
static IOReturn hw_hid_open(UInt64 id, hw_hid **out) {
	io_service_t s = IOServiceGetMatchingService(MACH_PORT_NULL, IORegistryEntryIDMatching(id));
	if (!s) return kIOReturnNoDevice;
	IOHIDDeviceRef dev = IOHIDDeviceCreate(kCFAllocatorDefault, s);
	IOObjectRelease(s);
	if (!dev) return kIOReturnNoDevice;
	IOReturn r = IOHIDDeviceOpen(dev, kIOHIDOptionsTypeNone);
	if (r != kIOReturnSuccess) {
		CFRelease(dev);
		return r;
	}
	hw_hid *h = calloc(1, sizeof *h);
	h->dev = dev;
	pthread_mutex_init(&h->mu, NULL);
	pthread_cond_init(&h->cond, NULL);
	IOHIDDeviceRegisterInputReportCallback(dev, h->in, sizeof h->in, hid_report, h);
	IOHIDDeviceRegisterRemovalCallback(dev, hid_removed, h);
	pthread_create(&h->thread, NULL, hid_thread, h);
	pthread_mutex_lock(&h->mu);
	while (!h->ready) pthread_cond_wait(&h->cond, &h->mu);
	pthread_mutex_unlock(&h->mu);
	*out = h;
	return kIOReturnSuccess;
}

// A synchronous report ends with kIOReturnAborted when its thread takes a
// signal, and the Go runtime signals its threads: block them meanwhile.
static IOReturn hw_hid_write(hw_hid *h, const uint8_t *buf, CFIndex len) {
	sigset_t all, old;
	sigfillset(&all);
	pthread_sigmask(SIG_BLOCK, &all, &old);
	IOReturn r = IOHIDDeviceSetReport(h->dev, kIOHIDReportTypeOutput, 0, buf, len);
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	return r;
}

// hw_hid_read waits up to timeout_ms (0: forever) for a report; it returns
// its length, 0 on timeout, -1 if the device was removed.
static int hw_hid_read(hw_hid *h, uint8_t *buf, int len, int timeout_ms) {
	pthread_mutex_lock(&h->mu);
	struct timespec deadline;
	if (timeout_ms > 0) {
		struct timeval now;
		gettimeofday(&now, NULL);
		long ns = now.tv_usec * 1000L + (long)(timeout_ms % 1000) * 1000000L;
		deadline.tv_sec = now.tv_sec + timeout_ms / 1000 + ns / 1000000000L;
		deadline.tv_nsec = ns % 1000000000L;
	}
	while (h->count == 0 && !h->removed && !h->closed) {
		if (timeout_ms > 0) {
			if (pthread_cond_timedwait(&h->cond, &h->mu, &deadline) == ETIMEDOUT) break;
		} else {
			pthread_cond_wait(&h->cond, &h->mu);
		}
	}
	int n = 0;
	if (h->count > 0) {
		n = h->lens[h->head];
		if (n > len) n = len;
		memcpy(buf, h->queue[h->head], n);
		h->head = (h->head + 1) % HW_HID_QUEUE;
		h->count--;
	} else if (h->removed || h->closed) {
		n = -1;
	}
	pthread_mutex_unlock(&h->mu);
	return n;
}

static void hw_hid_close(hw_hid *h) {
	pthread_mutex_lock(&h->mu);
	h->closed = 1;
	pthread_cond_broadcast(&h->cond);
	pthread_mutex_unlock(&h->mu);
	CFRunLoopStop(h->loop);
	pthread_join(h->thread, NULL);
	IOHIDDeviceClose(h->dev, kIOHIDOptionsTypeNone);
	CFRelease(h->dev);
	pthread_mutex_destroy(&h->mu);
	pthread_cond_destroy(&h->cond);
	free(h);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

// ListHID lists the HID interfaces of devices that match m.
func ListHID(m Matcher) ([]Info, error) {
	const max = 32
	var infos [max]C.hw_hid_info
	n := int(C.hw_hid_list(C.UInt32(m.VendorID), C.UInt32(m.ProductID), &infos[0], max))
	if n < 0 {
		return nil, fmt.Errorf("usb: cannot list HID devices")
	}
	var out []Info
	for i := 0; i < n && i < max; i++ {
		out = append(out, Info{
			VendorID:  uint16(infos[i].vid),
			ProductID: uint16(infos[i].pid),
			UsagePage: uint16(infos[i].usagePage),
			Path:      strconv.FormatUint(uint64(infos[i].id), 16),
			Product:   C.GoString(&infos[i].product[0]),
			Serial:    C.GoString(&infos[i].serial[0]),
		})
	}
	return out, nil
}

type hidDevice struct {
	mu     sync.Mutex
	h      *C.hw_hid
	closed bool
}

// OpenHID opens a listed HID interface.
func OpenHID(info Info) (Device, error) {
	id, err := strconv.ParseUint(info.Path, 16, 64)
	if err != nil {
		return nil, fmt.Errorf("usb: invalid path %q", info.Path)
	}
	var h *C.hw_hid
	if r := C.hw_hid_open(C.UInt64(id), &h); r != C.kIOReturnSuccess {
		return nil, ioErr("open", r)
	}
	return &hidDevice{h: h}, nil
}

// Write sends an output report (without a report id).
func (d *hidDevice) Write(p []byte) error {
	if d.closed {
		return ErrClosed
	}
	if r := C.hw_hid_write(d.h, (*C.uint8_t)(unsafe.Pointer(&p[0])), C.CFIndex(len(p))); r != C.kIOReturnSuccess {
		return ioErr("write", r)
	}
	return nil
}

func (d *hidDevice) Read(timeout time.Duration) ([]byte, error) {
	if d.closed {
		return nil, ErrClosed
	}
	buf := make([]byte, 128)
	ms := int(timeout / time.Millisecond)
	if timeout > 0 && ms == 0 {
		ms = 1
	}
	n := int(C.hw_hid_read(d.h, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.int(len(buf)), C.int(ms)))
	switch {
	case n < 0:
		return nil, errors.New("usb: device disconnected")
	case n == 0:
		return nil, ErrTimeout
	}
	return buf[:n], nil
}

func (d *hidDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		C.hw_hid_close(d.h)
	}
	return nil
}
