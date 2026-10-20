// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package usb

// What Linux shows of USB devices in sysfs, and the descriptors they give.
// This file only reads files and bytes, so it has no build tag and its
// tests run on any system; the calls into the kernel are in raw_linux.go
// and hid_linux.go.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Where Linux shows the devices; tests point them at a tree of their own.
var (
	sysRoot = "/sys"
	devRoot = "/dev"
)

// attr reads an attribute of a sysfs directory, "" if it has none.
func attr(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func numAttr(dir, name string, base, bits int) (uint64, error) {
	return strconv.ParseUint(attr(dir, name), base, bits)
}

// listUSB lists the USB devices that match m, with their usbfs node as
// path.
func listUSB(m Matcher, iface int) ([]Info, error) {
	dir := filepath.Join(sysRoot, "bus", "usb", "devices")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("usb: cannot list USB devices: %w", err)
	}
	var out []Info
	for _, e := range entries {
		if strings.Contains(e.Name(), ":") {
			continue // an interface, not a device
		}
		d := filepath.Join(dir, e.Name())
		vid, err1 := numAttr(d, "idVendor", 16, 16)
		pid, err2 := numAttr(d, "idProduct", 16, 16)
		if err1 != nil || err2 != nil || !m.matches(uint16(vid), uint16(pid)) {
			continue
		}
		bus, err1 := numAttr(d, "busnum", 10, 16)
		num, err2 := numAttr(d, "devnum", 10, 16)
		if err1 != nil || err2 != nil {
			continue // gone while listing
		}
		out = append(out, Info{
			VendorID:  uint16(vid),
			ProductID: uint16(pid),
			Interface: iface,
			Path:      filepath.Join(devRoot, "bus", "usb", fmt.Sprintf("%03d", bus), fmt.Sprintf("%03d", num)),
			Product:   attr(d, "product"),
			Serial:    attr(d, "serial"),
		})
	}
	return out, nil
}

// busUSB is the bus of USB HID devices in HID_ID.
const busUSB = 0x03

// listHIDRaw lists the hidraw nodes of USB devices that match m. In sysfs a
// hidraw node belongs to a HID device, under the USB interface it comes
// from, under the USB device.
func listHIDRaw(m Matcher) ([]Info, error) {
	dir := filepath.Join(sysRoot, "class", "hidraw")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // no hidraw node at all
	}
	if err != nil {
		return nil, fmt.Errorf("usb: cannot list HID devices: %w", err)
	}
	var out []Info
	for _, e := range entries {
		hid, err := filepath.EvalSymlinks(filepath.Join(dir, e.Name(), "device"))
		if err != nil {
			continue
		}
		bus, vid, pid, ok := parseHIDID(attr(hid, "uevent"))
		if !ok || bus != busUSB || !m.matches(vid, pid) {
			continue
		}
		intf := filepath.Dir(hid)
		n, err := numAttr(intf, "bInterfaceNumber", 16, 8)
		if err != nil {
			continue
		}
		desc, _ := os.ReadFile(filepath.Join(hid, "report_descriptor"))
		dev := filepath.Dir(intf)
		out = append(out, Info{
			VendorID:  vid,
			ProductID: pid,
			Interface: int(n),
			Path:      filepath.Join(devRoot, e.Name()),
			Product:   attr(dev, "product"),
			Serial:    attr(dev, "serial"),
			UsagePage: primaryUsagePage(desc),
		})
	}
	return out, nil
}

// parseHIDID reads the HID_ID line of a HID device's uevent: bus, vendor
// and product, in hex.
func parseHIDID(uevent string) (bus, vid, pid uint16, ok bool) {
	for _, line := range strings.Split(uevent, "\n") {
		v, found := strings.CutPrefix(line, "HID_ID=")
		if !found {
			continue
		}
		parts := strings.Split(v, ":")
		if len(parts) != 3 {
			return 0, 0, 0, false
		}
		var n [3]uint64
		for i, p := range parts {
			var err error
			if n[i], err = strconv.ParseUint(p, 16, 16); err != nil {
				return 0, 0, 0, false
			}
		}
		return uint16(n[0]), uint16(n[1]), uint16(n[2]), true
	}
	return 0, 0, 0, false
}

// primaryUsagePage returns the usage page of the first top-level collection
// of a HID report descriptor, 0 if there is none.
func primaryUsagePage(desc []byte) uint16 {
	var page uint32
	for i := 0; i < len(desc); {
		prefix := desc[i]
		if prefix == 0xfe { // a long item: data size, tag, data
			if i+1 >= len(desc) {
				return 0
			}
			i += 3 + int(desc[i+1])
			continue
		}
		size := int(prefix & 3)
		if size == 3 {
			size = 4
		}
		if i+1+size > len(desc) {
			return 0
		}
		var v uint32
		for j := size; j > 0; j-- {
			v = v<<8 | uint32(desc[i+j])
		}
		switch prefix & 0xfc {
		case 0x04: // Usage Page
			page = v
		case 0xa0: // Collection
			return uint16(page)
		}
		i += 1 + size
	}
	return 0
}

// endpoint is an endpoint of an interface, from its descriptor.
type endpoint struct {
	address    uint8
	attributes uint8 // the transfer type in the low two bits
	maxPacket  int
}

// Descriptor types and transfer types.
const (
	descConfig        = 2
	descInterface     = 4
	descEndpoint      = 5
	transferBulk      = 2
	transferInterrupt = 3
)

// findEndpoints finds the first interrupt or bulk endpoints in and out of
// interface iface, alternate setting 0, in the descriptors usbfs gives:
// the device descriptor, then each configuration with its interfaces and
// endpoints.
func findEndpoints(desc []byte, iface int) (in, out endpoint, err error) {
	inIface := false
	for i := 0; i+2 <= len(desc); {
		n := int(desc[i])
		if n < 2 || i+n > len(desc) {
			break
		}
		d := desc[i : i+n]
		switch d[1] {
		case descConfig:
			inIface = false
		case descInterface:
			inIface = n >= 4 && int(d[2]) == iface && d[3] == 0
		case descEndpoint:
			if !inIface || n < 6 {
				break
			}
			ep := endpoint{address: d[2], attributes: d[3], maxPacket: int(binary.LittleEndian.Uint16(d[4:]) & 0x7ff)}
			if t := ep.attributes & 3; t != transferBulk && t != transferInterrupt {
				break
			}
			if ep.address&0x80 != 0 {
				if in.address == 0 {
					in = ep
				}
			} else if out.address == 0 {
				out = ep
			}
		}
		if in.address != 0 && out.address != 0 {
			return in, out, nil
		}
		i += n
	}
	return endpoint{}, endpoint{}, errors.New("no endpoints in and out")
}
