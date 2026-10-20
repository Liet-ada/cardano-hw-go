// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package usb

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Report descriptors of a Ledger: its APDU interface and its FIDO one.
var (
	ledgerAPDUDescriptor = []byte{
		0x06, 0xa0, 0xff, 0x09, 0x01, 0xa1, 0x01,
		0x09, 0x03, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x08,
		0x09, 0x04, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x08,
		0xc0,
	}
	ledgerFIDODescriptor = []byte{
		0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01,
		0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
		0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02,
		0xc0,
	}
)

// writeTree writes files under root; a value that starts with "->" makes a
// symbolic link to the rest.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		var err error
		if target, ok := strings.CutPrefix(content, "->"); ok {
			err = os.Symlink(target, p)
		} else {
			err = os.WriteFile(p, []byte(content), 0o644)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// fakeSys points sysRoot and devRoot at a tree like the one Linux shows
// with a Trezor Safe 7, a Ledger over USB and over Bluetooth, a keyboard
// and a device that left while being listed.
func fakeSys(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	usb1 := "devices/pci0000:00/0000:00:14.0/usb1"
	writeTree(t, root, map[string]string{
		usb1 + "/idVendor":  "1d6b\n",
		usb1 + "/idProduct": "0002\n",
		usb1 + "/busnum":    "1\n",
		usb1 + "/devnum":    "1\n",
		usb1 + "/product":   "xHCI Host Controller\n",

		usb1 + "/1-1/idVendor":                 "1209\n",
		usb1 + "/1-1/idProduct":                "53c1\n",
		usb1 + "/1-1/busnum":                   "1\n",
		usb1 + "/1-1/devnum":                   "7\n",
		usb1 + "/1-1/product":                  "Trezor Safe 7\n",
		usb1 + "/1-1/serial":                   "3C0F2A61B1E4D2F09A8C7B55\n",
		usb1 + "/1-1/1-1:1.0/bInterfaceNumber": "00\n",

		usb1 + "/1-2/idVendor":                                          "2c97\n",
		usb1 + "/1-2/idProduct":                                         "5011\n",
		usb1 + "/1-2/busnum":                                            "1\n",
		usb1 + "/1-2/devnum":                                            "12\n",
		usb1 + "/1-2/product":                                           "Nano S Plus\n",
		usb1 + "/1-2/serial":                                            "0001\n",
		usb1 + "/1-2/1-2:1.0/bInterfaceNumber":                          "00\n",
		usb1 + "/1-2/1-2:1.0/0003:2C97:5011.0001/uevent":                "DRIVER=hid-generic\nHID_ID=0003:00002C97:00005011\nHID_NAME=Ledger Nano S Plus\nHID_UNIQ=0001\n",
		usb1 + "/1-2/1-2:1.0/0003:2C97:5011.0001/report_descriptor":     string(ledgerAPDUDescriptor),
		usb1 + "/1-2/1-2:1.0/0003:2C97:5011.0001/hidraw/hidraw0/dev":    "245:0\n",
		usb1 + "/1-2/1-2:1.0/0003:2C97:5011.0001/hidraw/hidraw0/device": "->../../../0003:2C97:5011.0001",
		usb1 + "/1-2/1-2:1.1/bInterfaceNumber":                          "01\n",
		usb1 + "/1-2/1-2:1.1/0003:2C97:5011.0002/uevent":                "DRIVER=hid-generic\nHID_ID=0003:00002C97:00005011\nHID_NAME=Ledger Nano S Plus\n",
		usb1 + "/1-2/1-2:1.1/0003:2C97:5011.0002/report_descriptor":     string(ledgerFIDODescriptor),
		usb1 + "/1-2/1-2:1.1/0003:2C97:5011.0002/hidraw/hidraw1/device": "->../../../0003:2C97:5011.0002",

		usb1 + "/1-3/idVendor":                                          "046d\n",
		usb1 + "/1-3/idProduct":                                         "c31c\n",
		usb1 + "/1-3/busnum":                                            "1\n",
		usb1 + "/1-3/devnum":                                            "3\n",
		usb1 + "/1-3/1-3:1.0/bInterfaceNumber":                          "00\n",
		usb1 + "/1-3/1-3:1.0/0003:046D:C31C.0004/uevent":                "HID_ID=0003:0000046D:0000C31C\n",
		usb1 + "/1-3/1-3:1.0/0003:046D:C31C.0004/report_descriptor":     "\x05\x01\x09\x06\xa1\x01\x05\x07\xc0",
		usb1 + "/1-3/1-3:1.0/0003:046D:C31C.0004/hidraw/hidraw3/device": "->../../../0003:046D:C31C.0004",

		"devices/virtual/misc/uhid/0005:2C97:5011.0003/uevent":                "HID_ID=0005:00002C97:00005011\nHID_NAME=Nano X\n",
		"devices/virtual/misc/uhid/0005:2C97:5011.0003/hidraw/hidraw2/device": "->../../../0005:2C97:5011.0003",

		"devices/pci0000:00/0000:00:14.0/usb2/2-1/idVendor":  "1209\n",
		"devices/pci0000:00/0000:00:14.0/usb2/2-1/idProduct": "53c1\n",

		"bus/usb/devices/usb1":    "->../../../" + usb1,
		"bus/usb/devices/1-1":     "->../../../" + usb1 + "/1-1",
		"bus/usb/devices/1-1:1.0": "->../../../" + usb1 + "/1-1/1-1:1.0",
		"bus/usb/devices/1-2":     "->../../../" + usb1 + "/1-2",
		"bus/usb/devices/1-3":     "->../../../" + usb1 + "/1-3",
		"bus/usb/devices/2-1":     "->../../../devices/pci0000:00/0000:00:14.0/usb2/2-1",

		"class/hidraw/hidraw0": "->../../" + usb1 + "/1-2/1-2:1.0/0003:2C97:5011.0001/hidraw/hidraw0",
		"class/hidraw/hidraw1": "->../../" + usb1 + "/1-2/1-2:1.1/0003:2C97:5011.0002/hidraw/hidraw1",
		"class/hidraw/hidraw2": "->../../devices/virtual/misc/uhid/0005:2C97:5011.0003/hidraw/hidraw2",
		"class/hidraw/hidraw3": "->../../" + usb1 + "/1-3/1-3:1.0/0003:046D:C31C.0004/hidraw/hidraw3",
	})
	oldSys, oldDev := sysRoot, devRoot
	sysRoot, devRoot = root, "/dev"
	t.Cleanup(func() { sysRoot, devRoot = oldSys, oldDev })
}

func TestListUSB(t *testing.T) {
	fakeSys(t)
	trezor := Info{VendorID: 0x1209, ProductID: 0x53c1, Path: "/dev/bus/usb/001/007", Product: "Trezor Safe 7", Serial: "3C0F2A61B1E4D2F09A8C7B55"}
	ledger := Info{VendorID: 0x2c97, ProductID: 0x5011, Interface: 2, Path: "/dev/bus/usb/001/012", Product: "Nano S Plus", Serial: "0001"}
	for _, c := range []struct {
		m     Matcher
		iface int
		want  []Info
	}{
		{Matcher{0x1209, 0x53c1}, 0, []Info{trezor}},
		{Matcher{0x1209, 0}, 0, []Info{trezor}},
		{Matcher{0x2c97, 0}, 2, []Info{ledger}},
		{Matcher{0x1209, 0x53c0}, 0, nil},
		{Matcher{0x534c, 0x0001}, 0, nil},
	} {
		got, err := listUSB(c.m, c.iface)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%04x:%04x: %+v, want %+v", c.m.VendorID, c.m.ProductID, got, c.want)
		}
	}
}

func TestListHIDRaw(t *testing.T) {
	fakeSys(t)
	got, err := listHIDRaw(Matcher{VendorID: 0x2c97})
	if err != nil {
		t.Fatal(err)
	}
	want := []Info{
		{VendorID: 0x2c97, ProductID: 0x5011, Interface: 0, Path: "/dev/hidraw0", Product: "Nano S Plus", Serial: "0001", UsagePage: 0xffa0},
		{VendorID: 0x2c97, ProductID: 0x5011, Interface: 1, Path: "/dev/hidraw1", Product: "Nano S Plus", Serial: "0001", UsagePage: 0xf1d0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%+v, want %+v", got, want)
	}

	sysRoot = t.TempDir() // no hidraw node at all
	if got, err := listHIDRaw(Matcher{VendorID: 0x2c97}); err != nil || got != nil {
		t.Errorf("without hidraw: %+v, %v", got, err)
	}
}

func TestParseHIDID(t *testing.T) {
	for _, c := range []struct {
		uevent        string
		bus, vid, pid uint16
		ok            bool
	}{
		{"DRIVER=hid-generic\nHID_ID=0003:00002C97:00005011\nHID_NAME=x\n", 3, 0x2c97, 0x5011, true},
		{"HID_ID=0005:0000046D:0000B023", 5, 0x46d, 0xb023, true},
		{"HID_NAME=x\n", 0, 0, 0, false},
		{"HID_ID=0003:00002C97\n", 0, 0, 0, false},
		{"HID_ID=0003:00012C97:00005011\n", 0, 0, 0, false},
		{"HID_ID=0003:zz:00005011\n", 0, 0, 0, false},
	} {
		bus, vid, pid, ok := parseHIDID(c.uevent)
		if bus != c.bus || vid != c.vid || pid != c.pid || ok != c.ok {
			t.Errorf("%q: %x %x %x %v", c.uevent, bus, vid, pid, ok)
		}
	}
}

func TestPrimaryUsagePage(t *testing.T) {
	for _, c := range []struct {
		name string
		desc []byte
		want uint16
	}{
		{"ledger apdu", ledgerAPDUDescriptor, 0xffa0},
		{"ledger fido", ledgerFIDODescriptor, 0xf1d0},
		{"keyboard, a page inside the collection", []byte{0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0xc0}, 0x01},
		{"four-byte page", []byte{0x07, 0xa0, 0xff, 0x00, 0x00, 0xa1, 0x01}, 0xffa0},
		{"long item first", []byte{0xfe, 0x02, 0x10, 0xaa, 0xbb, 0x06, 0xa0, 0xff, 0xa1, 0x01}, 0xffa0},
		{"no collection", []byte{0x06, 0xa0, 0xff, 0x09, 0x01}, 0},
		{"cut item", []byte{0x06, 0xa0}, 0},
		{"cut long item", []byte{0xfe}, 0},
		{"empty", nil, 0},
	} {
		if got := primaryUsagePage(c.desc); got != c.want {
			t.Errorf("%s: %#x, want %#x", c.name, got, c.want)
		}
	}
}

func interfaceDesc(number, alt, endpoints byte) []byte {
	return []byte{9, descInterface, number, alt, endpoints, 0xff, 0, 0, 0}
}

func endpointDesc(address, attributes byte, size uint16) []byte {
	d := binary.LittleEndian.AppendUint16([]byte{7, descEndpoint, address, attributes}, size)
	return append(d, 1) // bInterval
}

// trezorDescriptors are the descriptors usbfs gives for a Trezor, laid
// out as in trezor-firmware: the wire interface 0 on endpoints 0x81/0x01,
// the debug interface 1 on 0x82/0x02, here behind an isochronous endpoint,
// and an interface 2 with endpoints only in its alternate setting 1.
func trezorDescriptors() []byte {
	var body []byte
	for _, d := range [][]byte{
		interfaceDesc(0, 0, 2), endpointDesc(0x81, transferInterrupt, 64), endpointDesc(0x01, transferInterrupt, 64),
		interfaceDesc(1, 0, 3), endpointDesc(0x86, 0x01, 64), endpointDesc(0x82, transferInterrupt, 64), endpointDesc(0x02, transferInterrupt, 64),
		interfaceDesc(2, 0, 0),
		interfaceDesc(2, 1, 2), endpointDesc(0x83, transferBulk, 512), endpointDesc(0x03, transferBulk, 512),
	} {
		body = append(body, d...)
	}
	device := []byte{18, 1, 0x10, 0x02, 0, 0, 0, 64, 0x09, 0x12, 0xc1, 0x53, 0, 1, 1, 2, 3, 1}
	config := binary.LittleEndian.AppendUint16([]byte{9, descConfig}, uint16(9+len(body)))
	config = append(config, 3, 1, 0, 0x80, 0xfa)
	return append(append(device, config...), body...)
}

func TestFindEndpoints(t *testing.T) {
	desc := trezorDescriptors()
	for _, c := range []struct {
		iface   int
		in, out endpoint
	}{
		{0, endpoint{0x81, transferInterrupt, 64}, endpoint{0x01, transferInterrupt, 64}},
		{1, endpoint{0x82, transferInterrupt, 64}, endpoint{0x02, transferInterrupt, 64}},
	} {
		in, out, err := findEndpoints(desc, c.iface)
		if err != nil || in != c.in || out != c.out {
			t.Errorf("interface %d: %+v %+v %v", c.iface, in, out, err)
		}
	}
	for name, c := range map[string]struct {
		desc  []byte
		iface int
	}{
		"only an alternate setting": {desc, 2},
		"no such interface":         {desc, 5},
		"cut":                       {desc[:len(desc)-35], 1}, // inside the endpoint 0x02
		"zero length":               {append([]byte{0}, desc[1:]...), 0},
		"empty":                     {nil, 0},
	} {
		if in, out, err := findEndpoints(c.desc, c.iface); err == nil {
			t.Errorf("%s: %+v %+v", name, in, out)
		}
	}
}
