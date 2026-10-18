// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package ledger talks to the Cardano app of Ledger devices over APDUs, in
// the command sets of app versions 7 and 8. It follows the Cardano
// Foundation's ledgerjs-hw-app-cardano (Apache-2.0), from which its
// serializations and checks are ported.
package ledger

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Exchanger sends one APDU to the device and returns its response, status
// word included.
type Exchanger interface {
	Exchange(apdu []byte) ([]byte, error)
	Close() error
}

// HIDDevice exchanges 64-byte HID reports.
type HIDDevice interface {
	Write(p []byte) error
	Read(timeout time.Duration) ([]byte, error)
	Close() error
}

const (
	hidChannel    = 0x0101
	hidTagAPDU    = 0x05
	hidPacketSize = 64
	// readTimeout bounds each wait for the device, which may wait for the
	// person to confirm.
	readTimeout = 5 * time.Minute
)

// HIDTransport frames APDUs into the HID reports of Ledger devices.
type HIDTransport struct {
	dev HIDDevice
}

// NewHIDTransport wraps an open HID interface of a Ledger.
func NewHIDTransport(dev HIDDevice) *HIDTransport { return &HIDTransport{dev: dev} }

// Close closes the device.
func (t *HIDTransport) Close() error { return t.dev.Close() }

// Exchange writes an APDU and reads the response.
func (t *HIDTransport) Exchange(apdu []byte) ([]byte, error) {
	if err := t.write(apdu); err != nil {
		return nil, err
	}
	return t.read()
}

func (t *HIDTransport) write(apdu []byte) error {
	data := binary.BigEndian.AppendUint16(nil, uint16(len(apdu)))
	data = append(data, apdu...)
	for seq := 0; len(data) > 0; seq++ {
		p := make([]byte, hidPacketSize)
		binary.BigEndian.PutUint16(p, hidChannel)
		p[2] = hidTagAPDU
		binary.BigEndian.PutUint16(p[3:], uint16(seq))
		n := copy(p[5:], data)
		data = data[n:]
		if err := t.dev.Write(p); err != nil {
			return err
		}
	}
	return nil
}

func (t *HIDTransport) read() ([]byte, error) {
	var out []byte
	want := -1
	for seq := 0; want < 0 || len(out) < want; {
		p, err := t.dev.Read(readTimeout)
		if err != nil {
			return nil, err
		}
		if len(p) < 5 || binary.BigEndian.Uint16(p) != hidChannel || p[2] != hidTagAPDU {
			continue
		}
		if int(binary.BigEndian.Uint16(p[3:])) != seq {
			return nil, errors.New("ledger: unexpected packet sequence")
		}
		body := p[5:]
		if seq == 0 {
			if len(body) < 2 {
				return nil, errors.New("ledger: short response")
			}
			want = int(binary.BigEndian.Uint16(body))
			body = body[2:]
		}
		out = append(out, body...)
		seq++
	}
	return out[:want], nil
}

// SpeculosTransport talks to the Speculos emulator over its APDU TCP port:
// each APDU goes with a 4-byte length, and each response comes with the
// length of its data, then the data and the status word.
type SpeculosTransport struct {
	conn net.Conn
}

// DialSpeculos connects to the APDU port of Speculos at addr (host:port).
func DialSpeculos(addr string) (*SpeculosTransport, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return &SpeculosTransport{conn: c}, nil
}

// Close closes the connection.
func (t *SpeculosTransport) Close() error { return t.conn.Close() }

// Exchange sends an APDU and reads the response.
func (t *SpeculosTransport) Exchange(apdu []byte) ([]byte, error) {
	msg := binary.BigEndian.AppendUint32(nil, uint32(len(apdu)))
	if _, err := t.conn.Write(append(msg, apdu...)); err != nil {
		return nil, err
	}
	if err := t.conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return nil, err
	}
	var head [4]byte
	if _, err := io.ReadFull(t.conn, head[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n > 0xffff {
		return nil, fmt.Errorf("ledger: response of %d bytes from Speculos", n)
	}
	resp := make([]byte, n+2)
	if _, err := io.ReadFull(t.conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
