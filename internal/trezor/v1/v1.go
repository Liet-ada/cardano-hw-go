// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package v1 implements Codec v1, the unencrypted protocol of Trezors
// without THP (Model T, Safe 3 and Safe 5 on older firmware) and of the
// emulator's debug link.
package v1

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor/wire"
)

// MaxMessageSize bounds the messages read from a device.
const MaxMessageSize = 1 << 20

// Conn sends and receives Codec v1 messages over a link.
type Conn struct {
	Link wire.Link
}

// Write sends a message: "?##", the type, the length and the data, then
// continuation packets starting with "?".
func (c *Conn) Write(msgType uint16, data []byte) error {
	buf := make([]byte, 0, 8+len(data))
	buf = append(buf, '#', '#')
	buf = binary.BigEndian.AppendUint16(buf, msgType)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(data)))
	buf = append(buf, data...)
	for len(buf) > 0 {
		p := make([]byte, wire.PacketSize)
		p[0] = '?'
		n := copy(p[1:], buf)
		buf = buf[n:]
		if err := c.Link.Write(p); err != nil {
			return err
		}
	}
	return nil
}

// Read returns the next message, waiting up to timeout for all of it (zero
// waits without limit), so that a device sending packets that are not a
// message cannot keep it waiting longer.
func (c *Conn) Read(timeout time.Duration) (uint16, []byte, error) {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	read := func() ([]byte, error) {
		if deadline.IsZero() {
			return c.Link.Read(0)
		}
		wait := time.Until(deadline)
		if wait <= 0 {
			return nil, wire.ErrTimeout
		}
		return c.Link.Read(wait)
	}
	var p []byte
	var err error
	for {
		if p, err = read(); err != nil {
			return 0, nil, err
		}
		if len(p) >= 9 && p[0] == '?' && p[1] == '#' && p[2] == '#' {
			break
		}
	}
	msgType := binary.BigEndian.Uint16(p[3:])
	n := binary.BigEndian.Uint32(p[5:])
	if n > MaxMessageSize {
		return 0, nil, errors.New("v1: message too long")
	}
	data := append([]byte{}, p[9:]...)
	for uint32(len(data)) < n {
		if p, err = read(); err != nil {
			return 0, nil, err
		}
		if len(p) < 1 || p[0] != '?' {
			return 0, nil, errors.New("v1: invalid continuation packet")
		}
		data = append(data, p[1:]...)
	}
	return msgType, data[:n], nil
}
