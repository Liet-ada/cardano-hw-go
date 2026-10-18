// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package wire

import (
	"errors"
	"net"
	"os"
	"time"
)

// UDP is a link to the Trezor emulator, which serves its USB interface over
// UDP (port 21324, and the debug link on the next port).
type UDP struct {
	conn *net.UDPConn
}

// DialUDP connects to the emulator at addr (host:port).
func DialUDP(addr string) (*UDP, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", nil, a)
	if err != nil {
		return nil, err
	}
	return &UDP{conn: c}, nil
}

// Ping reports whether the emulator answers.
func (u *UDP) Ping() bool {
	if _, err := u.conn.Write([]byte("PINGPING")); err != nil {
		return false
	}
	u.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	defer u.conn.SetReadDeadline(time.Time{})
	b := make([]byte, 64)
	n, err := u.conn.Read(b)
	return err == nil && string(b[:n]) == "PONGPONG"
}

func (u *UDP) Write(p []byte) error {
	_, err := u.conn.Write(p)
	return err
}

func (u *UDP) Read(timeout time.Duration) ([]byte, error) {
	if timeout > 0 {
		u.conn.SetReadDeadline(time.Now().Add(timeout))
	} else {
		u.conn.SetReadDeadline(time.Time{})
	}
	b := make([]byte, 2*PacketSize)
	for {
		n, err := u.conn.Read(b)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, ErrTimeout
		}
		if err != nil {
			return nil, err
		}
		if n == PacketSize {
			return append([]byte{}, b[:n]...), nil
		}
	}
}

func (u *UDP) Close() error { return u.conn.Close() }
