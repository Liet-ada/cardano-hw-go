// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package thp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"time"

	"github.com/Liet-ada/cardano-hw-go/internal/trezor/wire"
)

// The transport layer of THP: packets, CRC, channel allocation and the
// alternating bit protocol.

// Control bytes.
const (
	ctrlContinuation       = 0x80
	ctrlChannelAllocReq    = 0x40
	ctrlChannelAllocResp   = 0x41
	ctrlTransportError     = 0x42
	ctrlPing               = 0x43
	ctrlPong               = 0x44
	ctrlCodecV1            = 0x3f
	ctrlAck                = 0x20
	ctrlHandshakeInitReq   = 0x00
	ctrlHandshakeInitResp  = 0x01
	ctrlHandshakeCompReq   = 0x02
	ctrlHandshakeCompResp  = 0x03
	ctrlEncryptedTransport = 0x04

	maskData = 0xe7 // matches handshake and encrypted transport messages
	maskAck  = 0xf7
	bitSeq   = 0x10
	bitAck   = 0x08

	broadcastCID = 0xffff
)

// Transport error codes.
const (
	errCodeTransportBusy      = 1
	errCodeUnallocatedChannel = 2
	errCodeDecryptionFailed   = 3
	errCodeDeviceLocked       = 5
)

// TransportError is an error the Trezor reports at the transport layer.
type TransportError struct{ Code byte }

func (e *TransportError) Error() string {
	switch e.Code {
	case errCodeTransportBusy:
		return "thp: the Trezor is busy with another channel"
	case errCodeUnallocatedChannel:
		return "thp: the Trezor does not know this channel"
	case errCodeDecryptionFailed:
		return "thp: the Trezor could not decrypt the message"
	case errCodeDeviceLocked:
		return "thp: the Trezor is locked"
	}
	return fmt.Sprintf("thp: transport error %d", e.Code)
}

// ErrDeviceLocked reports a locked Trezor.
var ErrDeviceLocked = &TransportError{Code: errCodeDeviceLocked}

// Is makes errors.Is match transport errors by code.
func (e *TransportError) Is(target error) bool {
	t, ok := target.(*TransportError)
	return ok && t.Code == e.Code
}

const (
	ackTimeout       = 500 * time.Millisecond
	maxRetransmits   = 20
	maxBusyBackoffMS = 500
)

// transport is one channel's transport layer.
type transport struct {
	link    wire.Link
	cid     uint16
	sendBit byte // sequence bit of the next message sent
	recvBit byte // sequence bit expected in the next message received
	// pending holds a data message that arrived while waiting for an ACK.
	pending *message
}

type message struct {
	ctrl    byte
	payload []byte
}

func crc(ctrl byte, cid uint16, length int, payload []byte) []byte {
	h := crc32.NewIEEE()
	h.Write([]byte{ctrl, byte(cid >> 8), byte(cid), byte(length >> 8), byte(length)})
	h.Write(payload)
	return binary.BigEndian.AppendUint32(nil, h.Sum32())
}

// packets segments a transport payload into packets.
func packets(ctrl byte, cid uint16, payload []byte) ([][]byte, error) {
	length := len(payload) + 4
	if length > 0xffff {
		return nil, errors.New("thp: message too long")
	}
	data := append(append([]byte{}, payload...), crc(ctrl, cid, length, payload)...)
	first := make([]byte, wire.PacketSize)
	first[0] = ctrl
	binary.BigEndian.PutUint16(first[1:], cid)
	binary.BigEndian.PutUint16(first[3:], uint16(length))
	n := copy(first[5:], data)
	out := [][]byte{first}
	for data = data[n:]; len(data) > 0; {
		p := make([]byte, wire.PacketSize)
		p[0] = ctrlContinuation
		binary.BigEndian.PutUint16(p[1:], cid)
		n := copy(p[3:], data)
		data = data[n:]
		out = append(out, p)
	}
	return out, nil
}

func (t *transport) writeMessage(ctrl byte, cid uint16, payload []byte) error {
	ps, err := packets(ctrl, cid, payload)
	if err != nil {
		return err
	}
	for _, p := range ps {
		if err := t.link.Write(p); err != nil {
			return err
		}
	}
	return nil
}

// readMessage reassembles the next valid message on cid, skipping packets of
// other channels and corrupted messages.
func (t *transport) readMessage(cid uint16, timeout time.Duration) (*message, error) {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	var cur *message
	var want int
	var buf []byte
	for {
		wait := time.Duration(0)
		if timeout > 0 {
			wait = time.Until(deadline)
			if wait <= 0 {
				return nil, wire.ErrTimeout
			}
		}
		p, err := t.link.Read(wait)
		if err != nil {
			return nil, err
		}
		if len(p) < 5 || binary.BigEndian.Uint16(p[1:]) != cid {
			continue
		}
		if p[0]&ctrlContinuation != 0 {
			if cur == nil {
				continue
			}
			buf = append(buf, p[3:]...)
		} else {
			cur = &message{ctrl: p[0]}
			want = int(binary.BigEndian.Uint16(p[3:]))
			if want < 4 {
				cur = nil
				continue
			}
			buf = append([]byte{}, p[5:]...)
		}
		if len(buf) < want {
			continue
		}
		data := buf[:want]
		payload, sum := data[:want-4], data[want-4:]
		if !bytes.Equal(crc(cur.ctrl, cid, want, payload), sum) {
			cur = nil
			continue
		}
		cur.payload = payload
		return cur, nil
	}
}

func randomNonce() []byte {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// allocateChannel asks the Trezor for a channel on the broadcast channel and
// returns its id and the device properties.
func allocateChannel(link wire.Link) (*transport, []byte, error) {
	t := &transport{link: link}
	nonce := randomNonce()
	for attempt := 0; attempt < 5; attempt++ {
		if err := t.writeMessage(ctrlChannelAllocReq, broadcastCID, nonce); err != nil {
			return nil, nil, err
		}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			m, err := t.readMessage(broadcastCID, time.Until(deadline))
			if errors.Is(err, wire.ErrTimeout) {
				break
			}
			if err != nil {
				return nil, nil, err
			}
			if m.ctrl == ctrlTransportError && len(m.payload) > 0 {
				return nil, nil, &TransportError{m.payload[0]}
			}
			if m.ctrl != ctrlChannelAllocResp || len(m.payload) < 10 || !bytes.Equal(m.payload[:8], nonce) {
				continue
			}
			t.cid = binary.BigEndian.Uint16(m.payload[8:])
			return t, m.payload[10:], nil
		}
	}
	return nil, nil, errors.New("thp: the Trezor did not allocate a channel")
}

func isAck(ctrl byte) bool { return ctrl&maskAck == ctrlAck }
func isData(ctrl byte) bool {
	return ctrl&0x80 == 0 && ctrl&maskData <= ctrlEncryptedTransport && ctrl&0x60 == 0
}
func seqBit(ctrl byte) byte     { return ctrl >> 4 & 1 }
func ackBitOf(ctrl byte) byte   { return ctrl >> 3 & 1 }
func dataType(ctrl byte) byte   { return ctrl & maskData }
func ackFor(seq byte) byte      { return ctrlAck | seq<<3 }
func withSeq(ctrl, b byte) byte { return ctrl&^bitSeq | b<<4 }

func (t *transport) sendAck(seq byte) error {
	return t.writeMessage(ackFor(seq), t.cid, nil)
}

// send transmits a data message and waits for its ACK, retransmitting it
// when the ACK does not come.
func (t *transport) send(ctrl byte, payload []byte) error {
	ctrl = withSeq(ctrl, t.sendBit)
	timeout := ackTimeout
	for attempt := 0; attempt <= maxRetransmits; attempt++ {
		if err := t.writeMessage(ctrl, t.cid, payload); err != nil {
			return err
		}
		deadline := time.Now().Add(timeout)
		for {
			wait := time.Until(deadline)
			if wait <= 0 {
				break
			}
			m, err := t.readMessage(t.cid, wait)
			if errors.Is(err, wire.ErrTimeout) {
				break
			}
			if err != nil {
				return err
			}
			switch {
			case m.ctrl == ctrlTransportError:
				if len(m.payload) > 0 && m.payload[0] == errCodeTransportBusy {
					n, _ := rand.Int(rand.Reader, big.NewInt(maxBusyBackoffMS))
					time.Sleep(time.Duration(n.Int64()) * time.Millisecond)
					deadline = time.Now() // retransmit
					continue
				}
				if len(m.payload) > 0 {
					return &TransportError{m.payload[0]}
				}
			case isAck(m.ctrl):
				if ackBitOf(m.ctrl) == t.sendBit {
					t.sendBit ^= 1
					return nil
				}
			case isData(m.ctrl):
				// A new message from the Trezor answers what it received:
				// take it as the ACK and keep it for receive. A repeated
				// one is only acknowledged again.
				fresh := seqBit(m.ctrl) == t.recvBit
				if err := t.accept(m); err != nil {
					return err
				}
				if fresh {
					t.sendBit ^= 1
					return nil
				}
			}
		}
		timeout = timeout * 3 / 2
		if timeout > 4*time.Second {
			timeout = 4 * time.Second
		}
	}
	return errors.New("thp: the Trezor did not acknowledge the message")
}

// accept handles an incoming data message: it acknowledges it and keeps it
// unless it is a duplicate.
func (t *transport) accept(m *message) error {
	s := seqBit(m.ctrl)
	if err := t.sendAck(s); err != nil {
		return err
	}
	if s != t.recvBit {
		return nil // a retransmission of the previous message
	}
	t.recvBit ^= 1
	t.pending = m
	return nil
}

// receive returns the next data message, waiting up to timeout (zero waits
// without limit).
func (t *transport) receive(timeout time.Duration) (*message, error) {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		if t.pending != nil {
			m := t.pending
			t.pending = nil
			return m, nil
		}
		wait := time.Duration(0)
		if timeout > 0 {
			if wait = time.Until(deadline); wait <= 0 {
				return nil, wire.ErrTimeout
			}
		}
		m, err := t.readMessage(t.cid, wait)
		if err != nil {
			return nil, err
		}
		switch {
		case m.ctrl == ctrlTransportError:
			if len(m.payload) > 0 {
				return nil, &TransportError{m.payload[0]}
			}
		case isData(m.ctrl):
			if err := t.accept(m); err != nil {
				return nil, err
			}
		}
	}
}
