// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cardano

import (
	"crypto/sha3"
	"errors"
	"hash/crc32"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
)

// AddressType is the header type of an address, as in the Cardano CDDL.
type AddressType int

const (
	AddrBasePaymentKeyStakeKey       AddressType = 0b0000
	AddrBasePaymentScriptStakeKey    AddressType = 0b0001
	AddrBasePaymentKeyStakeScript    AddressType = 0b0010
	AddrBasePaymentScriptStakeScript AddressType = 0b0011
	AddrPointerKey                   AddressType = 0b0100
	AddrPointerScript                AddressType = 0b0101
	AddrEnterpriseKey                AddressType = 0b0110
	AddrEnterpriseScript             AddressType = 0b0111
	AddrByron                        AddressType = 0b1000
	AddrRewardKey                    AddressType = 0b1110
	AddrRewardScript                 AddressType = 0b1111
)

// Network ids and protocol magics.
const (
	NetworkIDMainnet = 1
	NetworkIDTestnet = 0

	ProtocolMagicMainnet = 764824073
	ProtocolMagicPreprod = 1
	ProtocolMagicPreview = 2
)

// Network is the network a transaction or address belongs to.
type Network struct {
	NetworkID     uint32
	ProtocolMagic uint32
}

// Mainnet is the main network.
var Mainnet = Network{NetworkIDMainnet, ProtocolMagicMainnet}

// KeyHashLength is the length of a key hash.
const KeyHashLength = 28

// ErrInvalidAddress is the error cardano-hw-cli gives for an address it
// cannot read.
var ErrInvalidAddress = errors.New("Invalid address")

// AddressTypeOf returns the header type of a binary address.
func AddressTypeOf(addr []byte) (AddressType, error) {
	if len(addr) == 0 {
		return 0, ErrInvalidAddress
	}
	t := AddressType(addr[0] >> 4)
	switch t {
	case 0b1001, 0b1010, 0b1011, 0b1100, 0b1101:
		return 0, ErrInvalidAddress
	}
	return t, nil
}

// EncodeAddress writes a binary address in bech32, or in base58 for Byron.
func EncodeAddress(addr []byte) (string, error) {
	t, err := AddressTypeOf(addr)
	if err != nil {
		return "", err
	}
	if t == AddrByron {
		return Base58Encode(addr), nil
	}
	prefix := "addr"
	if t == AddrRewardKey || t == AddrRewardScript {
		prefix = "stake"
	}
	if addr[0]&0x0f == NetworkIDTestnet {
		prefix += "_test"
	}
	return Bech32Encode(prefix, addr), nil
}

// DecodeAddress reads a bech32 Shelley address or a base58 Byron address.
func DecodeAddress(s string) ([]byte, error) {
	if b, err := Base58Decode(s); err == nil {
		if _, err := parseByron(b); err == nil {
			return b, nil
		}
	}
	_, b, err := Bech32Decode(s)
	if err != nil {
		return nil, ErrInvalidAddress
	}
	t, err := AddressTypeOf(b)
	if err != nil || t == AddrByron {
		return nil, ErrInvalidAddress
	}
	return b, nil
}

// AddressAttributes are what a hardware wallet needs to know about an
// address to show it.
type AddressAttributes struct {
	Type          AddressType
	NetworkID     uint32
	ProtocolMagic uint32
}

// Attributes reads the type and network of a human readable address. For
// Shelley addresses the protocol magic only matters to Byron, so it is that
// of mainnet or preview.
func Attributes(s string) (AddressAttributes, error) {
	b, err := DecodeAddress(s)
	if err != nil {
		return AddressAttributes{}, err
	}
	t, _ := AddressTypeOf(b)
	if t == AddrByron {
		magic, err := parseByron(b)
		if err != nil {
			return AddressAttributes{}, err
		}
		id := uint32(NetworkIDTestnet)
		if magic == ProtocolMagicMainnet {
			id = NetworkIDMainnet
		}
		return AddressAttributes{AddrByron, id, magic}, nil
	}
	id := uint32(b[0] & 0x0f)
	magic := uint32(ProtocolMagicPreview)
	if id == NetworkIDMainnet {
		magic = ProtocolMagicMainnet
	}
	return AddressAttributes{t, id, magic}, nil
}

// parseByron checks a Byron address and returns its protocol magic.
func parseByron(b []byte) (uint32, error) {
	v, err := cbor.Decode(b)
	if err != nil || v.Kind != cbor.Array || len(v.Items) != 2 {
		return 0, ErrInvalidAddress
	}
	tagged, crc := v.Items[0], v.Items[1]
	if tagged.Kind != cbor.Tag || tagged.Uint != cbor.TagEncodedCBOR || tagged.Content().Kind != cbor.Bytes || crc.Kind != cbor.Uint {
		return 0, ErrInvalidAddress
	}
	payload := tagged.Content().Bytes
	if uint64(crc32.ChecksumIEEE(payload)) != crc.Uint {
		return 0, ErrInvalidAddress
	}
	data, err := cbor.Decode(payload)
	if err != nil || data.Kind != cbor.Array || len(data.Items) != 3 || data.Items[0].Kind != cbor.Bytes || data.Items[1].Kind != cbor.Map {
		return 0, ErrInvalidAddress
	}
	magic := uint32(ProtocolMagicMainnet)
	for _, e := range data.Items[1].Entries {
		if e.Key.Kind == cbor.Uint && e.Key.Uint == 2 && e.Value.Kind == cbor.Bytes {
			m, err := cbor.Decode(e.Value.Bytes)
			if err != nil || m.Kind != cbor.Uint || m.Uint > 0xffffffff {
				return 0, ErrInvalidAddress
			}
			magic = uint32(m.Uint)
		}
	}
	return magic, nil
}

// KeyHash is the Blake2b-224 hash of a public key.
func KeyHash(pub []byte) []byte {
	h, _ := blake2b.New(KeyHashLength, nil)
	h.Write(pub)
	return h.Sum(nil)
}

// BaseAddress packs a base address from a payment key hash and a staking
// hash of the given type.
func BaseAddress(t AddressType, payment, staking []byte, networkID uint32) []byte {
	return append(append([]byte{byte(t)<<4 | byte(networkID)}, payment...), staking...)
}

// EnterpriseAddress packs an enterprise address with a key hash.
func EnterpriseAddress(payment []byte, networkID uint32) []byte {
	return append([]byte{byte(AddrEnterpriseKey)<<4 | byte(networkID)}, payment...)
}

// RewardAddress packs a reward address with a key hash.
func RewardAddress(staking []byte, networkID uint32) []byte {
	return append([]byte{byte(AddrRewardKey)<<4 | byte(networkID)}, staking...)
}

// ByronAddress packs the Byron address of an extended public key for the
// derivation scheme of hardware wallets (V2, no encrypted derivation path).
func ByronAddress(xpub []byte, protocolMagic uint32) []byte {
	attrs := cbor.NewMap()
	if protocolMagic != ProtocolMagicMainnet {
		attrs = cbor.NewMap(cbor.Entry{Key: cbor.NewUint(2), Value: cbor.NewBytes(cbor.Encode(cbor.NewUint(uint64(protocolMagic))))})
	}
	spending := cbor.NewArray(cbor.NewUint(0), cbor.NewArray(cbor.NewUint(0), cbor.NewBytes(xpub)), attrs)
	sha := sha3.Sum256(cbor.Encode(spending))
	h, _ := blake2b.New(28, nil)
	h.Write(sha[:])
	root := h.Sum(nil)
	data := cbor.Encode(cbor.NewArray(cbor.NewBytes(root), attrs, cbor.NewUint(0)))
	return cbor.Encode(cbor.NewArray(cbor.NewTag(cbor.TagEncodedCBOR, cbor.NewBytes(data)), cbor.NewUint(uint64(crc32.ChecksumIEEE(data)))))
}
