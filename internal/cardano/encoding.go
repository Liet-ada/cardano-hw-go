// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cardano

import (
	"errors"
	"math/big"
	"strings"
)

// Bech32 as in BIP-173, without its 90 character limit: Cardano addresses
// are longer.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Gen = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= bech32Gen[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	var acc, bits uint
	maxv := uint(1)<<to - 1
	var out []byte
	for _, b := range data {
		if uint(b)>>from != 0 {
			return nil, errors.New("bech32: invalid data")
		}
		acc = acc<<from | uint(b)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv))
		}
	} else if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, errors.New("bech32: invalid padding")
	}
	return out, nil
}

// Bech32Encode encodes data with the human readable part hrp.
func Bech32Encode(hrp string, data []byte) string {
	five, _ := convertBits(data, 8, 5, true)
	values := append(hrpExpand(hrp), five...)
	mod := bech32Polymod(append(values, 0, 0, 0, 0, 0, 0)) ^ 1
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, v := range five {
		b.WriteByte(bech32Charset[v])
	}
	for i := 0; i < 6; i++ {
		b.WriteByte(bech32Charset[(mod>>uint(5*(5-i)))&31])
	}
	return b.String()
}

// Bech32Decode decodes a bech32 string into its human readable part and data.
func Bech32Decode(s string) (string, []byte, error) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, errors.New("bech32: mixed case")
	}
	s = strings.ToLower(s)
	sep := strings.LastIndexByte(s, '1')
	if sep < 1 || sep+7 > len(s) {
		return "", nil, errors.New("bech32: invalid separator position")
	}
	hrp := s[:sep]
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", nil, errors.New("bech32: invalid human readable part")
		}
	}
	var values []byte
	for i := sep + 1; i < len(s); i++ {
		v := strings.IndexByte(bech32Charset, s[i])
		if v < 0 {
			return "", nil, errors.New("bech32: invalid character")
		}
		values = append(values, byte(v))
	}
	if bech32Polymod(append(hrpExpand(hrp), values...)) != 1 {
		return "", nil, errors.New("bech32: invalid checksum")
	}
	data, err := convertBits(values[:len(values)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, data, nil
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Base58Encode encodes data in Bitcoin's base58 alphabet, as Byron
// addresses are.
func Base58Encode(data []byte) string {
	n := new(big.Int).SetBytes(data)
	radix := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for _, b := range data {
		if b != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// Base58Decode decodes base58.
func Base58Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("base58: empty string")
	}
	n := new(big.Int)
	radix := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(base58Alphabet, s[i])
		if v < 0 {
			return nil, errors.New("base58: invalid character")
		}
		n.Mul(n, radix).Add(n, big.NewInt(int64(v)))
	}
	out := n.Bytes()
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	return append(make([]byte, zeros), out...), nil
}
