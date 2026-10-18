// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cbor

import "errors"

// ErrNotWellFormed reports bytes that are not one well-formed data item.
var ErrNotWellFormed = errors.New("cbor: not well-formed")

// WellFormed reports whether data is exactly one well-formed data item
// (RFC 8949, section 5.3.1), without the checks Decode adds. It is what
// cardano-hw-cli's CBOR library accepts when it tells CBOR from not.
func WellFormed(data []byte) error {
	end, err := wellFormedItem(data, 0, 0)
	if err != nil {
		return err
	}
	if end != len(data) {
		return ErrTrailingBytes
	}
	return nil
}

func wellFormedItem(b []byte, i, depth int) (int, error) {
	if depth > 10000 || i >= len(b) {
		return 0, ErrNotWellFormed
	}
	major, info := b[i]>>5, b[i]&0x1f
	i++
	var arg uint64
	switch {
	case info < 24:
		arg = uint64(info)
	case info <= 27:
		n := 1 << (info - 24)
		if i+n > len(b) {
			return 0, ErrNotWellFormed
		}
		for _, c := range b[i : i+n] {
			arg = arg<<8 | uint64(c)
		}
		i += n
	case info == 31:
		switch major {
		case majorBytes, majorText:
			for {
				if i >= len(b) {
					return 0, ErrNotWellFormed
				}
				if b[i] == 0xff {
					return i + 1, nil
				}
				// chunks are definite strings of the same type
				if b[i]>>5 != major || b[i]&0x1f == 31 {
					return 0, ErrNotWellFormed
				}
				var err error
				if i, err = wellFormedItem(b, i, depth+1); err != nil {
					return 0, err
				}
			}
		case majorArray, majorMap:
			for n := 0; ; n++ {
				if i >= len(b) {
					return 0, ErrNotWellFormed
				}
				if b[i] == 0xff {
					if major == majorMap && n%2 == 1 {
						return 0, ErrNotWellFormed
					}
					return i + 1, nil
				}
				var err error
				if i, err = wellFormedItem(b, i, depth+1); err != nil {
					return 0, err
				}
			}
		}
		return 0, ErrNotWellFormed // a break, or indefinite integers or tags
	default:
		return 0, ErrNotWellFormed // 28 to 30
	}
	switch major {
	case majorBytes, majorText:
		if arg > uint64(len(b)-i) {
			return 0, ErrNotWellFormed
		}
		return i + int(arg), nil
	case majorArray, majorMap:
		n := arg
		if major == majorMap {
			if n > uint64(len(b)) {
				return 0, ErrNotWellFormed
			}
			n *= 2
		}
		for k := uint64(0); k < n; k++ {
			var err error
			if i, err = wellFormedItem(b, i, depth+1); err != nil {
				return 0, err
			}
		}
		return i, nil
	case majorTag:
		return wellFormedItem(b, i, depth+1)
	}
	return i, nil
}
