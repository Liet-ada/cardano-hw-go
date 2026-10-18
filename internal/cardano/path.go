// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package cardano holds what cardano-hw-cli knows about Cardano outside the
// transaction itself: derivation paths, key and address formats, and the
// files it reads and writes.
package cardano

import (
	"errors"
	"math"
	"strconv"
	"strings"

	"github.com/Liet-ada/cardano-hw-go/internal/js"
)

// Hardened is the offset of hardened derivation indexes.
const Hardened = 0x80000000

// Path is a BIP32 derivation path.
type Path []uint32

// ErrInvalidPath is the error cardano-hw-cli gives for a path it cannot read.
var ErrInvalidPath = errors.New("Can not parse path")

// ParsePath reads a path like 1852H/1815H/0H/0/0 as cardano-hw-cli does:
// each part is read by parseInt, so "12x" is 12 and "0h" is 0 (not
// hardened). A part out of the range of 32 bits, which cardano-hw-cli
// only refuses at the device, is refused here (cardano-hw-cli defect
// path-part-out-of-range).
func ParsePath(s string) (Path, error) {
	var p Path
	for _, part := range strings.Split(s, "/") {
		n := 0.0
		if strings.HasSuffix(part, "H") {
			n = js.ParseInt(part[:len(part)-1]) + Hardened
		} else {
			n = js.ParseInt(part)
		}
		if math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > math.MaxUint32 {
			return nil, ErrInvalidPath
		}
		p = append(p, uint32(n))
	}
	return p, nil
}

// String writes the path the way cardano-hw-cli does, with H for hardened.
func (p Path) String() string {
	parts := make([]string, len(p))
	for i, n := range p {
		if n >= Hardened {
			parts[i] = strconv.FormatUint(uint64(n-Hardened), 10) + "H"
		} else {
			parts[i] = strconv.FormatUint(uint64(n), 10)
		}
	}
	return strings.Join(parts, "/")
}

// Equal reports whether two paths are the same.
func (p Path) Equal(q Path) bool {
	if len(p) != len(q) {
		return false
	}
	for i := range p {
		if p[i] != q[i] {
			return false
		}
	}
	return true
}

// PathType is what a path is used for.
type PathType int

const (
	PathWalletAccount PathType = iota
	PathWalletSpendingKeyByron
	PathWalletSpendingKeyShelley
	PathWalletStakingKey
	PathDRepKey
	PathCommitteeColdKey
	PathCommitteeHotKey
	PathWalletAccountMultisig
	PathWalletSpendingKeyMultisig
	PathWalletStakingKeyMultisig
	PathWalletMintingKey
	PathPoolColdKey
	PathCVoteAccount
	PathCVoteKey
	PathInvalid
)

// Classify tells what a path is for, as cardano-hw-cli does.
func Classify(p Path) PathType {
	const h = Hardened
	if len(p) < 3 || p[1] != 1815+h {
		return PathInvalid
	}
	switch p[0] {
	case 44 + h:
		if len(p) == 3 {
			return PathWalletAccount
		}
		if len(p) == 5 && (p[3] == 0 || p[3] == 1) {
			return PathWalletSpendingKeyByron
		}
	case 1852 + h:
		if len(p) == 3 {
			return PathWalletAccount
		}
		if len(p) != 5 {
			return PathInvalid
		}
		switch p[3] {
		case 0, 1:
			return PathWalletSpendingKeyShelley
		case 2:
			return PathWalletStakingKey
		case 3:
			return PathDRepKey
		case 4:
			return PathCommitteeColdKey
		case 5:
			return PathCommitteeHotKey
		}
	case 1853 + h:
		if len(p) == 4 && p[2] == 0+h && p[3] >= h {
			return PathPoolColdKey
		}
	case 1854 + h:
		if len(p) == 3 {
			return PathWalletAccountMultisig
		}
		if len(p) == 5 && p[3] == 0 {
			return PathWalletSpendingKeyMultisig
		}
		if len(p) == 5 && p[3] == 2 {
			return PathWalletStakingKeyMultisig
		}
	case 1855 + h:
		if len(p) == 3 && p[2] >= h {
			return PathWalletMintingKey
		}
	case 1694 + h:
		if len(p) == 3 && p[2] >= h {
			return PathCVoteAccount
		}
		if len(p) == 5 && p[2] >= h && p[3] == 0 {
			return PathCVoteKey
		}
	}
	return PathInvalid
}
