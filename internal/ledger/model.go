// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ledger

import (
	"encoding/binary"
	"fmt"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
)

// The request model: a transaction as the Ledger app takes it, with keys
// the device owns given as paths.

// CredentialKind tells how a credential is given.
type CredentialKind int

const (
	CredKeyPath CredentialKind = iota
	CredKeyHash
	CredScriptHash
)

// Credential is a stake, DRep or committee credential.
type Credential struct {
	Kind CredentialKind
	Path cardano.Path
	Hash []byte
}

// StakingKind tells how the staking part of an address is given.
type StakingKind int

const (
	StakingNone StakingKind = iota
	StakingKeyPath
	StakingKeyHash
	StakingScriptHash
)

// AddressParams describe an address the device derives.
type AddressParams struct {
	Type               cardano.AddressType
	NetworkID          uint8
	ProtocolMagic      uint32 // Byron
	SpendingPath       cardano.Path
	SpendingScriptHash []byte
	Staking            StakingKind
	StakingPath        cardano.Path
	StakingHash        []byte
}

// Destination is where an output goes: a third-party address or one the
// device derives.
type Destination struct {
	DeviceOwned bool
	Address     []byte
	Params      AddressParams
}

// AssetGroup is a policy and its tokens; amounts are int64 for mint.
type AssetGroup struct {
	PolicyID []byte
	Tokens   []Token
}

// Token is an amount of one asset.
type Token struct {
	AssetName []byte
	Amount    uint64
	Mint      int64
}

// Output is a transaction output.
type Output struct {
	Format       uint8 // 0 legacy array, 1 Babbage map
	Destination  Destination
	Amount       uint64
	Tokens       []AssetGroup
	HasDatum     bool
	DatumInline  bool
	Datum        []byte // hash or inline bytes
	HasRefScript bool
	RefScript    []byte
}

// Input is a transaction input. A path, which the device does not see,
// asks for a witness of that key.
type Input struct {
	TxHash []byte
	Index  uint32
	Path   cardano.Path
}

// Anchor points to off-chain metadata.
type Anchor struct {
	URL  string
	Hash []byte
}

// DRep types on the wire.
const (
	DRepKeyHash      = 0
	DRepScriptHash   = 1
	DRepAbstain      = 2
	DRepNoConfidence = 3
	DRepKeyPath      = 100
)

// DRep is a delegated representative.
type DRep struct {
	Type uint8
	Path cardano.Path
	Hash []byte
}

// Relay is a pool relay.
type Relay struct {
	Type    uint8
	Port    *uint16
	IPv4    []byte
	IPv6    []byte
	DNSName string
}

// PoolParams are the parameters of a pool registration.
type PoolParams struct {
	PoolKeyPath       cardano.Path // device owned (operator)
	PoolKeyHash       []byte
	VRFKeyHash        []byte
	Pledge, Cost      uint64
	MarginNumerator   uint64
	MarginDenominator uint64
	RewardPath        cardano.Path // device owned
	RewardAccount     []byte
	Owners            []Credential // key paths or key hashes
	Relays            []Relay
	MetadataURL       string
	MetadataHash      []byte // nil: no metadata
}

// Certificate types, as numbered in the CDDL.
const (
	CertStakeRegistration         = 0
	CertStakeDeregistration       = 1
	CertStakeDelegation           = 2
	CertPoolRegistration          = 3
	CertPoolRetirement            = 4
	CertStakeRegistrationConway   = 7
	CertStakeDeregistrationConway = 8
	CertVoteDelegation            = 9
	CertAuthorizeCommitteeHot     = 14
	CertResignCommitteeCold       = 15
	CertDRepRegistration          = 16
	CertDRepDeregistration        = 17
	CertDRepUpdate                = 18
)

// Certificate is a certificate; which fields are set depends on Type.
type Certificate struct {
	Type            uint8
	StakeCredential Credential
	PoolKeyHash     []byte
	Deposit         uint64
	DRep            DRep
	Pool            *PoolParams
	RetirementPath  cardano.Path
	RetirementEpoch uint64
	ColdCredential  Credential
	HotCredential   Credential
	DRepCredential  Credential
	Anchor          *Anchor
}

// Withdrawal is a reward withdrawal.
type Withdrawal struct {
	Amount     uint64
	Credential Credential
}

// RequiredSigner is a key the transaction requires, as a path or hash.
type RequiredSigner struct {
	Path cardano.Path
	Hash []byte
}

// Voter types on the wire.
const (
	VoterCommitteeKeyHash    = 0
	VoterCommitteeScriptHash = 1
	VoterDRepKeyHash         = 2
	VoterDRepScriptHash      = 3
	VoterStakePoolKeyHash    = 4
	VoterCommitteeKeyPath    = 100
	VoterDRepKeyPath         = 102
	VoterStakePoolKeyPath    = 104
)

// Voter casts votes.
type Voter struct {
	Type uint8
	Path cardano.Path
	Hash []byte
}

// Vote is a vote on a governance action.
type Vote struct {
	GovActionTx    []byte
	GovActionIndex uint32
	Option         uint8
	Anchor         *Anchor
}

// VoterVotes are the votes of one voter.
type VoterVotes struct {
	Voter Voter
	Votes []Vote
}

// VoteDelegation delegates CIP-36 voting power.
type VoteDelegation struct {
	VoteKey     []byte
	VoteKeyPath cardano.Path
	Weight      uint32
}

// CIP36Registration is a vote registration the device signs within a
// transaction.
type CIP36Registration struct {
	Delegations   []VoteDelegation
	StakingPath   cardano.Path
	Destination   Destination
	Nonce         uint64
	VotingPurpose uint64
}

// Tx is a transaction body to sign.
type Tx struct {
	NetworkID        uint8
	ProtocolMagic    uint32
	Inputs           []Input
	Outputs          []Output
	Fee              uint64
	TTL              *uint64
	Certificates     []Certificate
	Withdrawals      []Withdrawal
	AuxDataHash      []byte
	CIP36            *CIP36Registration
	ValidityStart    *uint64
	HasMint          bool
	Mint             []AssetGroup
	ScriptDataHash   []byte
	Collateral       []Input
	RequiredSigners  []RequiredSigner
	IncludeNetworkID bool
	CollateralOutput *Output
	TotalCollateral  *uint64
	ReferenceInputs  []Input
	VotingProcedures []VoterVotes
	Treasury         *uint64
	Donation         *uint64
}

func (t *Tx) hasAuxData() bool { return t.AuxDataHash != nil || t.CIP36 != nil }

// Signing modes.
const (
	ModeOrdinary                 = 3
	ModePoolRegistrationOwner    = 4
	ModePoolRegistrationOperator = 5
	ModeMultisig                 = 6
	ModePlutus                   = 7
	ModeUnrestricted             = 9
)

// SignRequest asks the device to sign a transaction.
type SignRequest struct {
	Mode                uint8
	Tx                  Tx
	AdditionalWitnesses []cardano.Path
	TagCborSets         bool
}

// SignedTx is what the device returns.
type SignedTx struct {
	TxHash         []byte
	Witnesses      []PathSignature
	AuxDataHash    []byte
	CIP36Signature []byte
}

// PathSignature is a witness signature by the key of a path.
type PathSignature struct {
	Path      cardano.Path
	Signature []byte
}

// --- serialization helpers

func u8(v uint8) []byte   { return []byte{v} }
func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }
func i64(v int64) []byte  { return binary.BigEndian.AppendUint64(nil, uint64(v)) }
func cat(b ...[]byte) []byte {
	var out []byte
	for _, x := range b {
		out = append(out, x...)
	}
	return out
}

func pathBytes(p cardano.Path) []byte {
	out := []byte{byte(len(p))}
	for _, n := range p {
		out = binary.BigEndian.AppendUint32(out, n)
	}
	return out
}

// included is the option flag of the app: 1 no, 2 yes.
func included(b bool) []byte {
	if b {
		return []byte{2}
	}
	return []byte{1}
}

func stakingBytes(a AddressParams) ([]byte, error) {
	switch a.Staking {
	case StakingNone:
		return []byte{0x11}, nil
	case StakingKeyPath:
		return cat([]byte{0x22}, pathBytes(a.StakingPath)), nil
	case StakingKeyHash:
		return cat([]byte{0x33}, a.StakingHash), nil
	case StakingScriptHash:
		return cat([]byte{0x55}, a.StakingHash), nil
	}
	return nil, fmt.Errorf("ledger: unknown staking kind %d", a.Staking)
}

// addressParamsBytes serializes address parameters (the same in v7 and v8).
func addressParamsBytes(a AddressParams) ([]byte, error) {
	out := u8(uint8(a.Type))
	if a.Type == cardano.AddrByron {
		out = append(out, u32(a.ProtocolMagic)...)
	} else {
		out = append(out, a.NetworkID)
	}
	switch {
	case a.SpendingPath != nil:
		out = append(out, pathBytes(a.SpendingPath)...)
	case a.SpendingScriptHash != nil:
		out = append(out, a.SpendingScriptHash...)
	}
	s, err := stakingBytes(a)
	if err != nil {
		return nil, err
	}
	return append(out, s...), nil
}
