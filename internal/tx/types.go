// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package tx parses, serializes, validates and transforms Cardano
// transactions the way hardware wallets need them (CIP-21). It follows the
// behaviour of Vacuumlabs' cardano-hw-interop-lib, which cardano-hw-cli uses,
// so that validation reports the same issues.
package tx

import (
	"math/big"

	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
)

// Lengths of fixed-size fields.
const (
	KeyHashLength           = 28
	ScriptHashLength        = 28
	PoolKeyHashLength       = 28
	RewardAccountLength     = 29
	VRFKeyHashLength        = 32
	AuxiliaryDataHashLength = 32
	TxIDLength              = 32
	DatumHashLength         = 32
	ScriptDataHashLength    = 32
	AnchorDataHashLength    = 32
	PoolMetadataHashLength  = 32
	IPv4Length              = 4
	IPv6Length              = 16
	AssetNameMaxLength      = 32
	URLMaxLength            = 128
	DNSNameMaxLength        = 128
	PortMax                 = 65535
)

// Set is a CDDL set: an array, tagged 258 or not. The tag is optional since
// Conway; the ledger accepts both.
type Set[T any] struct {
	Items  []T
	HasTag bool
}

// Input is a transaction input, also used for collateral and reference inputs.
type Input struct {
	TxID  []byte
	Index *big.Int
}

// Token is an amount of one asset.
type Token struct {
	AssetName []byte
	Amount    *big.Int
}

// AssetGroup holds the tokens of one policy.
type AssetGroup struct {
	PolicyID []byte
	Tokens   []Token
}

// Multiasset is a multi-asset value or mint, in the order of the CBOR map.
type Multiasset []AssetGroup

// Amount is an output value: coin alone, or coin with a multi-asset map
// (which may be empty in a malformed transaction).
type Amount struct {
	Coin          *big.Int
	HasMultiasset bool
	Multiasset    Multiasset
}

// DatumType is the kind of datum of a Babbage output.
type DatumType int

const (
	DatumHash   DatumType = 0
	DatumInline DatumType = 1
)

// Datum is the datum of a Babbage output: a hash, or inline data (the bytes
// inside tag 24).
type Datum struct {
	Type  DatumType
	Hash  []byte
	Bytes []byte
}

// OutputFormat is the serialization of an output.
type OutputFormat int

const (
	FormatArrayLegacy OutputFormat = 0
	FormatMapBabbage  OutputFormat = 1
)

// Output is a transaction output.
type Output struct {
	Format  OutputFormat
	Address []byte
	Amount  Amount
	// DatumHash is the datum hash of a legacy output, nil if absent.
	DatumHash []byte
	// Datum is the datum of a Babbage output, nil if absent.
	Datum *Datum
	// ReferenceScript holds the script bytes inside tag 24 of a Babbage
	// output when HasReferenceScript is set.
	HasReferenceScript bool
	ReferenceScript    []byte
}

// CertificateType is the type of a certificate, as numbered in the CDDL.
type CertificateType int

const (
	CertStakeRegistration                      CertificateType = 0
	CertStakeDeregistration                    CertificateType = 1
	CertStakeDelegation                        CertificateType = 2
	CertPoolRegistration                       CertificateType = 3
	CertPoolRetirement                         CertificateType = 4
	CertGenesisKeyDelegation                   CertificateType = 5
	CertMoveInstantaneousRewards               CertificateType = 6
	CertStakeRegistrationConway                CertificateType = 7
	CertStakeDeregistrationConway              CertificateType = 8
	CertVoteDelegation                         CertificateType = 9
	CertStakeAndVoteDelegation                 CertificateType = 10
	CertStakeRegistrationAndDelegation         CertificateType = 11
	CertStakeRegistrationWithVoteDelegation    CertificateType = 12
	CertStakeRegistrationWithStakeAndVoteDeleg CertificateType = 13
	CertAuthorizeCommitteeHot                  CertificateType = 14
	CertResignCommitteeCold                    CertificateType = 15
	CertDRepRegistration                       CertificateType = 16
	CertDRepDeregistration                     CertificateType = 17
	CertDRepUpdate                             CertificateType = 18
	certificateTypeCount                                       = 19
)

// CredentialType tells a key hash credential from a script hash one.
type CredentialType int

const (
	CredentialKeyHash    CredentialType = 0
	CredentialScriptHash CredentialType = 1
)

// Credential is a stake, DRep or committee credential.
type Credential struct {
	Type CredentialType
	Hash []byte
}

// DRepType is the kind of a DRep in a vote delegation.
type DRepType int

const (
	DRepKeyHash      DRepType = 0
	DRepScriptHash   DRepType = 1
	DRepAbstain      DRepType = 2
	DRepNoConfidence DRepType = 3
)

// DRep is a delegated representative.
type DRep struct {
	Type DRepType
	Hash []byte // nil for abstain and no confidence
}

// Anchor points to off-chain metadata.
type Anchor struct {
	URL      string
	DataHash []byte
}

// RelayType is the kind of a pool relay.
type RelayType int

const (
	RelaySingleHostAddress RelayType = 0
	RelaySingleHostName    RelayType = 1
	RelayMultiHostName     RelayType = 2
)

// Relay is a pool relay. Nil fields are CBOR null.
type Relay struct {
	Type    RelayType
	Port    *uint64
	IPv4    []byte
	IPv6    []byte
	DNSName string
}

// PoolMetadata is the metadata reference of a pool registration.
type PoolMetadata struct {
	URL  string
	Hash []byte
}

// PoolParams are the parameters of a pool registration.
type PoolParams struct {
	Operator      []byte
	VRFKeyHash    []byte
	Pledge        *big.Int
	Cost          *big.Int
	Margin        [2]*big.Int
	RewardAccount []byte
	Owners        Set[[]byte]
	Relays        []Relay
	Metadata      *PoolMetadata // nil is null
}

// Certificate is a certificate. Which fields are set depends on Type.
type Certificate struct {
	Type            CertificateType
	StakeCredential Credential
	PoolKeyHash     []byte
	Deposit         *big.Int
	DRep            DRep
	PoolParams      *PoolParams
	Epoch           *big.Int
	ColdCredential  Credential
	HotCredential   Credential
	DRepCredential  Credential
	Anchor          *Anchor // nil is null
	// Rest holds the unparsed fields of genesis key delegation and move
	// instantaneous rewards certificates, which hardware wallets refuse.
	Rest []cbor.Value
}

// Withdrawal is a reward withdrawal.
type Withdrawal struct {
	RewardAccount []byte
	Amount        *big.Int
}

// VoterType is the kind of voter in voting procedures.
type VoterType int

const (
	VoterCommitteeKey    VoterType = 0
	VoterCommitteeScript VoterType = 1
	VoterDRepKey         VoterType = 2
	VoterDRepScript      VoterType = 3
	VoterStakePool       VoterType = 4
)

// Voter casts votes.
type Voter struct {
	Type VoterType
	Hash []byte
}

// GovActionID identifies a governance action.
type GovActionID struct {
	TxID  []byte
	Index *big.Int
}

// VoteOption is a vote.
type VoteOption int

const (
	VoteNo      VoteOption = 0
	VoteYes     VoteOption = 1
	VoteAbstain VoteOption = 2
)

// VotingProcedure is a vote with an optional anchor.
type VotingProcedure struct {
	Vote   VoteOption
	Anchor *Anchor
}

// Vote is a voting procedure on one governance action.
type Vote struct {
	GovActionID GovActionID
	Procedure   VotingProcedure
}

// VoterVotes are the votes of one voter.
type VoterVotes struct {
	Voter Voter
	Votes []Vote
}

// ProposalProcedure is a governance proposal; hardware wallets refuse them,
// so the action itself is kept unparsed.
type ProposalProcedure struct {
	Deposit       *big.Int
	RewardAccount []byte
	GovAction     cbor.Value
	Anchor        Anchor
}

// Body is a transaction body. Nil pointers and false Has* fields are absent
// entries.
type Body struct {
	Inputs                Set[Input]
	Outputs               []Output
	Fee                   *big.Int
	TTL                   *big.Int
	Certificates          *Set[Certificate]
	HasWithdrawals        bool
	Withdrawals           []Withdrawal
	Update                *cbor.Value
	AuxiliaryDataHash     []byte
	ValidityIntervalStart *big.Int
	HasMint               bool
	Mint                  Multiasset
	ScriptDataHash        []byte
	CollateralInputs      *Set[Input]
	RequiredSigners       *Set[[]byte]
	NetworkID             *big.Int
	CollateralReturn      *Output
	TotalCollateral       *big.Int
	ReferenceInputs       *Set[Input]
	HasVotingProcedures   bool
	VotingProcedures      []VoterVotes
	ProposalProcedures    *Set[ProposalProcedure]
	Treasury              *big.Int
	Donation              *big.Int
}

// Transaction is a whole transaction. The parts other than the body are kept
// unparsed.
type Transaction struct {
	Body           Body
	WitnessSet     cbor.Value
	ScriptValidity *cbor.Value // present in the Alonzo format only
	AuxiliaryData  cbor.Value
}

// Body map keys.
const (
	keyInputs                = 0
	keyOutputs               = 1
	keyFee                   = 2
	keyTTL                   = 3
	keyCertificates          = 4
	keyWithdrawals           = 5
	keyUpdate                = 6
	keyAuxiliaryDataHash     = 7
	keyValidityIntervalStart = 8
	keyMint                  = 9
	keyScriptDataHash        = 11
	keyCollateralInputs      = 13
	keyRequiredSigners       = 14
	keyNetworkID             = 15
	keyCollateralReturn      = 16
	keyTotalCollateral       = 17
	keyReferenceInputs       = 18
	keyVotingProcedures      = 19
	keyProposalProcedures    = 20
	keyTreasury              = 21
	keyDonation              = 22
)

// Babbage output map keys.
const (
	outKeyAddress         = 0
	outKeyAmount          = 1
	outKeyDatum           = 2
	outKeyReferenceScript = 3
)

// Witness set map keys.
const (
	WitnessVKey           = 0
	WitnessNativeScripts  = 1
	WitnessBootstrap      = 2
	WitnessPlutusV1Script = 3
	WitnessPlutusData     = 4
	WitnessRedeemers      = 5
	WitnessPlutusV2Script = 6
	WitnessPlutusV3Script = 7
)

// sets returns every CDDL set of the body, including the owners of a pool
// registration, for the consistency of 258 tags.
func (b *Body) sets() []*bool {
	var tags []*bool
	tags = append(tags, &b.Inputs.HasTag)
	if b.Certificates != nil {
		tags = append(tags, &b.Certificates.HasTag)
		for i := range b.Certificates.Items {
			c := &b.Certificates.Items[i]
			if c.Type == CertPoolRegistration {
				tags = append(tags, &c.PoolParams.Owners.HasTag)
				break
			}
		}
	}
	if b.CollateralInputs != nil {
		tags = append(tags, &b.CollateralInputs.HasTag)
	}
	if b.RequiredSigners != nil {
		tags = append(tags, &b.RequiredSigners.HasTag)
	}
	if b.ReferenceInputs != nil {
		tags = append(tags, &b.ReferenceInputs.HasTag)
	}
	if b.ProposalProcedures != nil {
		tags = append(tags, &b.ProposalProcedures.HasTag)
	}
	return tags
}

// PoolRegistration returns the first pool registration certificate, if any.
func (b *Body) PoolRegistration() *Certificate {
	if b.Certificates == nil {
		return nil
	}
	for i := range b.Certificates.Items {
		if b.Certificates.Items[i].Type == CertPoolRegistration {
			return &b.Certificates.Items[i]
		}
	}
	return nil
}
