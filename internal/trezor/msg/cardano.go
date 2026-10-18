// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package msg

// Cardano derivation types.
const (
	DerivationLedger       = 0
	DerivationIcarus       = 1
	DerivationIcarusTrezor = 2
)

// Cardano address types.
const (
	AddressBase             = 0
	AddressBaseScriptKey    = 1
	AddressBaseKeyScript    = 2
	AddressBaseScriptScript = 3
	AddressPointer          = 4
	AddressPointerScript    = 5
	AddressEnterprise       = 6
	AddressEnterpriseScript = 7
	AddressByron            = 8
	AddressReward           = 14
	AddressRewardScript     = 15
)

// Native script types.
const (
	NativeScriptPubKey           = 0
	NativeScriptAll              = 1
	NativeScriptAny              = 2
	NativeScriptNOfK             = 3
	NativeScriptInvalidBefore    = 4
	NativeScriptInvalidHereafter = 5
)

// Native script hash display formats.
const (
	NativeScriptHashHide     = 0
	NativeScriptHashBech32   = 1
	NativeScriptHashPolicyID = 2
)

// Output serialization formats.
const (
	OutputArrayLegacy = 0
	OutputMapBabbage  = 1
)

// Certificate types.
const (
	CertStakeRegistration         = 0
	CertStakeDeregistration       = 1
	CertStakeDelegation           = 2
	CertStakePoolRegistration     = 3
	CertStakeRegistrationConway   = 7
	CertStakeDeregistrationConway = 8
	CertVoteDelegation            = 9
)

// DRep types.
const (
	DRepKeyHash      = 0
	DRepScriptHash   = 1
	DRepAbstain      = 2
	DRepNoConfidence = 3
)

// Pool relay types.
const (
	RelaySingleHostIP   = 0
	RelaySingleHostName = 1
	RelayMultiHostName  = 2
)

// Auxiliary data supplement types.
const (
	AuxSupplementNone                       = 0
	AuxSupplementCVoteRegistrationSignature = 1
)

// CIP-15 and CIP-36 registration formats.
const (
	CVoteFormatCIP15 = 0
	CVoteFormatCIP36 = 1
)

// Signing modes.
const (
	SigningOrdinary                = 0
	SigningPoolRegistrationAsOwner = 1
	SigningMultisig                = 2
	SigningPlutus                  = 3
)

// Witness types.
const (
	WitnessByron   = 0
	WitnessShelley = 1
)

type CardanoBlockchainPointer struct {
	BlockIndex       uint32 `pb:"1"`
	TxIndex          uint32 `pb:"2"`
	CertificateIndex uint32 `pb:"3"`
}

type CardanoNativeScript struct {
	Type                    uint32                `pb:"1"`
	Scripts                 []CardanoNativeScript `pb:"2"`
	KeyHash                 []byte                `pb:"3"`
	KeyPath                 []uint32              `pb:"4"`
	RequiredSignaturesCount *uint32               `pb:"5"`
	InvalidBefore           *uint64               `pb:"6"`
	InvalidHereafter        *uint64               `pb:"7"`
}

type CardanoGetNativeScriptHash struct {
	Script         CardanoNativeScript `pb:"1"`
	DisplayFormat  uint32              `pb:"2"`
	DerivationType uint32              `pb:"3"`
}

type CardanoNativeScriptHash struct {
	ScriptHash []byte `pb:"1"`
}

type CardanoAddressParameters struct {
	AddressType        uint32                    `pb:"1"`
	AddressN           []uint32                  `pb:"2"`
	AddressNStaking    []uint32                  `pb:"3"`
	StakingKeyHash     []byte                    `pb:"4"`
	CertificatePointer *CardanoBlockchainPointer `pb:"5"`
	ScriptPaymentHash  []byte                    `pb:"6"`
	ScriptStakingHash  []byte                    `pb:"7"`
}

type CardanoGetAddress struct {
	ShowDisplay       *bool                    `pb:"2"`
	ProtocolMagic     uint32                   `pb:"3"`
	NetworkID         uint32                   `pb:"4"`
	AddressParameters CardanoAddressParameters `pb:"5"`
	DerivationType    uint32                   `pb:"6"`
	Chunkify          *bool                    `pb:"7"`
}

type CardanoAddress struct {
	Address string `pb:"1"`
	MAC     []byte `pb:"2"`
}

type CardanoGetPublicKey struct {
	AddressN       []uint32 `pb:"1"`
	ShowDisplay    *bool    `pb:"2"`
	DerivationType uint32   `pb:"3"`
}

type CardanoPublicKey struct {
	Xpub string     `pb:"1"`
	Node HDNodeType `pb:"2"`
}

type CardanoSignTxInit struct {
	SigningMode             uint32  `pb:"1"`
	ProtocolMagic           uint32  `pb:"2"`
	NetworkID               uint32  `pb:"3"`
	InputsCount             uint32  `pb:"4"`
	OutputsCount            uint32  `pb:"5"`
	Fee                     uint64  `pb:"6"`
	TTL                     *uint64 `pb:"7"`
	CertificatesCount       uint32  `pb:"8"`
	WithdrawalsCount        uint32  `pb:"9"`
	HasAuxiliaryData        bool    `pb:"10"`
	ValidityIntervalStart   *uint64 `pb:"11"`
	WitnessRequestsCount    uint32  `pb:"12"`
	MintingAssetGroupsCount uint32  `pb:"13"`
	DerivationType          uint32  `pb:"14"`
	IncludeNetworkID        *bool   `pb:"15"`
	ScriptDataHash          []byte  `pb:"16"`
	CollateralInputsCount   uint32  `pb:"17"`
	RequiredSignersCount    uint32  `pb:"18"`
	HasCollateralReturn     *bool   `pb:"19"`
	TotalCollateral         *uint64 `pb:"20"`
	ReferenceInputsCount    *uint32 `pb:"21"`
	Chunkify                *bool   `pb:"22"`
	TagCborSets             *bool   `pb:"23"`
}

type CardanoTxInput struct {
	PrevHash  []byte `pb:"1"`
	PrevIndex uint32 `pb:"2"`
}

type CardanoTxOutput struct {
	Address             *string                   `pb:"1"`
	AddressParameters   *CardanoAddressParameters `pb:"2"`
	Amount              uint64                    `pb:"3"`
	AssetGroupsCount    uint32                    `pb:"4"`
	DatumHash           []byte                    `pb:"5"`
	Format              *uint32                   `pb:"6"`
	InlineDatumSize     *uint32                   `pb:"7"`
	ReferenceScriptSize *uint32                   `pb:"8"`
}

type CardanoAssetGroup struct {
	PolicyID    []byte `pb:"1"`
	TokensCount uint32 `pb:"2"`
}

type CardanoToken struct {
	AssetNameBytes []byte  `pb:"1"`
	Amount         *uint64 `pb:"2"`
	MintAmount     *int64  `pb:"3,zigzag"`
}

type CardanoTxInlineDatumChunk struct {
	Data []byte `pb:"1"`
}

type CardanoTxReferenceScriptChunk struct {
	Data []byte `pb:"1"`
}

type CardanoPoolOwner struct {
	StakingKeyPath []uint32 `pb:"1"`
	StakingKeyHash []byte   `pb:"2"`
}

type CardanoPoolRelayParameters struct {
	Type        uint32  `pb:"1"`
	IPv4Address []byte  `pb:"2"`
	IPv6Address []byte  `pb:"3"`
	HostName    *string `pb:"4"`
	Port        *uint32 `pb:"5"`
}

type CardanoPoolMetadata struct {
	URL  string `pb:"1"`
	Hash []byte `pb:"2"`
}

type CardanoPoolParameters struct {
	PoolID            []byte               `pb:"1"`
	VRFKeyHash        []byte               `pb:"2"`
	Pledge            uint64               `pb:"3"`
	Cost              uint64               `pb:"4"`
	MarginNumerator   uint64               `pb:"5"`
	MarginDenominator uint64               `pb:"6"`
	RewardAccount     string               `pb:"7"`
	Metadata          *CardanoPoolMetadata `pb:"10"`
	OwnersCount       uint32               `pb:"11"`
	RelaysCount       uint32               `pb:"12"`
}

type CardanoDRep struct {
	Type       uint32 `pb:"1"`
	KeyHash    []byte `pb:"2"`
	ScriptHash []byte `pb:"3"`
}

type CardanoTxCertificate struct {
	Type           uint32                 `pb:"1"`
	Path           []uint32               `pb:"2"`
	Pool           []byte                 `pb:"3"`
	PoolParameters *CardanoPoolParameters `pb:"4"`
	ScriptHash     []byte                 `pb:"5"`
	KeyHash        []byte                 `pb:"6"`
	Deposit        *uint64                `pb:"7"`
	DRep           *CardanoDRep           `pb:"8"`
}

type CardanoTxWithdrawal struct {
	Path       []uint32 `pb:"1"`
	Amount     uint64   `pb:"2"`
	ScriptHash []byte   `pb:"3"`
	KeyHash    []byte   `pb:"4"`
}

type CardanoCVoteRegistrationDelegation struct {
	VotePublicKey []byte `pb:"1"`
	Weight        uint32 `pb:"2"`
}

type CardanoCVoteRegistrationParameters struct {
	VotePublicKey            []byte                               `pb:"1"`
	StakingPath              []uint32                             `pb:"2"`
	PaymentAddressParameters *CardanoAddressParameters            `pb:"3"`
	Nonce                    uint64                               `pb:"4"`
	Format                   *uint32                              `pb:"5"`
	Delegations              []CardanoCVoteRegistrationDelegation `pb:"6"`
	VotingPurpose            *uint64                              `pb:"7"`
	PaymentAddress           *string                              `pb:"8"`
}

type CardanoTxAuxiliaryData struct {
	CVoteRegistrationParameters *CardanoCVoteRegistrationParameters `pb:"1"`
	Hash                        []byte                              `pb:"2"`
}

type CardanoTxMint struct {
	AssetGroupsCount uint32 `pb:"1"`
}

type CardanoTxCollateralInput struct {
	PrevHash  []byte `pb:"1"`
	PrevIndex uint32 `pb:"2"`
}

type CardanoTxRequiredSigner struct {
	KeyHash []byte   `pb:"1"`
	KeyPath []uint32 `pb:"2"`
}

type CardanoTxReferenceInput struct {
	PrevHash  []byte `pb:"1"`
	PrevIndex uint32 `pb:"2"`
}

type CardanoTxItemAck struct{}

type CardanoTxAuxiliaryDataSupplement struct {
	Type                       uint32 `pb:"1"`
	AuxiliaryDataHash          []byte `pb:"2"`
	CVoteRegistrationSignature []byte `pb:"3"`
}

type CardanoTxWitnessRequest struct {
	Path []uint32 `pb:"1"`
}

type CardanoTxWitnessResponse struct {
	Type      uint32 `pb:"1"`
	PubKey    []byte `pb:"2"`
	Signature []byte `pb:"3"`
	ChainCode []byte `pb:"4"`
}

type CardanoTxHostAck struct{}

type CardanoTxBodyHash struct {
	TxHash []byte `pb:"1"`
}

type CardanoSignTxFinished struct{}

type CardanoSignMessageInit struct {
	ProtocolMagic     *uint32                   `pb:"1"`
	NetworkID         *uint32                   `pb:"2"`
	SigningPath       []uint32                  `pb:"3"`
	PayloadSize       uint32                    `pb:"4"`
	PreferHexDisplay  bool                      `pb:"5"`
	AddressParameters *CardanoAddressParameters `pb:"6"`
	DerivationType    uint32                    `pb:"7"`
}

type CardanoMessageDataRequest struct {
	Length uint32 `pb:"1"`
	Offset uint32 `pb:"2"`
}

type CardanoMessageDataResponse struct {
	Data []byte `pb:"1"`
}

type CardanoMessageSignature struct {
	Signature []byte `pb:"1"`
	Address   []byte `pb:"2"`
	PubKey    []byte `pb:"3"`
}
