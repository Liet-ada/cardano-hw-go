// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package msg describes the Trezor protocol buffers messages that
// cardano-hw-go exchanges: field numbers, wire types and message type
// numbers, as the firmware expects them. Only the fields used are listed.
package msg

// Message type numbers.
const (
	TypeInitialize        = 0
	TypeSuccess           = 2
	TypeFailure           = 3
	TypeFeatures          = 17
	TypeCancel            = 20
	TypeButtonRequest     = 26
	TypeButtonAck         = 27
	TypePassphraseRequest = 41
	TypePassphraseAck     = 42
	TypeGetFeatures       = 55
	TypeEndSession        = 83

	TypeDebugLinkDecision       = 100
	TypeDebugLinkGetState       = 101
	TypeDebugLinkState          = 102
	TypeDebugLinkGetPairingInfo = 9011
	TypeDebugLinkPairingInfo    = 9012

	TypeCardanoGetPublicKey              = 305
	TypeCardanoPublicKey                 = 306
	TypeCardanoGetAddress                = 307
	TypeCardanoAddress                   = 308
	TypeCardanoTxItemAck                 = 313
	TypeCardanoTxAuxiliaryDataSupplement = 314
	TypeCardanoTxWitnessRequest          = 315
	TypeCardanoTxWitnessResponse         = 316
	TypeCardanoTxHostAck                 = 317
	TypeCardanoTxBodyHash                = 318
	TypeCardanoSignTxFinished            = 319
	TypeCardanoSignTxInit                = 320
	TypeCardanoTxInput                   = 321
	TypeCardanoTxOutput                  = 322
	TypeCardanoAssetGroup                = 323
	TypeCardanoToken                     = 324
	TypeCardanoTxCertificate             = 325
	TypeCardanoTxWithdrawal              = 326
	TypeCardanoTxAuxiliaryData           = 327
	TypeCardanoPoolOwner                 = 328
	TypeCardanoPoolRelayParameters       = 329
	TypeCardanoGetNativeScriptHash       = 330
	TypeCardanoNativeScriptHash          = 331
	TypeCardanoTxMint                    = 332
	TypeCardanoTxCollateralInput         = 333
	TypeCardanoTxRequiredSigner          = 334
	TypeCardanoTxInlineDatumChunk        = 335
	TypeCardanoTxReferenceScriptChunk    = 336
	TypeCardanoTxReferenceInput          = 337
	TypeCardanoSignMessageInit           = 338
	TypeCardanoMessageDataRequest        = 339
	TypeCardanoMessageDataResponse       = 340
	TypeCardanoMessageSignature          = 341

	TypeThpCreateNewSession            = 1000
	TypeThpPairingRequest              = 1008
	TypeThpPairingRequestApproved      = 1009
	TypeThpSelectMethod                = 1010
	TypeThpPairingPreparationsFinished = 1011
	TypeThpCredentialRequest           = 1016
	TypeThpCredentialResponse          = 1017
	TypeThpEndRequest                  = 1018
	TypeThpEndResponse                 = 1019
	TypeThpCodeEntryCommitment         = 1024
	TypeThpCodeEntryChallenge          = 1025
	TypeThpCodeEntryCpaceTrezor        = 1026
	TypeThpCodeEntryCpaceHostTag       = 1027
	TypeThpCodeEntrySecret             = 1028
)

// --- management

type Initialize struct {
	SessionID     []byte `pb:"1"`
	DeriveCardano *bool  `pb:"3"`
}

type GetFeatures struct{}

// Capability values of Features.
const (
	CapabilityCardano         = 4
	CapabilityPassphraseEntry = 17
)

type Features struct {
	Vendor               *string  `pb:"1"`
	MajorVersion         uint32   `pb:"2"`
	MinorVersion         uint32   `pb:"3"`
	PatchVersion         uint32   `pb:"4"`
	BootloaderMode       *bool    `pb:"5"`
	DeviceID             *string  `pb:"6"`
	PinProtection        *bool    `pb:"7"`
	PassphraseProtection *bool    `pb:"8"`
	Label                *string  `pb:"10"`
	Initialized          *bool    `pb:"12"`
	Unlocked             *bool    `pb:"16"`
	Model                *string  `pb:"21"`
	FwVendor             *string  `pb:"25"`
	Capabilities         []uint32 `pb:"30"`
	SessionID            []byte   `pb:"35"`
	InternalModel        *string  `pb:"44"`
}

type Success struct {
	Message *string `pb:"1"`
}

// Failure codes.
const (
	FailureUnexpectedMessage     = 1
	FailureButtonExpected        = 2
	FailureDataError             = 3
	FailureActionCancelled       = 4
	FailurePinExpected           = 5
	FailurePinCancelled          = 6
	FailurePinInvalid            = 7
	FailureProcessError          = 9
	FailureNotInitialized        = 11
	FailureInvalidSession        = 14
	FailureBusy                  = 15
	FailureThpUnallocatedSession = 16
	FailureInvalidProtocol       = 17
	FailureFirmwareError         = 99
)

type Failure struct {
	Code    *uint32 `pb:"1"`
	Message *string `pb:"2"`
}

type ButtonRequest struct {
	Code  *uint32 `pb:"1"`
	Pages *uint32 `pb:"2"`
	Name  *string `pb:"4"`
}

type ButtonAck struct{}

type PassphraseRequest struct{}

type PassphraseAck struct {
	Passphrase *string `pb:"1"`
	OnDevice   *bool   `pb:"3"`
}

type Cancel struct{}

type EndSession struct{}

type HDNodeType struct {
	Depth       uint32 `pb:"1"`
	Fingerprint uint32 `pb:"2"`
	ChildNum    uint32 `pb:"3"`
	ChainCode   []byte `pb:"4"`
	PublicKey   []byte `pb:"6"`
}

// --- debuglink, for the emulator

type DebugLinkDecision struct {
	Button *uint32 `pb:"1"`
	Swipe  *uint32 `pb:"2"`
	Input  *string `pb:"3"`
	X      *uint32 `pb:"4"`
	Y      *uint32 `pb:"5"`
}

// DebugLinkDecision buttons.
const (
	DebugButtonNo  = 0
	DebugButtonYes = 1
)

type DebugLinkGetState struct {
	WaitLayout *uint32 `pb:"3"`
}

type DebugLinkState struct {
	Tokens []string `pb:"13"`
}

type DebugLinkGetPairingInfo struct {
	ChannelID     []byte `pb:"1"`
	HandshakeHash []byte `pb:"2"`
}

type DebugLinkPairingInfo struct {
	ChannelID     []byte  `pb:"1"`
	HandshakeHash []byte  `pb:"2"`
	CodeEntryCode *uint32 `pb:"3"`
}

// --- THP

type ThpDeviceProperties struct {
	InternalModel        string   `pb:"1"`
	ModelVariant         *uint32  `pb:"2"`
	ProtocolVersionMajor uint32   `pb:"3"`
	ProtocolVersionMinor uint32   `pb:"4"`
	PairingMethods       []uint32 `pb:"5"`
}

// Pairing methods.
const (
	PairingSkip      = 1
	PairingCodeEntry = 2
	PairingQrCode    = 3
	PairingNFC       = 4
)

type ThpHandshakeCompletionReqNoisePayload struct {
	HostPairingCredential []byte `pb:"1"`
}

type ThpCreateNewSession struct {
	Passphrase    *string `pb:"1"`
	OnDevice      *bool   `pb:"2"`
	DeriveCardano *bool   `pb:"3"`
}

type ThpPairingRequest struct {
	HostName string `pb:"1"`
	AppName  string `pb:"2"`
}

type ThpPairingRequestApproved struct{}

type ThpSelectMethod struct {
	SelectedPairingMethod uint32 `pb:"1"`
}

type ThpPairingPreparationsFinished struct{}

type ThpCodeEntryCommitment struct {
	Commitment []byte `pb:"1"`
}

type ThpCodeEntryChallenge struct {
	Challenge []byte `pb:"1"`
}

type ThpCodeEntryCpaceTrezor struct {
	CpaceTrezorPublicKey []byte `pb:"1"`
}

type ThpCodeEntryCpaceHostTag struct {
	CpaceHostPublicKey []byte `pb:"1"`
	Tag                []byte `pb:"2"`
}

type ThpCodeEntrySecret struct {
	Secret []byte `pb:"1"`
}

type ThpCredentialRequest struct {
	HostStaticPublicKey []byte `pb:"1"`
	Autoconnect         *bool  `pb:"2"`
	Credential          []byte `pb:"3"`
}

type ThpCredentialResponse struct {
	TrezorStaticPublicKey []byte `pb:"1"`
	Credential            []byte `pb:"2"`
}

type ThpEndRequest struct{}

type ThpEndResponse struct{}
