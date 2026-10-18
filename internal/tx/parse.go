// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tx

import (
	"math/big"
	"unicode/utf16"

	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
)

// ParseError reports a transaction that does not follow the CDDL. Its
// message is the reason cardano-hw-interop-lib gives for the same input.
type ParseError struct{ Reason string }

func (e *ParseError) Error() string { return e.Reason }

// Parse error reasons, as cardano-hw-interop-lib words them.
const (
	errInvalidCoin                  = "Invalid coin"
	errInvalidTransactionID         = "Invalid transaction id"
	errInvalidTxInputIndex          = "Invalid transaction input index"
	errInvalidTxInput               = "Invalid transaction input"
	errInvalidTxInputs              = "Invalid transaction inputs"
	errInvalidPolicyID              = "Invalid policy id"
	errInvalidAssetName             = "Invalid asset name"
	errInvalidOutputAddress         = "Invalid output address"
	errInvalidOutputAmount          = "Invalid output amount"
	errInvalidOutputMultiasset      = "Invalid output multiasset"
	errInvalidOutputDatumType       = "Invalid output datum type"
	errInvalidOutputDatumHash       = "Invalid output datum hash"
	errInvalidOutputDatumInline     = "Invalid output inline datum"
	errInvalidOutputDatum           = "Invalid output datum"
	errInvalidOutputReferenceScript = "Invalid output reference script"
	errInvalidTxOutput              = "Invalid transaction output"
	errInvalidTxOutputs             = "Invalid transaction outputs"
	errInvalidFee                   = "Invalid transaction fee"
	errInvalidTTL                   = "Invalid transaction ttl"
	errInvalidCertificateType       = "Invalid certificate type"
	errInvalidCertificate           = "Invalid certificate"
	errInvalidCredentialType        = "Invalid credential type"
	errInvalidCredentialKeyHash     = "Invalid credential key hash"
	errInvalidCredentialScriptHash  = "Invalid credential script hash"
	errInvalidCredential            = "Invalid credential"
	errInvalidPoolKeyHash           = "Invalid pool key hash"
	errInvalidVRFKeyHash            = "Invalid vrf key hash"
	errInvalidPoolParams            = "Invalid pool params"
	errInvalidUnitInterval          = "Invalid unit interval"
	errInvalidUnitIntervalStart     = "Invalid unit interval start"
	errInvalidUnitIntervalEnd       = "Invalid unit interval end"
	errInvalidPoolOwner             = "Invalid pool owner"
	errInvalidPoolOwners            = "Invalid pool owners"
	errInvalidRelayType             = "Invalid relay type"
	errInvalidRelayPort             = "Invalid relay port"
	errInvalidRelayIPv4             = "Invalid relay IPv4"
	errInvalidRelayIPv6             = "Invalid relay IPv6"
	errInvalidRelayDNSName          = "Invalid relay DNS name"
	errInvalidRelay                 = "Invalid relay"
	errInvalidRelays                = "Invalid relays"
	errInvalidPoolMetadataURL       = "Invalid pool metadata URL"
	errInvalidPoolMetadataHash      = "Invalid pool metadata metadata hash"
	errInvalidPoolMetadata          = "Invalid pool metadata"
	errInvalidDRepType              = "Invalid DRep type"
	errInvalidDRep                  = "Invalid DRep"
	errInvalidAnchor                = "Invalid anchor"
	errInvalidAnchorURL             = "Invalid anchor URL"
	errInvalidAnchorDataHash        = "Invalid anchor data hash"
	errInvalidCertificates          = "Invalid transaction certificates"
	errInvalidWithdrawalAmount      = "Invalid withdrawal amount"
	errInvalidRewardAccount         = "Invalid reward account"
	errInvalidWithdrawals           = "Invalid transaction withdrawals"
	errInvalidAuxiliaryDataHash     = "Invalid transaction auxiliary data hash"
	errInvalidValidityIntervalStart = "Invalid transaction validity interval start"
	errInvalidMintAmount            = "Invalid mint amount"
	errInvalidMint                  = "Invalid transaction mint"
	errInvalidScriptDataHash        = "Invalid transaction script data hash"
	errInvalidCollateralInputIndex  = "Invalid transaction collateral input index"
	errInvalidCollateralInput       = "Invalid transaction collateral input"
	errInvalidCollateralInputs      = "Invalid transaction collateral inputs"
	errInvalidRequiredSigners       = "Invalid transaction required signers"
	errInvalidNetworkID             = "Invalid transaction network id"
	errInvalidTotalCollateral       = "Invalid transaction total collateral"
	errInvalidReferenceInputIndex   = "Invalid transaction reference input index"
	errInvalidReferenceInput        = "Invalid transaction reference input"
	errInvalidReferenceInputs       = "Invalid transaction reference inputs"
	errInvalidVotingProcedures      = "Invalid transaction voting procedures"
	errInvalidVotingProceduresEmpty = "Invalid transaction voting procedures --- an empty map included"
	errInvalidVoter                 = "Invalid voter"
	errInvalidGovActionID           = "Invalid governance action id"
	errInvalidVoteOption            = "Invalid vote"
	errInvalidVotingProcedure       = "Invalid voting procedure"
	errInvalidProposalProcedures    = "Invalid proposal procedures"
	errInvalidProposalProcedure     = "Invalid proposal procedure"
	errInvalidTreasury              = "Invalid treasury"
	errInvalidDonation              = "Invalid donation"
	errInvalidTxCBOR                = "Invalid transaction CBOR"
	errInvalidTxBodyCBOR            = "Invalid transaction body CBOR"
	errInvalidTxBodyUnknownItems    = "Transaction body contains unknown items"
)

func perr(reason string) error { return &ParseError{reason} }

// absent reports a missing optional value; CBOR undefined counts as missing,
// as it does in JavaScript.
func absent(v cbor.Value, ok bool) bool {
	return !ok || (v.Kind == cbor.Simple && v.Uint == cbor.SimpleUndefined)
}

func parseUint(v cbor.Value, reason string) (*big.Int, error) {
	if !v.IsInt() {
		return nil, perr(reason)
	}
	n := v.BigInt()
	if n.Sign() < 0 {
		return nil, perr(reason)
	}
	return n, nil
}

func parseInt(v cbor.Value, reason string) (*big.Int, error) {
	if !v.IsInt() {
		return nil, perr(reason)
	}
	return v.BigInt(), nil
}

// smallUint parses an enum discriminator: a JavaScript number in range.
func smallUint(v cbor.Value, max uint64, reason string) (int, error) {
	if v.Kind != cbor.Uint || v.Uint > max {
		return 0, perr(reason)
	}
	return int(v.Uint), nil
}

func parseBytesLen(v cbor.Value, n int, reason string) ([]byte, error) {
	if v.Kind != cbor.Bytes || len(v.Bytes) != n {
		return nil, perr(reason)
	}
	return v.Bytes, nil
}

func parseBytesMax(v cbor.Value, max int, reason string) ([]byte, error) {
	if v.Kind != cbor.Bytes || len(v.Bytes) > max {
		return nil, perr(reason)
	}
	return v.Bytes, nil
}

// parseText parses a string of at most max UTF-16 code units, the way
// JavaScript counts string length.
func parseText(v cbor.Value, max int, reason string) (string, error) {
	if v.Kind != cbor.Text {
		return "", perr(reason)
	}
	s := string(v.Bytes)
	if len(utf16.Encode([]rune(s))) > max {
		return "", perr(reason)
	}
	return s, nil
}

func parseEmbeddedCBOR(v cbor.Value, reason string) ([]byte, error) {
	if v.Kind != cbor.Tag || v.Uint != cbor.TagEncodedCBOR || v.Content().Kind != cbor.Bytes {
		return nil, perr(reason)
	}
	return v.Content().Bytes, nil
}

func tuple(v cbor.Value, n int, reason string) ([]cbor.Value, error) {
	if v.Kind != cbor.Array || len(v.Items) != n {
		return nil, perr(reason)
	}
	return v.Items, nil
}

// typed splits [type, ...rest], checking the type against max.
func typed(v cbor.Value, max uint64, typeReason, reason string) (int, []cbor.Value, error) {
	if v.Kind != cbor.Array || len(v.Items) < 1 {
		return 0, nil, perr(reason)
	}
	t, err := smallUint(v.Items[0], max, typeReason)
	if err != nil {
		return 0, nil, err
	}
	return t, v.Items[1:], nil
}

// mapEntries returns the entries of a map; an empty map is fine.
func mapEntries(v cbor.Value, reason string) ([]cbor.Entry, error) {
	if v.Kind != cbor.Map {
		return nil, perr(reason)
	}
	return v.Entries, nil
}

// parseSet parses a CDDL set, tagged or not, with unique items.
func parseSet[T any](v cbor.Value, nonEmpty bool, reason string, item func(cbor.Value) (T, error)) (Set[T], error) {
	var s Set[T]
	if v.Kind == cbor.Tag {
		if v.Uint != cbor.TagSet {
			return s, perr(reason)
		}
		v = v.Content()
		s.HasTag = true
	}
	if v.Kind != cbor.Array {
		return s, perr(reason)
	}
	seen := map[string]bool{}
	s.Items = make([]T, 0, len(v.Items))
	for _, it := range v.Items {
		x, err := item(it)
		if err != nil {
			return s, err
		}
		// the item serializes to the same CBOR it was parsed from, so its
		// canonical encoding tells duplicates apart
		k := string(cbor.EncodeCanonical(it))
		if seen[k] {
			return s, perr(reason)
		}
		seen[k] = true
		s.Items = append(s.Items, x)
	}
	if nonEmpty && len(s.Items) == 0 {
		return s, perr(reason)
	}
	return s, nil
}

func parseCredential(v cbor.Value) (Credential, error) {
	t, rest, err := typed(v, 1, errInvalidCredentialType, errInvalidCredential)
	if err != nil {
		return Credential{}, err
	}
	if len(rest) != 1 {
		return Credential{}, perr(errInvalidCredential)
	}
	reason := errInvalidCredentialKeyHash
	if t == int(CredentialScriptHash) {
		reason = errInvalidCredentialScriptHash
	}
	h, err := parseBytesLen(rest[0], KeyHashLength, reason)
	return Credential{CredentialType(t), h}, err
}

func parseInput(v cbor.Value, inputReason, indexReason string) (Input, error) {
	t, err := tuple(v, 2, inputReason)
	if err != nil {
		return Input{}, err
	}
	id, err := parseBytesLen(t[0], TxIDLength, errInvalidTransactionID)
	if err != nil {
		return Input{}, err
	}
	idx, err := parseUint(t[1], indexReason)
	return Input{id, idx}, err
}

func parseMultiasset(v cbor.Value, reason string, amount func(cbor.Value) (*big.Int, error)) (Multiasset, error) {
	policies, err := mapEntries(v, reason)
	if err != nil {
		return nil, err
	}
	m := make(Multiasset, 0, len(policies))
	for _, p := range policies {
		pid, err := parseBytesLen(p.Key, ScriptHashLength, errInvalidPolicyID)
		if err != nil {
			return nil, err
		}
		assets, err := mapEntries(p.Value, reason)
		if err != nil {
			return nil, err
		}
		g := AssetGroup{PolicyID: pid, Tokens: make([]Token, 0, len(assets))}
		for _, a := range assets {
			name, err := parseBytesMax(a.Key, AssetNameMaxLength, errInvalidAssetName)
			if err != nil {
				return nil, err
			}
			n, err := amount(a.Value)
			if err != nil {
				return nil, err
			}
			g.Tokens = append(g.Tokens, Token{name, n})
		}
		m = append(m, g)
	}
	return m, nil
}

func parseAmount(v cbor.Value) (Amount, error) {
	if v.IsInt() {
		coin, err := parseUint(v, errInvalidOutputAmount)
		return Amount{Coin: coin}, err
	}
	t, err := tuple(v, 2, errInvalidOutputAmount)
	if err != nil {
		return Amount{}, err
	}
	coin, err := parseUint(t[0], errInvalidOutputAmount)
	if err != nil {
		return Amount{}, err
	}
	m, err := parseMultiasset(t[1], errInvalidOutputMultiasset, func(v cbor.Value) (*big.Int, error) {
		return parseUint(v, errInvalidOutputMultiasset)
	})
	return Amount{Coin: coin, HasMultiasset: true, Multiasset: m}, err
}

func parseOutput(v cbor.Value) (Output, error) {
	if v.Kind == cbor.Array {
		if len(v.Items) < 2 || len(v.Items) > 3 {
			return Output{}, perr(errInvalidTxOutput)
		}
		addr, err := parseBytesMax(v.Items[0], 1<<30, errInvalidOutputAddress)
		if err != nil {
			return Output{}, err
		}
		amount, err := parseAmount(v.Items[1])
		if err != nil {
			return Output{}, err
		}
		o := Output{Format: FormatArrayLegacy, Address: addr, Amount: amount}
		if len(v.Items) == 3 {
			if o.DatumHash, err = parseBytesLen(v.Items[2], DatumHashLength, errInvalidOutputDatumHash); err != nil {
				return Output{}, err
			}
		}
		return o, nil
	}

	entries, err := mapEntries(v, errInvalidTxOutput)
	if err != nil {
		return Output{}, err
	}
	if len(entries) == 0 {
		return Output{}, perr(errInvalidTxOutput)
	}
	for _, e := range entries {
		if e.Key.Kind != cbor.Uint || e.Key.Uint > outKeyReferenceScript {
			return Output{}, perr(errInvalidTxOutput)
		}
	}
	o := Output{Format: FormatMapBabbage}
	addr, ok := v.Get(outKeyAddress)
	if absent(addr, ok) {
		return Output{}, perr(errInvalidOutputAddress)
	}
	if o.Address, err = parseBytesMax(addr, 1<<30, errInvalidOutputAddress); err != nil {
		return Output{}, err
	}
	amount, ok := v.Get(outKeyAmount)
	if absent(amount, ok) {
		return Output{}, perr(errInvalidOutputAmount)
	}
	if o.Amount, err = parseAmount(amount); err != nil {
		return Output{}, err
	}
	if d, ok := v.Get(outKeyDatum); !absent(d, ok) {
		t, rest, err := typed(d, 1, errInvalidOutputDatumType, errInvalidOutputDatum)
		if err != nil {
			return Output{}, err
		}
		if len(rest) != 1 {
			return Output{}, perr(errInvalidOutputDatum)
		}
		datum := &Datum{Type: DatumType(t)}
		if datum.Type == DatumHash {
			datum.Hash, err = parseBytesLen(rest[0], DatumHashLength, errInvalidOutputDatumHash)
		} else {
			datum.Bytes, err = parseEmbeddedCBOR(rest[0], errInvalidOutputDatumInline)
		}
		if err != nil {
			return Output{}, err
		}
		o.Datum = datum
	}
	if s, ok := v.Get(outKeyReferenceScript); !absent(s, ok) {
		if o.ReferenceScript, err = parseEmbeddedCBOR(s, errInvalidOutputReferenceScript); err != nil {
			return Output{}, err
		}
		o.HasReferenceScript = true
	}
	return o, nil
}

func parseAnchor(v cbor.Value) (Anchor, error) {
	t, err := tuple(v, 2, errInvalidAnchor)
	if err != nil {
		return Anchor{}, err
	}
	url, err := parseText(t[0], URLMaxLength, errInvalidAnchorURL)
	if err != nil {
		return Anchor{}, err
	}
	h, err := parseBytesLen(t[1], AnchorDataHashLength, errInvalidAnchorDataHash)
	return Anchor{url, h}, err
}

func parseNullableAnchor(v cbor.Value) (*Anchor, error) {
	if v.IsNull() {
		return nil, nil
	}
	a, err := parseAnchor(v)
	return &a, err
}

func parseDRep(v cbor.Value) (DRep, error) {
	t, rest, err := typed(v, 3, errInvalidDRepType, errInvalidDRep)
	if err != nil {
		return DRep{}, err
	}
	d := DRep{Type: DRepType(t)}
	switch d.Type {
	case DRepKeyHash, DRepScriptHash:
		if len(rest) != 1 {
			return DRep{}, perr(errInvalidDRep)
		}
		d.Hash, err = parseBytesLen(rest[0], KeyHashLength, errInvalidDRep)
	default:
		if len(rest) != 0 {
			return DRep{}, perr(errInvalidDRep)
		}
	}
	return d, err
}

func parseRelay(v cbor.Value) (Relay, error) {
	t, rest, err := typed(v, 2, errInvalidRelayType, errInvalidRelay)
	if err != nil {
		return Relay{}, err
	}
	r := Relay{Type: RelayType(t)}
	port := func(v cbor.Value) error {
		if v.IsNull() {
			return nil
		}
		if v.Kind != cbor.Uint || v.Uint > PortMax {
			return perr(errInvalidRelayPort)
		}
		p := v.Uint
		r.Port = &p
		return nil
	}
	switch r.Type {
	case RelaySingleHostAddress:
		if len(rest) != 3 {
			return Relay{}, perr(errInvalidRelay)
		}
		if err := port(rest[0]); err != nil {
			return Relay{}, err
		}
		if !rest[1].IsNull() {
			if r.IPv4, err = parseBytesLen(rest[1], IPv4Length, errInvalidRelayIPv4); err != nil {
				return Relay{}, err
			}
		}
		if !rest[2].IsNull() {
			if r.IPv6, err = parseBytesLen(rest[2], IPv6Length, errInvalidRelayIPv6); err != nil {
				return Relay{}, err
			}
		}
	case RelaySingleHostName:
		if len(rest) != 2 {
			return Relay{}, perr(errInvalidRelay)
		}
		if err := port(rest[0]); err != nil {
			return Relay{}, err
		}
		if r.DNSName, err = parseText(rest[1], DNSNameMaxLength, errInvalidRelayDNSName); err != nil {
			return Relay{}, err
		}
	case RelayMultiHostName:
		if len(rest) != 1 {
			return Relay{}, perr(errInvalidRelay)
		}
		if r.DNSName, err = parseText(rest[0], DNSNameMaxLength, errInvalidRelayDNSName); err != nil {
			return Relay{}, err
		}
	}
	return r, nil
}

func parsePoolParams(fields []cbor.Value) (*PoolParams, error) {
	if len(fields) != 9 {
		return nil, perr(errInvalidPoolParams)
	}
	p := &PoolParams{}
	var err error
	if p.Operator, err = parseBytesLen(fields[0], PoolKeyHashLength, errInvalidPoolKeyHash); err != nil {
		return nil, err
	}
	if p.VRFKeyHash, err = parseBytesLen(fields[1], VRFKeyHashLength, errInvalidVRFKeyHash); err != nil {
		return nil, err
	}
	if p.Pledge, err = parseUint(fields[2], errInvalidCoin); err != nil {
		return nil, err
	}
	if p.Cost, err = parseUint(fields[3], errInvalidCoin); err != nil {
		return nil, err
	}
	m := fields[4]
	if m.Kind != cbor.Tag || m.Uint != cbor.TagRational {
		return nil, perr(errInvalidUnitInterval)
	}
	mt, err := tuple(m.Content(), 2, errInvalidUnitInterval)
	if err != nil {
		return nil, err
	}
	if p.Margin[0], err = parseUint(mt[0], errInvalidUnitIntervalStart); err != nil {
		return nil, err
	}
	if p.Margin[1], err = parseUint(mt[1], errInvalidUnitIntervalEnd); err != nil {
		return nil, err
	}
	if p.RewardAccount, err = parseBytesLen(fields[5], RewardAccountLength, errInvalidRewardAccount); err != nil {
		return nil, err
	}
	if p.Owners, err = parseSet(fields[6], false, errInvalidPoolOwners, func(v cbor.Value) ([]byte, error) {
		return parseBytesLen(v, KeyHashLength, errInvalidPoolOwner)
	}); err != nil {
		return nil, err
	}
	if fields[7].Kind != cbor.Array {
		return nil, perr(errInvalidRelays)
	}
	p.Relays = make([]Relay, 0, len(fields[7].Items))
	for _, r := range fields[7].Items {
		relay, err := parseRelay(r)
		if err != nil {
			return nil, err
		}
		p.Relays = append(p.Relays, relay)
	}
	if !fields[8].IsNull() {
		t, err := tuple(fields[8], 2, errInvalidPoolMetadata)
		if err != nil {
			return nil, err
		}
		url, err := parseText(t[0], URLMaxLength, errInvalidPoolMetadataURL)
		if err != nil {
			return nil, err
		}
		h, err := parseBytesLen(t[1], PoolMetadataHashLength, errInvalidPoolMetadataHash)
		if err != nil {
			return nil, err
		}
		p.Metadata = &PoolMetadata{url, h}
	}
	return p, nil
}

func parseCertificate(v cbor.Value) (Certificate, error) {
	t, f, err := typed(v, certificateTypeCount-1, errInvalidCertificateType, errInvalidCertificate)
	if err != nil {
		return Certificate{}, err
	}
	c := Certificate{Type: CertificateType(t)}
	want := map[CertificateType]int{
		CertStakeRegistration: 1, CertStakeDeregistration: 1, CertStakeDelegation: 2,
		CertPoolRetirement: 2, CertStakeRegistrationConway: 2, CertStakeDeregistrationConway: 2,
		CertVoteDelegation: 2, CertStakeAndVoteDelegation: 3, CertStakeRegistrationAndDelegation: 3,
		CertStakeRegistrationWithVoteDelegation: 3, CertStakeRegistrationWithStakeAndVoteDeleg: 4,
		CertAuthorizeCommitteeHot: 2, CertResignCommitteeCold: 2, CertDRepRegistration: 3,
		CertDRepDeregistration: 2, CertDRepUpdate: 2,
	}
	if n, ok := want[c.Type]; ok && len(f) != n {
		return Certificate{}, perr(errInvalidCertificate)
	}
	poolKeyHash := func(v cbor.Value) error {
		c.PoolKeyHash, err = parseBytesLen(v, PoolKeyHashLength, errInvalidPoolKeyHash)
		return err
	}
	deposit := func(v cbor.Value) error {
		c.Deposit, err = parseUint(v, errInvalidCoin)
		return err
	}
	drep := func(v cbor.Value) error {
		c.DRep, err = parseDRep(v)
		return err
	}
	anchor := func(v cbor.Value) error {
		c.Anchor, err = parseNullableAnchor(v)
		return err
	}
	cred := func(dst *Credential, v cbor.Value) error {
		*dst, err = parseCredential(v)
		return err
	}
	var errs []error
	switch c.Type {
	case CertStakeRegistration, CertStakeDeregistration:
		errs = []error{cred(&c.StakeCredential, f[0])}
	case CertStakeDelegation:
		errs = []error{cred(&c.StakeCredential, f[0]), poolKeyHash(f[1])}
	case CertPoolRegistration:
		c.PoolParams, err = parsePoolParams(f)
		errs = []error{err}
	case CertPoolRetirement:
		errs = []error{poolKeyHash(f[0])}
		if errs[0] == nil {
			c.Epoch, err = parseUint(f[1], errInvalidCoin)
			errs = append(errs, err)
		}
	case CertGenesisKeyDelegation, CertMoveInstantaneousRewards:
		c.Rest = f
	case CertStakeRegistrationConway, CertStakeDeregistrationConway:
		errs = []error{cred(&c.StakeCredential, f[0]), deposit(f[1])}
	case CertVoteDelegation:
		errs = []error{cred(&c.StakeCredential, f[0]), drep(f[1])}
	case CertStakeAndVoteDelegation:
		errs = []error{cred(&c.StakeCredential, f[0]), poolKeyHash(f[1]), drep(f[2])}
	case CertStakeRegistrationAndDelegation:
		errs = []error{cred(&c.StakeCredential, f[0]), poolKeyHash(f[1]), deposit(f[2])}
	case CertStakeRegistrationWithVoteDelegation:
		errs = []error{cred(&c.StakeCredential, f[0]), drep(f[1]), deposit(f[2])}
	case CertStakeRegistrationWithStakeAndVoteDeleg:
		errs = []error{cred(&c.StakeCredential, f[0]), poolKeyHash(f[1]), drep(f[2]), deposit(f[3])}
	case CertAuthorizeCommitteeHot:
		errs = []error{cred(&c.ColdCredential, f[0]), cred(&c.HotCredential, f[1])}
	case CertResignCommitteeCold:
		errs = []error{cred(&c.ColdCredential, f[0]), anchor(f[1])}
	case CertDRepRegistration:
		errs = []error{cred(&c.DRepCredential, f[0]), deposit(f[1]), anchor(f[2])}
	case CertDRepDeregistration:
		errs = []error{cred(&c.DRepCredential, f[0]), deposit(f[1])}
	case CertDRepUpdate:
		errs = []error{cred(&c.DRepCredential, f[0]), anchor(f[1])}
	}
	for _, e := range errs {
		if e != nil {
			return Certificate{}, e
		}
	}
	return c, nil
}

func parseVoterVotes(v cbor.Value) ([]VoterVotes, error) {
	voters, err := mapEntries(v, errInvalidVotingProcedures)
	if err != nil {
		return nil, err
	}
	var out []VoterVotes
	for _, e := range voters {
		t, rest, err := typed(e.Key, 4, errInvalidVoter, errInvalidVoter)
		if err != nil {
			return nil, err
		}
		if len(rest) != 1 {
			return nil, perr(errInvalidVoter)
		}
		hash, err := parseBytesLen(rest[0], KeyHashLength, errInvalidVoter)
		if err != nil {
			return nil, err
		}
		vv := VoterVotes{Voter: Voter{VoterType(t), hash}}
		votes, err := mapEntries(e.Value, errInvalidVoteOption)
		if err != nil {
			return nil, err
		}
		if len(votes) == 0 {
			return nil, perr(errInvalidVotingProceduresEmpty)
		}
		for _, ve := range votes {
			gt, err := tuple(ve.Key, 2, errInvalidGovActionID)
			if err != nil {
				return nil, err
			}
			txid, err := parseBytesLen(gt[0], TxIDLength, errInvalidGovActionID)
			if err != nil {
				return nil, err
			}
			idx, err := parseUint(gt[1], errInvalidGovActionID)
			if err != nil {
				return nil, err
			}
			pt, err := tuple(ve.Value, 2, errInvalidVotingProcedure)
			if err != nil {
				return nil, err
			}
			opt, err := smallUint(pt[0], 2, errInvalidVoteOption)
			if err != nil {
				return nil, err
			}
			anchor, err := parseNullableAnchor(pt[1])
			if err != nil {
				return nil, err
			}
			vv.Votes = append(vv.Votes, Vote{GovActionID{txid, idx}, VotingProcedure{VoteOption(opt), anchor}})
		}
		out = append(out, vv)
	}
	if len(out) == 0 {
		return nil, perr(errInvalidVotingProceduresEmpty)
	}
	return out, nil
}

var bodyKeys = map[uint64]bool{
	keyInputs: true, keyOutputs: true, keyFee: true, keyTTL: true, keyCertificates: true,
	keyWithdrawals: true, keyUpdate: true, keyAuxiliaryDataHash: true, keyValidityIntervalStart: true,
	keyMint: true, keyScriptDataHash: true, keyCollateralInputs: true, keyRequiredSigners: true,
	keyNetworkID: true, keyCollateralReturn: true, keyTotalCollateral: true, keyReferenceInputs: true,
	keyVotingProcedures: true, keyProposalProcedures: true, keyTreasury: true, keyDonation: true,
}

// ParseBody parses a transaction body.
func ParseBody(v cbor.Value) (Body, error) {
	var b Body
	if v.Kind != cbor.Map || len(v.Entries) == 0 {
		return b, perr(errInvalidTxBodyCBOR)
	}
	for _, e := range v.Entries {
		if e.Key.Kind != cbor.Uint && e.Key.Kind != cbor.NegInt {
			return b, perr(errInvalidTxBodyCBOR)
		}
	}
	for _, e := range v.Entries {
		if e.Key.Kind != cbor.Uint || !bodyKeys[e.Key.Uint] {
			return b, perr(errInvalidTxBodyUnknownItems)
		}
	}
	get := func(k uint64) (cbor.Value, bool) {
		x, ok := v.Get(k)
		return x, !absent(x, ok)
	}
	var err error

	inputs, _ := get(keyInputs)
	if b.Inputs, err = parseSet(inputs, false, errInvalidTxInputs, func(v cbor.Value) (Input, error) {
		return parseInput(v, errInvalidTxInput, errInvalidTxInputIndex)
	}); err != nil {
		return b, err
	}

	outputs, _ := get(keyOutputs)
	if outputs.Kind != cbor.Array {
		return b, perr(errInvalidTxOutputs)
	}
	b.Outputs = make([]Output, 0, len(outputs.Items))
	for _, o := range outputs.Items {
		out, err := parseOutput(o)
		if err != nil {
			return b, err
		}
		b.Outputs = append(b.Outputs, out)
	}

	fee, _ := get(keyFee)
	if b.Fee, err = parseUint(fee, errInvalidFee); err != nil {
		return b, err
	}
	if x, ok := get(keyTTL); ok {
		if b.TTL, err = parseUint(x, errInvalidTTL); err != nil {
			return b, err
		}
	}
	if x, ok := get(keyCertificates); ok {
		s, err := parseSet(x, true, errInvalidCertificates, parseCertificate)
		if err != nil {
			return b, err
		}
		b.Certificates = &s
	}
	if x, ok := get(keyWithdrawals); ok {
		entries, err := mapEntries(x, errInvalidWithdrawals)
		if err != nil {
			return b, err
		}
		b.HasWithdrawals = true
		for _, e := range entries {
			acct, err := parseBytesLen(e.Key, RewardAccountLength, errInvalidRewardAccount)
			if err != nil {
				return b, err
			}
			n, err := parseUint(e.Value, errInvalidWithdrawalAmount)
			if err != nil {
				return b, err
			}
			b.Withdrawals = append(b.Withdrawals, Withdrawal{acct, n})
		}
	}
	if x, ok := get(keyUpdate); ok {
		b.Update = &x
	}
	if x, ok := get(keyAuxiliaryDataHash); ok {
		if b.AuxiliaryDataHash, err = parseBytesLen(x, AuxiliaryDataHashLength, errInvalidAuxiliaryDataHash); err != nil {
			return b, err
		}
	}
	if x, ok := get(keyValidityIntervalStart); ok {
		if b.ValidityIntervalStart, err = parseUint(x, errInvalidValidityIntervalStart); err != nil {
			return b, err
		}
	}
	if x, ok := get(keyMint); ok {
		if b.Mint, err = parseMultiasset(x, errInvalidMint, func(v cbor.Value) (*big.Int, error) {
			return parseInt(v, errInvalidMintAmount)
		}); err != nil {
			return b, err
		}
		b.HasMint = true
	}
	if x, ok := get(keyScriptDataHash); ok {
		if b.ScriptDataHash, err = parseBytesLen(x, ScriptDataHashLength, errInvalidScriptDataHash); err != nil {
			return b, err
		}
	}
	if x, ok := get(keyCollateralInputs); ok {
		s, err := parseSet(x, true, errInvalidCollateralInputs, func(v cbor.Value) (Input, error) {
			return parseInput(v, errInvalidCollateralInput, errInvalidCollateralInputIndex)
		})
		if err != nil {
			return b, err
		}
		b.CollateralInputs = &s
	}
	if x, ok := get(keyRequiredSigners); ok {
		s, err := parseSet(x, true, errInvalidRequiredSigners, func(v cbor.Value) ([]byte, error) {
			return parseBytesLen(v, KeyHashLength, errInvalidRequiredSigners)
		})
		if err != nil {
			return b, err
		}
		b.RequiredSigners = &s
	}
	if x, ok := get(keyNetworkID); ok {
		if b.NetworkID, err = parseUint(x, errInvalidNetworkID); err != nil {
			return b, err
		}
	}
	if x, ok := get(keyCollateralReturn); ok {
		o, err := parseOutput(x)
		if err != nil {
			return b, err
		}
		b.CollateralReturn = &o
	}
	if x, ok := get(keyTotalCollateral); ok {
		if b.TotalCollateral, err = parseUint(x, errInvalidTotalCollateral); err != nil {
			return b, err
		}
	}
	if x, ok := get(keyReferenceInputs); ok {
		s, err := parseSet(x, true, errInvalidReferenceInputs, func(v cbor.Value) (Input, error) {
			return parseInput(v, errInvalidReferenceInput, errInvalidReferenceInputIndex)
		})
		if err != nil {
			return b, err
		}
		b.ReferenceInputs = &s
	}
	if x, ok := get(keyVotingProcedures); ok {
		if b.VotingProcedures, err = parseVoterVotes(x); err != nil {
			return b, err
		}
		b.HasVotingProcedures = true
	}
	if x, ok := get(keyProposalProcedures); ok {
		s, err := parseSet(x, true, errInvalidProposalProcedures, func(v cbor.Value) (ProposalProcedure, error) {
			t, err := tuple(v, 4, errInvalidProposalProcedure)
			if err != nil {
				return ProposalProcedure{}, err
			}
			var p ProposalProcedure
			if p.Deposit, err = parseUint(t[0], errInvalidCoin); err != nil {
				return p, err
			}
			if p.RewardAccount, err = parseBytesLen(t[1], RewardAccountLength, errInvalidRewardAccount); err != nil {
				return p, err
			}
			p.GovAction = t[2]
			p.Anchor, err = parseAnchor(t[3])
			return p, err
		})
		if err != nil {
			return b, err
		}
		b.ProposalProcedures = &s
	}
	if x, ok := get(keyTreasury); ok {
		if b.Treasury, err = parseUint(x, errInvalidTreasury); err != nil {
			return b, err
		}
	}
	if x, ok := get(keyDonation); ok {
		if b.Donation, err = parseUint(x, errInvalidDonation); err != nil {
			return b, err
		}
		if b.Donation.Sign() == 0 {
			return b, perr(errInvalidDonation)
		}
	}
	return b, nil
}

// ParseTx parses a transaction: [body, witness set, auxiliary data] in the
// Shelley to Mary format, or [body, witness set, script validity, auxiliary
// data] from Alonzo on.
//
// As cardano-hw-interop-lib does, the body is parsed before the number of
// items is checked; missing items and CBOR undefined count as absent, and
// may only come last.
func ParseTx(v cbor.Value) (Transaction, error) {
	if v.Kind != cbor.Array || len(v.Items) > 4 {
		return Transaction{}, perr(errInvalidTxCBOR)
	}
	var first cbor.Value // absent: not a map, so an invalid body
	if len(v.Items) > 0 {
		first = v.Items[0]
	}
	body, err := ParseBody(first)
	if err != nil {
		return Transaction{}, err
	}
	var present []cbor.Value
	ended := false
	for _, it := range v.Items[min(1, len(v.Items)):] {
		if it.Kind == cbor.Simple && it.Uint == cbor.SimpleUndefined {
			ended = true
			continue
		}
		if ended {
			return Transaction{}, perr(errInvalidTxCBOR)
		}
		present = append(present, it)
	}
	t := Transaction{Body: body}
	switch len(present) {
	case 2:
		t.WitnessSet, t.AuxiliaryData = present[0], present[1]
	case 3:
		sv := present[1]
		t.WitnessSet, t.ScriptValidity, t.AuxiliaryData = present[0], &sv, present[2]
	default:
		return Transaction{}, perr(errInvalidTxCBOR)
	}
	return t, nil
}
