// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package trezor is the hardware wallet provider for Trezor. It maps
// cardano-hw-cli's operations onto the Trezor's Cardano messages, streaming
// transactions item by item and checking what the device returns.
package trezor

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
	"github.com/Liet-ada/cardano-hw-go/internal/hw"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/msg"
	"github.com/Liet-ada/cardano-hw-go/internal/trezor/pb"
	"github.com/Liet-ada/cardano-hw-go/internal/tx"
)

// Errors with cardano-hw-cli's wording.
var (
	ErrPoolRegistrationAsOperator = errors.New("Trezor does not support signing pool registration certificate as operator")
	ErrVotingProcedures           = errors.New("Trezor does not support voting procedures")
	ErrTreasury                   = errors.New("Trezor does not support treasury item in transaction body")
	ErrDonation                   = errors.New("Trezor does not support donation item in transaction body")
	ErrUnsupportedCall            = errors.New("The call is not supported by the chosen crypto provider")
	ErrInvalidAddressParameters   = errors.New("Invalid address parameters provided")
	ErrXPubKeyCancelled           = errors.New("Extended public key export cancelled by user")
	ErrHashPayloadUnsupported     = errors.New("Trezor does not support the `--hashed` option in message signing")
	ErrMissingAuxDataSupplement   = errors.New("Missing auxiliary data supplement in response.")
	ErrMissingCIP36Signature      = errors.New("Missing CIP36 voting signature")
)

// chunkSize is the size of the chunks of inline datums and reference
// scripts.
const chunkSize = 1024

// Provider is a Trezor.
type Provider struct {
	c *trezor.Client
}

// New wraps a connected Trezor client.
func New(c *trezor.Client) *Provider { return &Provider{c: c} }

func (p *Provider) Close() error { return nil }

func (p *Provider) Version() (string, error) {
	f := p.c.Features()
	return fmt.Sprintf("Trezor app version %d.%d.%d", f.MajorVersion, f.MinorVersion, f.PatchVersion), nil
}

func (p *Provider) SupportsUnrestricted() (bool, error) { return false, nil }

func derivation(dt hw.DerivationType) uint32 {
	switch dt {
	case hw.DerivationLedger:
		return msg.DerivationLedger
	case hw.DerivationIcarus:
		return msg.DerivationIcarus
	}
	return msg.DerivationIcarusTrezor
}

func path(p cardano.Path) []uint32 { return append([]uint32{}, p...) }

func boolPtr(b bool) *bool   { return &b }
func u32(v uint32) *uint32   { return &v }
func u64(v uint64) *uint64   { return &v }
func str(s string) *string   { return &s }
func i64(v int64) *int64     { return &v }
func fits32(n *big.Int) bool { return n.IsUint64() && n.Uint64() <= math.MaxUint32 }
func optU64(n *big.Int) *uint64 {
	if n == nil {
		return nil
	}
	return u64(n.Uint64())
}

func (p *Provider) XPubKeys(paths []cardano.Path, dt hw.DerivationType) ([][]byte, error) {
	var out [][]byte
	for _, pa := range paths {
		var r msg.CardanoPublicKey
		err := p.c.Call(msg.TypeCardanoGetPublicKey, &msg.CardanoGetPublicKey{
			AddressN: path(pa), ShowDisplay: boolPtr(true), DerivationType: derivation(dt),
		}, msg.TypeCardanoPublicKey, &r)
		if trezor.Cancelled(err) {
			return nil, ErrXPubKeyCancelled
		}
		if err != nil {
			return nil, err
		}
		if len(r.Node.PublicKey) != 32 || len(r.Node.ChainCode) != 32 {
			return nil, errors.New("trezor: invalid public key")
		}
		out = append(out, append(append([]byte{}, r.Node.PublicKey...), r.Node.ChainCode...))
	}
	return out, nil
}

func (p *Provider) ShowAddress(a hw.ShowAddressParams) error {
	attrs, err := cardano.Attributes(a.Address)
	if err != nil {
		return err
	}
	params := msg.CardanoAddressParameters{
		AddressType:       uint32(attrs.Type),
		AddressN:          path(a.PaymentPath),
		AddressNStaking:   path(a.StakingPath),
		ScriptPaymentHash: a.PaymentScriptHash,
		ScriptStakingHash: a.StakingScriptHash,
	}
	var r msg.CardanoAddress
	if err := p.c.Call(msg.TypeCardanoGetAddress, &msg.CardanoGetAddress{
		ShowDisplay: boolPtr(true), ProtocolMagic: attrs.ProtocolMagic, NetworkID: attrs.NetworkID,
		AddressParameters: params, DerivationType: derivation(a.DerivationType),
	}, msg.TypeCardanoAddress, &r); err != nil {
		if trezor.Cancelled(err) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrInvalidAddressParameters, err)
	}
	// the device derives the address itself: it must be the one given
	if r.Address != a.Address {
		return fmt.Errorf("the Trezor shows %s, not the address in the file (%s)", r.Address, a.Address)
	}
	return nil
}

// addressParams builds the address parameters of a wallet address.
func addressParams(ap *hw.AddressParams) *msg.CardanoAddressParameters {
	return &msg.CardanoAddressParameters{
		AddressType:     uint32(ap.Type),
		AddressN:        path(ap.PaymentPath),
		AddressNStaking: path(ap.StakePath),
	}
}

// item is one message of the transaction stream.
type item struct {
	t   uint16
	msg any
}

type txBuilder struct {
	params hw.TxSigningParams
	change []cardano.SigningFile
}

func (b *txBuilder) tokenItems(m tx.Multiasset, mint bool) []item {
	var items []item
	for _, g := range m {
		items = append(items, item{msg.TypeCardanoAssetGroup, &msg.CardanoAssetGroup{PolicyID: g.PolicyID, TokensCount: uint32(len(g.Tokens))}})
		for _, t := range g.Tokens {
			tok := &msg.CardanoToken{AssetNameBytes: t.AssetName}
			if mint {
				tok.MintAmount = i64(t.Amount.Int64())
			} else {
				tok.Amount = u64(t.Amount.Uint64())
			}
			items = append(items, item{msg.TypeCardanoToken, tok})
		}
	}
	return items
}

func chunks(t uint16, data []byte, wrap func([]byte) any) []item {
	var items []item
	for len(data) > 0 {
		n := min(chunkSize, len(data))
		items = append(items, item{t, wrap(data[:n])})
		data = data[n:]
	}
	return items
}

func (b *txBuilder) outputItems(o tx.Output) ([]item, error) {
	out := &msg.CardanoTxOutput{Amount: o.Amount.Coin.Uint64()}
	if o.Format == tx.FormatMapBabbage {
		out.Format = u32(msg.OutputMapBabbage)
	} else {
		out.Format = u32(msg.OutputArrayLegacy)
	}
	if ap := hw.AddressParamsFor(b.change, o.Address, b.params.Network); ap != nil && hw.AddressParamsAllowed(b.params.Mode) {
		out.AddressParameters = addressParams(ap)
	} else {
		s, err := cardano.EncodeAddress(o.Address)
		if err != nil {
			return nil, err
		}
		out.Address = &s
	}
	var tokens []item
	if o.Amount.HasMultiasset {
		out.AssetGroupsCount = uint32(len(o.Amount.Multiasset))
		tokens = b.tokenItems(o.Amount.Multiasset, false)
	}
	var inline, script []byte
	switch {
	case o.Format == tx.FormatArrayLegacy:
		out.DatumHash = o.DatumHash
	case o.Datum != nil && o.Datum.Type == tx.DatumHash:
		out.DatumHash = o.Datum.Hash
	case o.Datum != nil:
		inline = o.Datum.Bytes
		out.InlineDatumSize = u32(uint32(len(inline)))
	}
	if o.HasReferenceScript {
		script = o.ReferenceScript
		out.ReferenceScriptSize = u32(uint32(len(script)))
	}
	items := append([]item{{msg.TypeCardanoTxOutput, out}}, tokens...)
	items = append(items, chunks(msg.TypeCardanoTxInlineDatumChunk, inline, func(d []byte) any { return &msg.CardanoTxInlineDatumChunk{Data: d} })...)
	items = append(items, chunks(msg.TypeCardanoTxReferenceScriptChunk, script, func(d []byte) any { return &msg.CardanoTxReferenceScriptChunk{Data: d} })...)
	return items, nil
}

// credential gives a key hash credential as a path when a signing file has
// its key, as cardano-hw-cli does; key hashes go as such only in Plutus mode.
func (b *txBuilder) credential(c tx.Credential) (keyPath []uint32, keyHash, scriptHash []byte, err error) {
	if c.Type == tx.CredentialScriptHash {
		return nil, nil, c.Hash, nil
	}
	if p := hw.PathForKeyHash(c.Hash, b.params.SigningFiles); p != nil {
		return path(p), nil, nil, nil
	}
	if b.params.Mode == hw.SigningPlutus {
		return nil, c.Hash, nil, nil
	}
	return nil, nil, nil, hw.ErrMissingSigningFileForCertificate
}

func (b *txBuilder) drep(d tx.DRep) *msg.CardanoDRep {
	r := &msg.CardanoDRep{Type: uint32(d.Type)}
	switch d.Type {
	case tx.DRepKeyHash:
		r.KeyHash = d.Hash
	case tx.DRepScriptHash:
		r.ScriptHash = d.Hash
	}
	return r
}

// swapIPv6 reverses each 32-bit word: the Trezor serializes the bytes it gets
// that way, so this gives back the transaction's bytes.
func swapIPv6(b []byte) []byte {
	out := make([]byte, len(b))
	for i := 0; i+4 <= len(b); i += 4 {
		out[i], out[i+1], out[i+2], out[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return out
}

func (b *txBuilder) certificateItems(c tx.Certificate) ([]item, error) {
	cert := &msg.CardanoTxCertificate{}
	simple := map[tx.CertificateType]uint32{
		tx.CertStakeRegistration:         msg.CertStakeRegistration,
		tx.CertStakeDeregistration:       msg.CertStakeDeregistration,
		tx.CertStakeDelegation:           msg.CertStakeDelegation,
		tx.CertStakeRegistrationConway:   msg.CertStakeRegistrationConway,
		tx.CertStakeDeregistrationConway: msg.CertStakeDeregistrationConway,
		tx.CertVoteDelegation:            msg.CertVoteDelegation,
	}
	if t, ok := simple[c.Type]; ok {
		cert.Type = t
		var err error
		if cert.Path, cert.KeyHash, cert.ScriptHash, err = b.credential(c.StakeCredential); err != nil {
			return nil, err
		}
		switch c.Type {
		case tx.CertStakeDelegation:
			cert.Pool = c.PoolKeyHash
		case tx.CertStakeRegistrationConway, tx.CertStakeDeregistrationConway:
			cert.Deposit = u64(c.Deposit.Uint64())
		case tx.CertVoteDelegation:
			cert.DRep = b.drep(c.DRep)
		}
		return []item{{msg.TypeCardanoTxCertificate, cert}}, nil
	}
	switch c.Type {
	case tx.CertPoolRegistration:
		pp := c.PoolParams
		var owners []item
		withPath := 0
		for _, o := range pp.Owners.Items {
			if pa := hw.PathForKeyHash(o, b.params.SigningFiles); pa != nil {
				owners = append(owners, item{msg.TypeCardanoPoolOwner, &msg.CardanoPoolOwner{StakingKeyPath: path(pa)}})
				withPath++
			} else {
				owners = append(owners, item{msg.TypeCardanoPoolOwner, &msg.CardanoPoolOwner{StakingKeyHash: o}})
			}
		}
		if withPath == 0 {
			return nil, hw.ErrMissingSigningFileForCertificate
		}
		if withPath > 1 {
			return nil, hw.ErrOwnerMultipleTimes
		}
		var relays []item
		for _, r := range pp.Relays {
			rp := &msg.CardanoPoolRelayParameters{Type: uint32(r.Type)}
			if r.Port != nil {
				rp.Port = u32(uint32(*r.Port))
			}
			if r.IPv4 != nil {
				rp.IPv4Address = r.IPv4
			}
			if r.IPv6 != nil {
				rp.IPv6Address = swapIPv6(r.IPv6)
			}
			if r.Type != tx.RelaySingleHostAddress {
				rp.HostName = str(r.DNSName)
			}
			relays = append(relays, item{msg.TypeCardanoPoolRelayParameters, rp})
		}
		reward, err := cardano.EncodeAddress(pp.RewardAccount)
		if err != nil {
			return nil, err
		}
		params := &msg.CardanoPoolParameters{
			PoolID: pp.Operator, VRFKeyHash: pp.VRFKeyHash,
			Pledge: pp.Pledge.Uint64(), Cost: pp.Cost.Uint64(),
			MarginNumerator: pp.Margin[0].Uint64(), MarginDenominator: pp.Margin[1].Uint64(),
			RewardAccount: reward, OwnersCount: uint32(len(owners)), RelaysCount: uint32(len(relays)),
		}
		if pp.Metadata != nil {
			params.Metadata = &msg.CardanoPoolMetadata{URL: pp.Metadata.URL, Hash: pp.Metadata.Hash}
		}
		cert.Type = msg.CertStakePoolRegistration
		cert.PoolParameters = params
		items := append([]item{{msg.TypeCardanoTxCertificate, cert}}, owners...)
		return append(items, relays...), nil
	case tx.CertPoolRetirement, tx.CertStakeAndVoteDelegation, tx.CertStakeRegistrationAndDelegation,
		tx.CertStakeRegistrationWithVoteDelegation, tx.CertStakeRegistrationWithStakeAndVoteDeleg,
		tx.CertAuthorizeCommitteeHot, tx.CertResignCommitteeCold, tx.CertDRepRegistration,
		tx.CertDRepDeregistration, tx.CertDRepUpdate:
		return nil, hw.ErrUnsupportedCertificateType
	}
	return nil, hw.ErrUnknownCertificate
}

func signingMode(m hw.SigningMode) (uint32, error) {
	switch m {
	case hw.SigningOrdinary:
		return msg.SigningOrdinary, nil
	case hw.SigningPoolRegistrationAsOwner:
		return msg.SigningPoolRegistrationAsOwner, nil
	case hw.SigningPoolRegistrationAsOperator:
		return 0, ErrPoolRegistrationAsOperator
	case hw.SigningMultisig:
		return msg.SigningMultisig, nil
	case hw.SigningPlutus:
		return msg.SigningPlutus, nil
	}
	return 0, hw.ErrUnreachable
}

func comparePaths(a, b cardano.Path) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return len(a) - len(b)
}

// witnessPaths gathers the keys to sign with: the signing files, plus keys
// the device recognises in certificates, withdrawals and required signers.
// They are unique and sorted, as Trezor's libraries send them.
func (b *txBuilder) witnessPaths(certs []item, withdrawals []*msg.CardanoTxWithdrawal, signers []*msg.CardanoTxRequiredSigner) []cardano.Path {
	set := map[string]cardano.Path{}
	add := func(p []uint32) {
		if len(p) > 0 {
			set[cardano.Path(p).String()] = cardano.Path(p)
		}
	}
	if b.params.Mode != hw.SigningMultisig {
		for _, it := range certs {
			switch m := it.msg.(type) {
			case *msg.CardanoTxCertificate:
				switch m.Type {
				case msg.CertStakeDeregistration, msg.CertStakeDelegation, msg.CertStakeRegistrationConway,
					msg.CertStakeDeregistrationConway, msg.CertVoteDelegation:
					add(m.Path)
				}
			case *msg.CardanoPoolOwner:
				add(m.StakingKeyPath)
			}
		}
		for _, w := range withdrawals {
			add(w.Path)
		}
	}
	for _, s := range signers {
		add(s.KeyPath)
	}
	for _, f := range b.params.SigningFiles {
		add(f.Path)
	}
	paths := make([]cardano.Path, 0, len(set))
	for _, p := range set {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return comparePaths(paths[i], paths[j]) < 0 })
	return paths
}

// signTx streams a transaction to the Trezor and returns its witnesses, the
// body hash it computed and its auxiliary data supplement.
func (p *Provider) signTx(b *txBuilder, aux *msg.CardanoTxAuxiliaryData) ([]msg.CardanoTxWitnessResponse, []byte, *msg.CardanoTxAuxiliaryDataSupplement, error) {
	body := &b.params.Tx.Body
	switch {
	case body.HasVotingProcedures:
		return nil, nil, nil, ErrVotingProcedures
	case body.Treasury != nil:
		return nil, nil, nil, ErrTreasury
	case body.Donation != nil:
		return nil, nil, nil, ErrDonation
	}
	mode, err := signingMode(b.params.Mode)
	if err != nil {
		return nil, nil, nil, err
	}

	var inputs []item
	for _, in := range body.Inputs.Items {
		if !fits32(in.Index) {
			return nil, nil, nil, hw.ErrInvalidInput
		}
		inputs = append(inputs, item{msg.TypeCardanoTxInput, &msg.CardanoTxInput{PrevHash: in.TxID, PrevIndex: uint32(in.Index.Uint64())}})
	}
	var outputs []item
	for _, o := range body.Outputs {
		its, err := b.outputItems(o)
		if err != nil {
			return nil, nil, nil, err
		}
		outputs = append(outputs, its...)
	}
	var certs []item
	nCerts := 0
	if body.Certificates != nil {
		for _, c := range body.Certificates.Items {
			its, err := b.certificateItems(c)
			if err != nil {
				return nil, nil, nil, err
			}
			certs = append(certs, its...)
			nCerts++
		}
	}
	var withdrawals []*msg.CardanoTxWithdrawal
	for _, w := range body.Withdrawals {
		cr, err := hw.RewardAccountCredential(w.RewardAccount)
		if err != nil {
			return nil, nil, nil, err
		}
		wm := &msg.CardanoTxWithdrawal{Amount: w.Amount.Uint64()}
		if wm.Path, wm.KeyHash, wm.ScriptHash, err = b.credential(cr); err != nil {
			return nil, nil, nil, err
		}
		withdrawals = append(withdrawals, wm)
	}
	if body.AuxiliaryDataHash != nil && aux == nil {
		aux = &msg.CardanoTxAuxiliaryData{Hash: body.AuxiliaryDataHash}
	}
	var mint []item
	if body.HasMint {
		mint = append([]item{{msg.TypeCardanoTxMint, &msg.CardanoTxMint{AssetGroupsCount: uint32(len(body.Mint))}}}, b.tokenItems(body.Mint, true)...)
	}
	var collateral []item
	if body.CollateralInputs != nil {
		for _, in := range body.CollateralInputs.Items {
			if !fits32(in.Index) {
				return nil, nil, nil, hw.ErrInvalidCollateralInput
			}
			collateral = append(collateral, item{msg.TypeCardanoTxCollateralInput, &msg.CardanoTxCollateralInput{PrevHash: in.TxID, PrevIndex: uint32(in.Index.Uint64())}})
		}
	}
	var signers []*msg.CardanoTxRequiredSigner
	if body.RequiredSigners != nil {
		for _, h := range body.RequiredSigners.Items {
			if pa := hw.PathForKeyHash(h, b.params.SigningFiles); pa != nil {
				signers = append(signers, &msg.CardanoTxRequiredSigner{KeyPath: path(pa)})
			} else {
				signers = append(signers, &msg.CardanoTxRequiredSigner{KeyHash: h})
			}
		}
	}
	var collateralReturn []item
	if body.CollateralReturn != nil {
		if collateralReturn, err = b.outputItems(*body.CollateralReturn); err != nil {
			return nil, nil, nil, err
		}
	}
	var refs []item
	if body.ReferenceInputs != nil {
		for _, in := range body.ReferenceInputs.Items {
			if !fits32(in.Index) {
				return nil, nil, nil, hw.ErrInvalidInput
			}
			refs = append(refs, item{msg.TypeCardanoTxReferenceInput, &msg.CardanoTxReferenceInput{PrevHash: in.TxID, PrevIndex: uint32(in.Index.Uint64())}})
		}
	}
	witnessPaths := b.witnessPaths(certs, withdrawals, signers)

	init := &msg.CardanoSignTxInit{
		SigningMode:             mode,
		ProtocolMagic:           b.params.Network.ProtocolMagic,
		NetworkID:               b.params.Network.NetworkID,
		InputsCount:             uint32(len(body.Inputs.Items)),
		OutputsCount:            uint32(len(body.Outputs)),
		Fee:                     body.Fee.Uint64(),
		TTL:                     optU64(body.TTL),
		CertificatesCount:       uint32(nCerts),
		WithdrawalsCount:        uint32(len(withdrawals)),
		HasAuxiliaryData:        aux != nil,
		ValidityIntervalStart:   optU64(body.ValidityIntervalStart),
		WitnessRequestsCount:    uint32(len(witnessPaths)),
		MintingAssetGroupsCount: uint32(len(body.Mint)),
		DerivationType:          derivation(b.params.DerivationType),
		IncludeNetworkID:        boolPtr(body.NetworkID != nil),
		ScriptDataHash:          body.ScriptDataHash,
		CollateralInputsCount:   uint32(len(collateral)),
		RequiredSignersCount:    uint32(len(signers)),
		HasCollateralReturn:     boolPtr(body.CollateralReturn != nil),
		TotalCollateral:         optU64(body.TotalCollateral),
		ReferenceInputsCount:    u32(uint32(len(refs))),
		TagCborSets:             boolPtr(body.Inputs.HasTag),
	}
	send := func(its []item) error {
		for _, it := range its {
			if err := p.c.Call(it.t, it.msg, msg.TypeCardanoTxItemAck, &msg.CardanoTxItemAck{}); err != nil {
				return err
			}
		}
		return nil
	}
	if err := send([]item{{msg.TypeCardanoSignTxInit, init}}); err != nil {
		return nil, nil, nil, err
	}
	for _, group := range [][]item{inputs, outputs, certs} {
		if err := send(group); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, w := range withdrawals {
		if err := send([]item{{msg.TypeCardanoTxWithdrawal, w}}); err != nil {
			return nil, nil, nil, err
		}
	}
	var supplement *msg.CardanoTxAuxiliaryDataSupplement
	if aux != nil {
		var s msg.CardanoTxAuxiliaryDataSupplement
		if err := p.c.Call(msg.TypeCardanoTxAuxiliaryData, aux, msg.TypeCardanoTxAuxiliaryDataSupplement, &s); err != nil {
			return nil, nil, nil, err
		}
		supplement = &s
		if err := send([]item{{msg.TypeCardanoTxHostAck, &msg.CardanoTxHostAck{}}}); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, group := range [][]item{mint, collateral} {
		if err := send(group); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, s := range signers {
		if err := send([]item{{msg.TypeCardanoTxRequiredSigner, s}}); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, group := range [][]item{collateralReturn, refs} {
		if err := send(group); err != nil {
			return nil, nil, nil, err
		}
	}
	var witnesses []msg.CardanoTxWitnessResponse
	for _, wp := range witnessPaths {
		var w msg.CardanoTxWitnessResponse
		if err := p.c.Call(msg.TypeCardanoTxWitnessRequest, &msg.CardanoTxWitnessRequest{Path: path(wp)}, msg.TypeCardanoTxWitnessResponse, &w); err != nil {
			return nil, nil, nil, err
		}
		witnesses = append(witnesses, w)
	}
	var h msg.CardanoTxBodyHash
	if err := p.c.Call(msg.TypeCardanoTxHostAck, &msg.CardanoTxHostAck{}, msg.TypeCardanoTxBodyHash, &h); err != nil {
		return nil, nil, nil, err
	}
	if err := p.c.Call(msg.TypeCardanoTxHostAck, &msg.CardanoTxHostAck{}, msg.TypeCardanoSignTxFinished, &msg.CardanoSignTxFinished{}); err != nil {
		return nil, nil, nil, err
	}
	return witnesses, h.TxHash, supplement, nil
}

func (p *Provider) WitnessTx(params hw.TxSigningParams, change []cardano.SigningFile) ([]hw.Witness, error) {
	b := &txBuilder{params: params, change: change}
	responses, hash, _, err := p.signTx(b, nil)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(hash, params.BodyHash) {
		return nil, hw.ErrTxSerializationMismatch
	}
	var out []hw.Witness
	for _, w := range responses {
		f := hw.FileForKey(w.PubKey, params.SigningFiles)
		if f == nil {
			return nil, hw.ErrMissingHwSigningDataAtXPub
		}
		if err := hw.VerifyWitness(params.BodyHash, *f, w.Signature); err != nil {
			return nil, err
		}
		chain := w.ChainCode
		if chain == nil {
			_, chain, _ = f.XPub()
		}
		out = append(out, hw.Witness{
			Path: f.Path, Byron: w.Type == msg.WitnessByron,
			PubKey: w.PubKey, Signature: w.Signature, ChainCode: chain,
		})
	}
	return out, nil
}

func (p *Provider) SignOperationalCertificate([]byte, uint64, hw.OpCertCounter, []cardano.SigningFile) ([]byte, error) {
	return nil, ErrUnsupportedCall
}

func (p *Provider) SignCIP36Registration(r hw.CIP36Params) ([]byte, error) {
	addr, err := cardano.DecodeAddress(r.PaymentAddress)
	if err != nil {
		return nil, err
	}
	params := &msg.CardanoCVoteRegistrationParameters{
		StakingPath:   path(r.StakeSigningFile.Path),
		Nonce:         r.Nonce,
		Format:        u32(msg.CVoteFormatCIP36),
		VotingPurpose: u64(r.VotingPurpose),
	}
	for _, d := range r.Delegations {
		if d.Weight > math.MaxUint32 {
			return nil, hw.ErrInvalidCVoteWeight
		}
		params.Delegations = append(params.Delegations, msg.CardanoCVoteRegistrationDelegation{VotePublicKey: d.VotePublicKey, Weight: uint32(d.Weight)})
	}
	if ap := hw.AddressParamsFor(r.PaymentSigningFiles, addr, r.Network); ap != nil {
		if err := hw.CheckCIP36AddressType(ap.Type); err != nil {
			return nil, err
		}
		params.PaymentAddressParameters = addressParams(ap)
	} else {
		params.PaymentAddress = str(r.PaymentAddress)
	}

	// The Trezor signs the registration inside a transaction: a dummy one,
	// which is never submitted.
	d := &dummyTx{p: p, network: r.Network, dt: r.DerivationType}
	supplement, err := d.sign(&msg.CardanoTxAuxiliaryData{CVoteRegistrationParameters: params})
	if err != nil {
		return nil, err
	}
	if supplement == nil {
		return nil, ErrMissingAuxDataSupplement
	}
	if supplement.CVoteRegistrationSignature == nil {
		return nil, ErrMissingCIP36Signature
	}
	return hw.EncodeCIP36Registration(r, addr, supplement.AuxiliaryDataHash, supplement.CVoteRegistrationSignature)
}

// dummyTx is the transaction the Trezor needs around a CIP-36 registration:
// one input and one output to the wallet, with no fee.
type dummyTx struct {
	p       *Provider
	network cardano.Network
	dt      hw.DerivationType
}

func (d *dummyTx) sign(aux *msg.CardanoTxAuxiliaryData) (*msg.CardanoTxAuxiliaryDataSupplement, error) {
	c := d.p.c
	init := &msg.CardanoSignTxInit{
		SigningMode: msg.SigningOrdinary, ProtocolMagic: d.network.ProtocolMagic, NetworkID: d.network.NetworkID,
		InputsCount: 1, OutputsCount: 1, Fee: 0, TTL: u64(0), HasAuxiliaryData: true,
		WitnessRequestsCount: 0, DerivationType: derivation(d.dt),
	}
	h := uint32(cardano.Hardened)
	steps := []item{
		{msg.TypeCardanoSignTxInit, init},
		{msg.TypeCardanoTxInput, &msg.CardanoTxInput{PrevHash: make([]byte, 32), PrevIndex: 0}},
		{msg.TypeCardanoTxOutput, &msg.CardanoTxOutput{
			AddressParameters: &msg.CardanoAddressParameters{
				AddressType:     msg.AddressBase,
				AddressN:        []uint32{1852 + h, 1815 + h, h, 0, 0},
				AddressNStaking: []uint32{1852 + h, 1815 + h, h, 2, 0},
			},
			Amount: 1,
		}},
	}
	for _, s := range steps {
		if err := c.Call(s.t, s.msg, msg.TypeCardanoTxItemAck, &msg.CardanoTxItemAck{}); err != nil {
			return nil, err
		}
	}
	var s msg.CardanoTxAuxiliaryDataSupplement
	if err := c.Call(msg.TypeCardanoTxAuxiliaryData, aux, msg.TypeCardanoTxAuxiliaryDataSupplement, &s); err != nil {
		return nil, err
	}
	if err := c.Call(msg.TypeCardanoTxHostAck, &msg.CardanoTxHostAck{}, msg.TypeCardanoTxItemAck, &msg.CardanoTxItemAck{}); err != nil {
		return nil, err
	}
	var hash msg.CardanoTxBodyHash
	if err := c.Call(msg.TypeCardanoTxHostAck, &msg.CardanoTxHostAck{}, msg.TypeCardanoTxBodyHash, &hash); err != nil {
		return nil, err
	}
	if err := c.Call(msg.TypeCardanoTxHostAck, &msg.CardanoTxHostAck{}, msg.TypeCardanoSignTxFinished, &msg.CardanoSignTxFinished{}); err != nil {
		return nil, err
	}
	if s.Type == msg.AuxSupplementNone {
		return nil, nil
	}
	return &s, nil
}

func (p *Provider) SignMessage(m hw.SignMessageParams) (hw.SignedMessage, error) {
	if m.HashPayload {
		return hw.SignedMessage{}, ErrHashPayloadUnsupported
	}
	init := &msg.CardanoSignMessageInit{
		SigningPath:      path(m.SigningFile.Path),
		PayloadSize:      uint32(len(m.Message)),
		PreferHexDisplay: m.PreferHexDisplay,
		DerivationType:   derivation(m.DerivationType),
	}
	var addr []byte
	if m.Address != "" {
		ap, network, err := hw.MessageAddressParams(m)
		if err != nil {
			return hw.SignedMessage{}, err
		}
		addr = ap.Address
		params := &msg.CardanoAddressParameters{AddressType: uint32(ap.Type), AddressN: path(ap.PaymentPath), AddressNStaking: path(ap.StakePath)}
		if ap.Type == cardano.AddrBasePaymentKeyStakeScript {
			params.ScriptStakingHash = ap.Address[1+cardano.KeyHashLength:]
		}
		init.AddressParameters = params
		init.NetworkID = u32(network.NetworkID)
		init.ProtocolMagic = u32(network.ProtocolMagic)
	}
	t, d, err := p.c.CallRaw(msg.TypeCardanoSignMessageInit, init)
	for err == nil && t == msg.TypeCardanoMessageDataRequest {
		var req msg.CardanoMessageDataRequest
		if err := pb.Unmarshal(d, &req); err != nil {
			return hw.SignedMessage{}, err
		}
		end := uint64(req.Offset) + uint64(req.Length)
		if end > uint64(len(m.Message)) {
			return hw.SignedMessage{}, errors.New("trezor: the device asked for data beyond the message")
		}
		t, d, err = p.c.CallRaw(msg.TypeCardanoMessageDataResponse, &msg.CardanoMessageDataResponse{Data: m.Message[req.Offset:end]})
	}
	if err != nil {
		return hw.SignedMessage{}, err
	}
	if t != msg.TypeCardanoMessageSignature {
		return hw.SignedMessage{}, fmt.Errorf("trezor: unexpected message type %d", t)
	}
	var sig msg.CardanoMessageSignature
	if err := pb.Unmarshal(d, &sig); err != nil {
		return hw.SignedMessage{}, err
	}
	if addr != nil && !bytes.Equal(addr, sig.Address) {
		return hw.SignedMessage{}, hw.ErrMessageAddressMismatch
	}
	if !bytes.Equal(m.SigningFile.PubKey(), sig.PubKey) {
		return hw.SignedMessage{}, hw.ErrSigningPubKeyMismatch
	}
	return hw.SignedMessage{Signature: sig.Signature, PubKey: sig.PubKey, Address: sig.Address}, nil
}

func nativeScript(s cardano.NativeScript, files []cardano.SigningFile) msg.CardanoNativeScript {
	n := msg.CardanoNativeScript{Type: uint32(s.Type)}
	switch s.Type {
	case cardano.ScriptPubKey:
		if pa := hw.PathForKeyHash(s.KeyHash, files); pa != nil {
			n.KeyPath = path(pa)
		} else {
			n.KeyHash = s.KeyHash
		}
	case cardano.ScriptAll, cardano.ScriptAny, cardano.ScriptNOfK:
		for _, sub := range s.Scripts {
			n.Scripts = append(n.Scripts, nativeScript(sub, files))
		}
		if s.Type == cardano.ScriptNOfK {
			n.RequiredSignaturesCount = u32(uint32(s.Required))
		}
	case cardano.ScriptInvalidBefore:
		n.InvalidBefore = u64(s.Slot)
	case cardano.ScriptInvalidHereafter:
		n.InvalidHereafter = u64(s.Slot)
	}
	return n
}

func (p *Provider) NativeScriptHash(s cardano.NativeScript, files []cardano.SigningFile, display hw.NativeScriptDisplay, dt hw.DerivationType) ([]byte, error) {
	format := uint32(msg.NativeScriptHashPolicyID)
	if display == hw.DisplayBech32 {
		format = msg.NativeScriptHashBech32
	}
	var r msg.CardanoNativeScriptHash
	if err := p.c.Call(msg.TypeCardanoGetNativeScriptHash, &msg.CardanoGetNativeScriptHash{
		Script: nativeScript(s, files), DisplayFormat: format, DerivationType: derivation(dt),
	}, msg.TypeCardanoNativeScriptHash, &r); err != nil {
		return nil, err
	}
	return r.ScriptHash, nil
}
