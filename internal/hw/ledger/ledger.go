// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package ledger is the hardware wallet provider for Ledger. It maps
// cardano-hw-cli's operations onto the Cardano app's requests, as
// cardano-hw-cli's Ledger crypto provider does, and checks what the device
// returns.
package ledger

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
	"github.com/Liet-ada/cardano-hw-go/internal/hw"
	"github.com/Liet-ada/cardano-hw-go/internal/ledger"
	"github.com/Liet-ada/cardano-hw-go/internal/tx"
)

// Errors with cardano-hw-cli's wording.
var (
	ErrInvalidAddressParameters = errors.New("Invalid address parameters provided")
	ErrInvalidTransactionType   = errors.New("Invalid transaction type")
	ErrMissingAuxDataSupplement = errors.New("Missing auxiliary data supplement in response.")
)

// failed is cardano-hw-cli's wrapping of what fails while talking to the
// Ledger.
type failed struct{ err error }

func (f *failed) Error() string {
	return "The requested operation failed. Check that your Ledger device is connected, unlocked and with Cardano app running.\nDetails: " + jsString(f.err)
}

func (f *failed) Unwrap() error { return f.err }

func fail(err error) error { return &failed{err} }

// jsString writes an error as JavaScript does: ledgerjs's errors with their
// own names, others as "Error".
func jsString(err error) string {
	var le *ledger.Error
	if errors.As(err, &le) && le == err {
		return le.Error()
	}
	return "Error: " + err.Error()
}

// Provider is a Ledger with the Cardano app open.
type Provider struct {
	app *ledger.App
}

// New wraps the Cardano app of a Ledger.
func New(app *ledger.App) *Provider { return &Provider{app: app} }

// Close does nothing: the transport is closed by whoever opened it.
func (p *Provider) Close() error { return nil }

func (p *Provider) Version() (string, error) {
	v, err := p.app.GetVersion()
	if err != nil {
		return "", fail(err)
	}
	return fmt.Sprintf("Ledger app version %d.%d.%d", v.Major, v.Minor, v.Patch), nil
}

func (p *Provider) SupportsUnrestricted() (bool, error) {
	v, err := p.app.GetVersion()
	if err != nil {
		return false, fail(err)
	}
	return v.SupportsUnrestricted(), nil
}

// deviceOwnedAddress builds the parameters of an address to show, from
// paths or script hashes: a path is preferred when both are given.
func deviceOwnedAddress(t cardano.AddressType, paymentPath cardano.Path, paymentScript []byte, stakingPath cardano.Path, stakingScript []byte) (ledger.AddressParams, error) {
	a := ledger.AddressParams{Type: t}
	spending := func() error {
		switch {
		case paymentPath != nil:
			a.SpendingPath = paymentPath
		case paymentScript != nil:
			a.SpendingScriptHash = paymentScript
		default:
			return ErrInvalidAddressParameters
		}
		return nil
	}
	staking := func() error {
		switch {
		case stakingPath != nil:
			a.Staking, a.StakingPath = ledger.StakingKeyPath, stakingPath
		case stakingScript != nil:
			a.Staking, a.StakingHash = ledger.StakingScriptHash, stakingScript
		default:
			return ErrInvalidAddressParameters
		}
		return nil
	}
	switch t {
	case cardano.AddrBasePaymentKeyStakeKey, cardano.AddrBasePaymentScriptStakeKey,
		cardano.AddrBasePaymentKeyStakeScript, cardano.AddrBasePaymentScriptStakeScript:
		if err := spending(); err != nil {
			return a, err
		}
		return a, staking()
	case cardano.AddrEnterpriseKey, cardano.AddrEnterpriseScript:
		return a, spending()
	case cardano.AddrRewardKey, cardano.AddrRewardScript:
		return a, staking()
	}
	return a, ErrInvalidAddressParameters
}

func (p *Provider) ShowAddress(s hw.ShowAddressParams) error {
	attrs, err := cardano.Attributes(s.Address)
	if err != nil {
		return err
	}
	a, err := deviceOwnedAddress(attrs.Type, s.PaymentPath, s.PaymentScriptHash, s.StakingPath, s.StakingScriptHash)
	if err != nil {
		return err
	}
	a.NetworkID, a.ProtocolMagic = uint8(attrs.NetworkID), attrs.ProtocolMagic
	if err := p.app.ShowAddress(a); err != nil {
		return fail(err)
	}
	return nil
}

func (p *Provider) XPubKeys(paths []cardano.Path, _ hw.DerivationType) ([][]byte, error) {
	xpubs, err := p.app.ExtendedPublicKeys(paths)
	if err != nil {
		return nil, fail(err)
	}
	return xpubs, nil
}

// builder turns a transaction into a Ledger request.
type builder struct {
	params hw.TxSigningParams
	change []cardano.SigningFile
}

const maxSafeInteger = 1<<53 - 1

func safe(n *big.Int) bool { return n.IsUint64() && n.Uint64() <= maxSafeInteger }

// input converts an input; the payment keys come as additional witnesses.
func input(in tx.Input, err error) (ledger.Input, error) {
	if !safe(in.Index) {
		return ledger.Input{}, err
	}
	if in.Index.Uint64() > math.MaxUint32 {
		return ledger.Input{}, ledger.InvalidData("invalid input utxo index")
	}
	return ledger.Input{TxHash: in.TxID, Index: uint32(in.Index.Uint64())}, nil
}

func tokens(m tx.Multiasset) []ledger.AssetGroup {
	out := make([]ledger.AssetGroup, 0, len(m))
	for _, g := range m {
		lg := ledger.AssetGroup{PolicyID: g.PolicyID}
		for _, t := range g.Tokens {
			tok := ledger.Token{AssetName: t.AssetName}
			if t.Amount.Sign() < 0 || !t.Amount.IsUint64() {
				tok.Mint = t.Amount.Int64()
			} else {
				tok.Amount = t.Amount.Uint64()
				tok.Mint = int64(t.Amount.Uint64())
			}
			lg.Tokens = append(lg.Tokens, tok)
		}
		out = append(out, lg)
	}
	return out
}

func (b *builder) output(o tx.Output) (ledger.Output, error) {
	out := ledger.Output{Format: uint8(o.Format), Amount: o.Amount.Coin.Uint64()}
	ap := hw.AddressParamsFor(b.change, o.Address, b.params.Network)
	if ap != nil && hw.AddressParamsAllowed(b.params.Mode) {
		if ap.PaymentPath == nil {
			return out, hw.ErrUnreachable
		}
		params := ledger.AddressParams{
			Type: ap.Type, NetworkID: uint8(b.params.Network.NetworkID), ProtocolMagic: b.params.Network.ProtocolMagic,
			SpendingPath: ap.PaymentPath,
		}
		if ap.StakePath != nil {
			params.Staking, params.StakingPath = ledger.StakingKeyPath, ap.StakePath
		}
		out.Destination = ledger.Destination{DeviceOwned: true, Params: params}
	} else {
		out.Destination = ledger.Destination{Address: o.Address}
	}
	if o.Amount.HasMultiasset {
		out.Tokens = tokens(o.Amount.Multiasset)
	}
	switch {
	case o.Format == tx.FormatArrayLegacy && o.DatumHash != nil:
		out.HasDatum, out.Datum = true, o.DatumHash
	case o.Format == tx.FormatMapBabbage && o.Datum != nil && o.Datum.Type == tx.DatumHash:
		out.HasDatum, out.Datum = true, o.Datum.Hash
	case o.Format == tx.FormatMapBabbage && o.Datum != nil:
		out.HasDatum, out.DatumInline, out.Datum = true, true, o.Datum.Bytes
	}
	if o.Format == tx.FormatMapBabbage && o.HasReferenceScript && len(o.ReferenceScript) > 0 {
		out.HasRefScript, out.RefScript = true, o.ReferenceScript
	}
	return out, nil
}

// credential gives a key hash as a path when a signing file has the key,
// so the person stays in control; otherwise as a hash where the signing
// mode allows it.
func (b *builder) credential(c tx.Credential, keyHashInOrdinary bool) (ledger.Credential, error) {
	if c.Type == tx.CredentialScriptHash {
		return ledger.Credential{Kind: ledger.CredScriptHash, Hash: c.Hash}, nil
	}
	if p := hw.PathForKeyHash(c.Hash, b.params.SigningFiles); p != nil {
		return ledger.Credential{Kind: ledger.CredKeyPath, Path: p}, nil
	}
	m := b.params.Mode
	if m == hw.SigningPlutus || m == hw.SigningUnrestricted ||
		(keyHashInOrdinary && (m == hw.SigningOrdinary || m == hw.SigningMultisig)) {
		return ledger.Credential{Kind: ledger.CredKeyHash, Hash: c.Hash}, nil
	}
	return ledger.Credential{}, hw.ErrMissingSigningFileForCertificate
}

func (b *builder) drep(d tx.DRep) ledger.DRep {
	switch d.Type {
	case tx.DRepKeyHash:
		if p := hw.PathForKeyHash(d.Hash, b.params.SigningFiles); p != nil {
			return ledger.DRep{Type: ledger.DRepKeyPath, Path: p}
		}
		return ledger.DRep{Type: ledger.DRepKeyHash, Hash: d.Hash}
	case tx.DRepScriptHash:
		return ledger.DRep{Type: ledger.DRepScriptHash, Hash: d.Hash}
	case tx.DRepAbstain:
		return ledger.DRep{Type: ledger.DRepAbstain}
	}
	return ledger.DRep{Type: ledger.DRepNoConfidence}
}

func anchor(a *tx.Anchor) *ledger.Anchor {
	if a == nil {
		return nil
	}
	return &ledger.Anchor{URL: a.URL, Hash: a.DataHash}
}

// swapIPv6 reverses each 32-bit word, as cardano-hw-cli writes the address
// for the device, which serializes it back the same way.
func swapIPv6(b []byte) []byte {
	out := make([]byte, len(b))
	for i := 0; i+4 <= len(b); i += 4 {
		out[i], out[i+1], out[i+2], out[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return out
}

func (b *builder) poolRegistration(c tx.Certificate) (*ledger.PoolParams, error) {
	pp := c.PoolParams
	files := b.params.SigningFiles
	out := &ledger.PoolParams{
		VRFKeyHash: pp.VRFKeyHash, Pledge: pp.Pledge.Uint64(), Cost: pp.Cost.Uint64(),
		MarginNumerator: pp.Margin[0].Uint64(), MarginDenominator: pp.Margin[1].Uint64(),
	}
	switch b.params.Mode {
	case hw.SigningPoolRegistrationAsOperator:
		out.PoolKeyPath = hw.PathForKeyHash(pp.Operator, files)
		if out.PoolKeyPath == nil {
			return nil, ledger.InvalidData("invalid pool key path in a pool registration certificate")
		}
	case hw.SigningPoolRegistrationAsOwner:
		out.PoolKeyHash = pp.Operator
	default:
		return nil, ErrInvalidTransactionType
	}
	if ap := hw.AddressParamsFor(files, pp.RewardAccount, b.params.Network); ap != nil {
		out.RewardPath = ap.StakePath
		if out.RewardPath == nil {
			return nil, ledger.InvalidData("invalid pool reward account key path in a pool registration certificate")
		}
	} else {
		out.RewardAccount = pp.RewardAccount
	}
	withPath := 0
	for _, o := range pp.Owners.Items {
		if p := hw.PathForKeyHash(o, files); p != nil && b.params.Mode == hw.SigningPoolRegistrationAsOwner {
			out.Owners = append(out.Owners, ledger.Credential{Kind: ledger.CredKeyPath, Path: p})
			withPath++
		} else {
			out.Owners = append(out.Owners, ledger.Credential{Kind: ledger.CredKeyHash, Hash: o})
		}
	}
	if withPath == 0 && b.params.Mode == hw.SigningPoolRegistrationAsOwner {
		return nil, hw.ErrMissingSigningFileForCertificate
	}
	if withPath > 1 {
		return nil, hw.ErrOwnerMultipleTimes
	}
	for _, r := range pp.Relays {
		lr := ledger.Relay{Type: uint8(r.Type)}
		// cardano-hw-cli leaves out a port of 0
		if r.Port != nil && *r.Port != 0 && r.Type != tx.RelayMultiHostName {
			port := uint16(*r.Port)
			lr.Port = &port
		}
		switch r.Type {
		case tx.RelaySingleHostAddress:
			lr.IPv4 = r.IPv4
			if r.IPv6 != nil {
				lr.IPv6 = swapIPv6(r.IPv6)
			}
		default:
			lr.DNSName = r.DNSName
		}
		out.Relays = append(out.Relays, lr)
	}
	if pp.Metadata != nil {
		out.MetadataURL, out.MetadataHash = pp.Metadata.URL, pp.Metadata.Hash
	}
	return out, nil
}

func (b *builder) certificate(c tx.Certificate) (ledger.Certificate, error) {
	lc := ledger.Certificate{Type: uint8(c.Type)}
	var err error
	switch c.Type {
	case tx.CertStakeRegistration, tx.CertStakeDeregistration:
		lc.StakeCredential, err = b.credential(c.StakeCredential, false)
	case tx.CertStakeRegistrationConway, tx.CertStakeDeregistrationConway:
		lc.StakeCredential, err = b.credential(c.StakeCredential, false)
		lc.Deposit = c.Deposit.Uint64()
	case tx.CertStakeDelegation:
		lc.PoolKeyHash = c.PoolKeyHash
		lc.StakeCredential, err = b.credential(c.StakeCredential, false)
	case tx.CertVoteDelegation:
		if lc.StakeCredential, err = b.credential(c.StakeCredential, false); err == nil {
			lc.DRep = b.drep(c.DRep)
		}
	case tx.CertAuthorizeCommitteeHot:
		if lc.ColdCredential, err = b.credential(c.ColdCredential, false); err == nil {
			lc.HotCredential, err = b.credential(c.HotCredential, true)
		}
	case tx.CertResignCommitteeCold:
		lc.ColdCredential, err = b.credential(c.ColdCredential, false)
		lc.Anchor = anchor(c.Anchor)
	case tx.CertDRepRegistration:
		lc.DRepCredential, err = b.credential(c.DRepCredential, false)
		lc.Deposit, lc.Anchor = c.Deposit.Uint64(), anchor(c.Anchor)
	case tx.CertDRepDeregistration:
		lc.DRepCredential, err = b.credential(c.DRepCredential, false)
		lc.Deposit = c.Deposit.Uint64()
	case tx.CertDRepUpdate:
		lc.DRepCredential, err = b.credential(c.DRepCredential, false)
		lc.Anchor = anchor(c.Anchor)
	case tx.CertPoolRegistration:
		lc.Pool, err = b.poolRegistration(c)
	case tx.CertPoolRetirement:
		lc.RetirementPath = hw.PathForKeyHash(c.PoolKeyHash, b.params.SigningFiles)
		if lc.RetirementPath == nil {
			return lc, hw.ErrMissingSigningFileForCertificate
		}
		lc.RetirementEpoch = c.Epoch.Uint64()
	case tx.CertStakeAndVoteDelegation, tx.CertStakeRegistrationAndDelegation,
		tx.CertStakeRegistrationWithVoteDelegation, tx.CertStakeRegistrationWithStakeAndVoteDeleg:
		return lc, hw.ErrUnsupportedCertificateType
	default:
		return lc, hw.ErrUnknownCertificate
	}
	return lc, err
}

func (b *builder) voter(v tx.Voter) ledger.Voter {
	p := hw.PathForKeyHash(v.Hash, b.params.SigningFiles)
	switch v.Type {
	case tx.VoterDRepKey:
		if p != nil {
			return ledger.Voter{Type: ledger.VoterDRepKeyPath, Path: p}
		}
		return ledger.Voter{Type: ledger.VoterDRepKeyHash, Hash: v.Hash}
	case tx.VoterDRepScript:
		return ledger.Voter{Type: ledger.VoterDRepScriptHash, Hash: v.Hash}
	case tx.VoterCommitteeKey:
		if p != nil {
			return ledger.Voter{Type: ledger.VoterCommitteeKeyPath, Path: p}
		}
		return ledger.Voter{Type: ledger.VoterCommitteeKeyHash, Hash: v.Hash}
	case tx.VoterCommitteeScript:
		return ledger.Voter{Type: ledger.VoterCommitteeScriptHash, Hash: v.Hash}
	}
	if p != nil {
		return ledger.Voter{Type: ledger.VoterStakePoolKeyPath, Path: p}
	}
	return ledger.Voter{Type: ledger.VoterStakePoolKeyHash, Hash: v.Hash}
}

func signingMode(m hw.SigningMode) (uint8, error) {
	switch m {
	case hw.SigningOrdinary:
		return ledger.ModeOrdinary, nil
	case hw.SigningPoolRegistrationAsOwner:
		return ledger.ModePoolRegistrationOwner, nil
	case hw.SigningPoolRegistrationAsOperator:
		return ledger.ModePoolRegistrationOperator, nil
	case hw.SigningMultisig:
		return ledger.ModeMultisig, nil
	case hw.SigningPlutus:
		return ledger.ModePlutus, nil
	case hw.SigningUnrestricted:
		return ledger.ModeUnrestricted, nil
	}
	return 0, hw.ErrUnreachable
}

func u64ptr(n *big.Int) *uint64 {
	if n == nil {
		return nil
	}
	v := n.Uint64()
	return &v
}

// request builds the request, in the order cardano-hw-cli prepares each
// part, so the first problem found is the same.
func (b *builder) request() (*ledger.SignRequest, error) {
	body := &b.params.Tx.Body
	t := ledger.Tx{
		NetworkID:     uint8(b.params.Network.NetworkID),
		ProtocolMagic: b.params.Network.ProtocolMagic,
	}
	for _, in := range body.Inputs.Items {
		li, err := input(in, hw.ErrInvalidInput)
		if err != nil {
			return nil, err
		}
		t.Inputs = append(t.Inputs, li)
	}
	for _, o := range body.Outputs {
		lo, err := b.output(o)
		if err != nil {
			return nil, err
		}
		t.Outputs = append(t.Outputs, lo)
	}
	t.Fee = body.Fee.Uint64()
	t.TTL = u64ptr(body.TTL)
	if body.Certificates != nil {
		for _, c := range body.Certificates.Items {
			lc, err := b.certificate(c)
			if err != nil {
				return nil, err
			}
			t.Certificates = append(t.Certificates, lc)
		}
	}
	for _, w := range body.Withdrawals {
		cr, err := hw.RewardAccountCredential(w.RewardAccount)
		if err != nil {
			return nil, err
		}
		lcr, err := b.credential(cr, false)
		if err != nil {
			return nil, err
		}
		t.Withdrawals = append(t.Withdrawals, ledger.Withdrawal{Amount: w.Amount.Uint64(), Credential: lcr})
	}
	t.AuxDataHash = body.AuxiliaryDataHash
	t.ValidityStart = u64ptr(body.ValidityIntervalStart)
	if body.HasMint {
		t.HasMint, t.Mint = true, tokens(body.Mint)
	}
	t.ScriptDataHash = body.ScriptDataHash
	if body.CollateralInputs != nil {
		for _, in := range body.CollateralInputs.Items {
			li, err := input(in, hw.ErrInvalidCollateralInput)
			if err != nil {
				return nil, err
			}
			t.Collateral = append(t.Collateral, li)
		}
	}
	if body.RequiredSigners != nil {
		for _, h := range body.RequiredSigners.Items {
			if p := hw.PathForKeyHash(h, b.params.SigningFiles); p != nil {
				t.RequiredSigners = append(t.RequiredSigners, ledger.RequiredSigner{Path: p})
			} else {
				t.RequiredSigners = append(t.RequiredSigners, ledger.RequiredSigner{Hash: h})
			}
		}
	}
	t.IncludeNetworkID = body.NetworkID != nil
	if body.CollateralReturn != nil {
		lo, err := b.output(*body.CollateralReturn)
		if err != nil {
			return nil, err
		}
		t.CollateralOutput = &lo
	}
	t.TotalCollateral = u64ptr(body.TotalCollateral)
	if body.ReferenceInputs != nil {
		for _, in := range body.ReferenceInputs.Items {
			li, err := input(in, hw.ErrInvalidInput)
			if err != nil {
				return nil, err
			}
			t.ReferenceInputs = append(t.ReferenceInputs, li)
		}
	}
	for _, vv := range body.VotingProcedures {
		lv := ledger.VoterVotes{Voter: b.voter(vv.Voter)}
		for _, v := range vv.Votes {
			if !safe(v.GovActionID.Index) {
				return nil, hw.ErrInvalidVotingProcedures
			}
			if v.GovActionID.Index.Uint64() > math.MaxUint32 {
				return nil, ledger.InvalidData("invalid governance action id index")
			}
			lv.Votes = append(lv.Votes, ledger.Vote{
				GovActionTx: v.GovActionID.TxID, GovActionIndex: uint32(v.GovActionID.Index.Uint64()),
				Option: uint8(v.Procedure.Vote), Anchor: anchor(v.Procedure.Anchor),
			})
		}
		t.VotingProcedures = append(t.VotingProcedures, lv)
	}
	t.Treasury = u64ptr(body.Treasury)
	t.Donation = u64ptr(body.Donation)

	mode, err := signingMode(b.params.Mode)
	if err != nil {
		return nil, err
	}
	req := &ledger.SignRequest{Mode: mode, Tx: t, TagCborSets: body.Inputs.HasTag}
	// every signing file asks for a witness; the app asks for each key once
	for _, f := range b.params.SigningFiles {
		req.AdditionalWitnesses = append(req.AdditionalWitnesses, f.Path)
	}
	return req, nil
}

// signTx is cardano-hw-cli's ledgerSignTx: what fails with the device, or
// a body hash other than ours, is wrapped once here.
func (p *Provider) signTx(params hw.TxSigningParams, change []cardano.SigningFile) ([]ledger.PathSignature, error) {
	b := &builder{params: params, change: change}
	req, err := b.request()
	var le *ledger.Error
	if errors.As(err, &le) {
		// ledgerjs refuses it as it parses the request, in the device call
		return nil, fail(err)
	}
	if err != nil {
		return nil, err
	}
	resp, err := p.app.SignTx(req)
	if err != nil {
		return nil, fail(err)
	}
	if !bytes.Equal(resp.TxHash, params.BodyHash) {
		return nil, fail(hw.ErrTxSerializationMismatch)
	}
	return resp.Witnesses, nil
}

func (p *Provider) WitnessTx(params hw.TxSigningParams, change []cardano.SigningFile) ([]hw.Witness, error) {
	sigs, err := p.signTx(params, change)
	if err != nil {
		// cardano-hw-cli wraps everything that fails in signing, again
		return nil, fail(err)
	}
	var out []hw.Witness
	for _, s := range sigs {
		var f *cardano.SigningFile
		for i := range params.SigningFiles {
			if params.SigningFiles[i].Path.Equal(s.Path) {
				f = &params.SigningFiles[i]
				break
			}
		}
		if f == nil {
			return nil, hw.ErrMissingHwSigningDataAtPath
		}
		pub, chain, err := f.XPub()
		if err != nil {
			return nil, err
		}
		if err := hw.VerifyWitness(params.BodyHash, *f, s.Signature); err != nil {
			return nil, err
		}
		out = append(out, hw.Witness{
			Path: s.Path, Byron: cardano.Classify(s.Path) == cardano.PathWalletSpendingKeyByron,
			PubKey: pub, Signature: s.Signature, ChainCode: chain,
		})
	}
	return out, nil
}

func (p *Provider) SignOperationalCertificate(kesVKey []byte, kesPeriod uint64, c hw.OpCertCounter, files []cardano.SigningFile) ([]byte, error) {
	var path cardano.Path
	if f := hw.FileForKey(c.PoolColdKey, files); f != nil {
		path = f.Path
	}
	if path == nil {
		return nil, fail(ledger.InvalidData("invalid operational certificate cold key path"))
	}
	sig, err := p.app.SignOperationalCertificate(ledger.OperationalCertificate{
		KESPublicKey: kesVKey, KESPeriod: kesPeriod, IssueCounter: c.Counter, ColdKeyPath: path,
	})
	if err != nil {
		return nil, fail(err)
	}
	return hw.SignedOpCert(kesVKey, kesPeriod, c, sig), nil
}

// The app signs a CIP-36 registration inside a transaction: a dummy one,
// which is never submitted.
var (
	dummyPaymentPath = cardano.Path{1852 + cardano.Hardened, 1815 + cardano.Hardened, cardano.Hardened, 0, 0}
	dummyStakePath   = cardano.Path{1852 + cardano.Hardened, 1815 + cardano.Hardened, cardano.Hardened, 2, 0}
)

func (p *Provider) SignCIP36Registration(r hw.CIP36Params) ([]byte, error) {
	_, addr, err := cardano.Bech32Decode(r.PaymentAddress)
	if err != nil {
		return nil, err
	}
	var dest ledger.Destination
	if ap := hw.AddressParamsFor(r.PaymentSigningFiles, addr, r.Network); ap != nil {
		if err := hw.CheckCIP36AddressType(ap.Type); err != nil {
			return nil, err
		}
		params := ledger.AddressParams{
			Type: ap.Type, NetworkID: uint8(r.Network.NetworkID), ProtocolMagic: r.Network.ProtocolMagic,
			SpendingPath: ap.PaymentPath,
		}
		if ap.StakePath != nil {
			params.Staking, params.StakingPath = ledger.StakingKeyPath, ap.StakePath
		}
		dest = ledger.Destination{DeviceOwned: true, Params: params}
	} else {
		dest = ledger.Destination{Address: addr}
	}
	reg := &ledger.CIP36Registration{
		StakingPath: r.StakeSigningFile.Path, Destination: dest, Nonce: r.Nonce, VotingPurpose: r.VotingPurpose,
	}
	for _, d := range r.Delegations {
		if d.Weight > maxSafeInteger {
			return nil, hw.ErrInvalidCVoteWeight
		}
		if d.Weight > math.MaxUint32 {
			return nil, fail(ledger.InvalidData("invalid CIP36 delegation weight"))
		}
		reg.Delegations = append(reg.Delegations, ledger.VoteDelegation{VoteKey: d.VotePublicKey, Weight: uint32(d.Weight)})
	}
	ttl := uint64(0)
	req := &ledger.SignRequest{
		Mode: ledger.ModeOrdinary,
		Tx: ledger.Tx{
			NetworkID: uint8(r.Network.NetworkID), ProtocolMagic: r.Network.ProtocolMagic,
			Inputs: []ledger.Input{{TxHash: make([]byte, 32), Index: 0, Path: dummyPaymentPath}},
			Outputs: []ledger.Output{{
				Destination: ledger.Destination{DeviceOwned: true, Params: ledger.AddressParams{
					Type: cardano.AddrBasePaymentKeyStakeKey, NetworkID: uint8(r.Network.NetworkID),
					ProtocolMagic: r.Network.ProtocolMagic, SpendingPath: dummyPaymentPath,
					Staking: ledger.StakingKeyPath, StakingPath: dummyStakePath,
				}},
				Amount: 1,
			}},
			Fee: 0, TTL: &ttl, CIP36: reg,
		},
	}
	resp, err := p.app.SignTx(req)
	if err != nil {
		return nil, fail(err)
	}
	if resp.AuxDataHash == nil {
		return nil, fail(ErrMissingAuxDataSupplement)
	}
	meta, err := hw.EncodeCIP36Registration(r, addr, resp.AuxDataHash, resp.CIP36Signature)
	if err != nil {
		return nil, fail(err)
	}
	return meta, nil
}

// isASCII is ledgerjs's test of a message the device may show as text:
// printable ASCII, not empty, without spaces at the ends or two together.
func isASCII(m []byte) bool {
	if len(m) == 0 || m[0] == ' ' || m[len(m)-1] == ' ' {
		return false
	}
	for i, c := range m {
		if c < 32 || c > 126 || (c == ' ' && i+1 < len(m) && m[i+1] == ' ') {
			return false
		}
	}
	return true
}

func (p *Provider) SignMessage(m hw.SignMessageParams) (hw.SignedMessage, error) {
	req := ledger.MessageRequest{
		Message: m.Message, SigningPath: m.SigningFile.Path, HashPayload: m.HashPayload,
		IsASCII: isASCII(m.Message) && !m.PreferHexDisplay,
	}
	var addr []byte
	if m.Address != "" {
		ap, network, err := hw.MessageAddressParams(m)
		if err != nil {
			return hw.SignedMessage{}, err
		}
		addr = ap.Address
		params := ledger.AddressParams{Type: ap.Type, NetworkID: uint8(network.NetworkID), ProtocolMagic: network.ProtocolMagic}
		switch ap.Type {
		case cardano.AddrBasePaymentKeyStakeKey:
			params.SpendingPath, params.Staking, params.StakingPath = ap.PaymentPath, ledger.StakingKeyPath, ap.StakePath
		case cardano.AddrBasePaymentKeyStakeScript:
			params.SpendingPath, params.Staking, params.StakingHash = ap.PaymentPath, ledger.StakingScriptHash, ap.Address[1+cardano.KeyHashLength:]
		case cardano.AddrRewardKey:
			params.Staking, params.StakingPath = ledger.StakingKeyPath, ap.StakePath
		case cardano.AddrEnterpriseKey:
			params.SpendingPath = ap.PaymentPath
		}
		req.Address = &params
	}
	s, err := p.app.SignMessage(req)
	if err != nil {
		return hw.SignedMessage{}, fail(err)
	}
	if addr != nil && !bytes.Equal(addr, s.AddressField) {
		return hw.SignedMessage{}, hw.ErrMessageAddressMismatch
	}
	if !bytes.Equal(m.SigningFile.PubKey(), s.PubKey) {
		return hw.SignedMessage{}, hw.ErrSigningPubKeyMismatch
	}
	return hw.SignedMessage{Signature: s.Signature, PubKey: s.PubKey, Address: s.AddressField}, nil
}

func nativeScript(s cardano.NativeScript, files []cardano.SigningFile) ledger.NativeScript {
	n := ledger.NativeScript{Type: uint8(s.Type)}
	switch s.Type {
	case cardano.ScriptPubKey:
		if p := hw.PathForKeyHash(s.KeyHash, files); p != nil {
			n.KeyPath = p
		} else {
			n.KeyHash = s.KeyHash
		}
	case cardano.ScriptAll, cardano.ScriptAny, cardano.ScriptNOfK:
		for _, sub := range s.Scripts {
			n.Scripts = append(n.Scripts, nativeScript(sub, files))
		}
		n.Required = uint32(s.Required)
	default:
		n.Slot = s.Slot
	}
	return n
}

func (p *Provider) NativeScriptHash(s cardano.NativeScript, files []cardano.SigningFile, display hw.NativeScriptDisplay, _ hw.DerivationType) ([]byte, error) {
	format := uint8(ledger.DisplayPolicyID)
	if display == hw.DisplayBech32 {
		format = ledger.DisplayBech32
	}
	h, err := p.app.NativeScriptHash(nativeScript(s, files), format)
	if err != nil {
		return nil, fail(err)
	}
	return h, nil
}
