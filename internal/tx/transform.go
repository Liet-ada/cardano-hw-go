// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tx

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/cardano-hw-go/internal/cbor"
)

func transformMultiasset(m Multiasset) Multiasset {
	var out Multiasset
	for _, g := range m {
		if len(g.Tokens) > 0 {
			out = append(out, g)
		}
	}
	return out
}

func transformOutput(o Output) Output {
	if o.Amount.HasMultiasset {
		o.Amount.Multiasset = transformMultiasset(o.Amount.Multiasset)
		if len(o.Amount.Multiasset) == 0 {
			o.Amount = Amount{Coin: o.Amount.Coin}
		}
	}
	if o.Format == FormatMapBabbage {
		if o.Datum != nil && o.Datum.Type == DatumInline && len(o.Datum.Bytes) == 0 {
			o.Datum = nil
		}
		if o.HasReferenceScript && len(o.ReferenceScript) == 0 {
			o.HasReferenceScript, o.ReferenceScript = false, nil
		}
	}
	return o
}

// TransformBody fixes the fixable CIP-21 issues of a body, given the
// auxiliary data of its transaction. The body keeps its meaning.
func TransformBody(b Body, auxiliaryData cbor.Value) Body {
	outs := make([]Output, len(b.Outputs))
	for i, o := range b.Outputs {
		outs[i] = transformOutput(o)
	}
	b.Outputs = outs
	if b.HasWithdrawals && len(b.Withdrawals) == 0 {
		b.HasWithdrawals, b.Withdrawals = false, nil
	}
	// the auxiliary data is re-encoded canonically, so its hash changes;
	// without auxiliary data the given hash stays
	if !auxiliaryData.IsNull() && !(auxiliaryData.Kind == cbor.Simple && auxiliaryData.Uint == cbor.SimpleUndefined) {
		h := blake2b.Sum256(cbor.EncodeCanonical(auxiliaryData))
		b.AuxiliaryDataHash = h[:]
	}
	if b.CollateralReturn != nil {
		cr := transformOutput(*b.CollateralReturn)
		b.CollateralReturn = &cr
	}
	if b.HasVotingProcedures && len(b.VotingProcedures) == 0 {
		b.HasVotingProcedures, b.VotingProcedures = false, nil
	}
	// a 258 tag on one set puts one on all of them
	tags := b.sets()
	for _, t := range tags {
		if *t {
			for _, u := range tags {
				*u = true
			}
			break
		}
	}
	return b
}

// TransformTx fixes the fixable CIP-21 issues of a transaction. When it has
// a script data hash, the hash is computed again over the canonical witness
// set, which takes the cost models of the protocol parameters; usedLanguages
// names the Plutus versions when the witness set holds no scripts.
func TransformTx(t Transaction, costModels CostModels, usedLanguages []string) (Transaction, error) {
	// copy the sets the transformation changes in place
	t.Body = cloneSets(t.Body)
	t.Body = TransformBody(t.Body, t.AuxiliaryData)
	h, err := transformScriptDataHash(t.Body.ScriptDataHash, t.WitnessSet, costModels, usedLanguages)
	if err != nil {
		return Transaction{}, err
	}
	t.Body.ScriptDataHash = h
	return t, nil
}

func cloneSets(b Body) Body {
	if b.Certificates != nil {
		c := *b.Certificates
		c.Items = append([]Certificate(nil), c.Items...)
		for i := range c.Items {
			if c.Items[i].PoolParams != nil {
				p := *c.Items[i].PoolParams
				c.Items[i].PoolParams = &p
			}
		}
		b.Certificates = &c
	}
	for _, s := range []**Set[Input]{&b.CollateralInputs, &b.ReferenceInputs} {
		if *s != nil {
			c := **s
			*s = &c
		}
	}
	if b.RequiredSigners != nil {
		c := *b.RequiredSigners
		b.RequiredSigners = &c
	}
	if b.ProposalProcedures != nil {
		c := *b.ProposalProcedures
		b.ProposalProcedures = &c
	}
	return b
}

// CostModels maps a Plutus language name (PlutusV1, PlutusV2, PlutusV3) to
// its cost model parameters.
type CostModels map[string][]int64

// PlutusLanguages are the Plutus versions with their language id and the key
// of their scripts in the witness set.
var PlutusLanguages = []struct {
	Name       string
	ID         uint64
	WitnessKey uint64
}{
	{"PlutusV1", 0, WitnessPlutusV1Script},
	{"PlutusV2", 1, WitnessPlutusV2Script},
	{"PlutusV3", 2, WitnessPlutusV3Script},
}

// Errors of the script data hash computation, worded as the library does.
var (
	ErrInvalidCostModelLanguage    = errors.New("Invalid cost model language name")
	ErrUsedLanguagesEmpty          = errors.New("Invalid used cost model languages --- empty list")
	ErrCannotInferPlutusLanguages  = errors.New("Could not infer Plutus language versions")
	ErrMissingCostModelForLanguage = errors.New("Missing cost model for required Plutus language")
	ErrMissingCostModels           = errors.New("Missing cost models for script data hash recomputation")
)

func languageID(name string) (uint64, error) {
	for _, l := range PlutusLanguages {
		if l.Name == name {
			return l.ID, nil
		}
	}
	return 0, fmt.Errorf("%w: %s", ErrInvalidCostModelLanguage, name)
}

func transformScriptDataHash(hash []byte, witnessSet cbor.Value, costModels CostModels, usedLanguages []string) ([]byte, error) {
	if hash == nil {
		return nil, nil
	}
	if costModels == nil {
		return nil, ErrMissingCostModels
	}
	if witnessSet.Kind != cbor.Map || len(witnessSet.Entries) == 0 {
		return hash, nil
	}
	redeemers, hasRedeemers := witnessSet.Get(WitnessRedeemers)
	datums, hasDatums := witnessSet.Get(WitnessPlutusData)
	if !hasRedeemers && !hasDatums {
		return hash, nil
	}

	models := map[uint64][]int64{}
	for name, params := range costModels {
		id, err := languageID(name)
		if err != nil {
			return nil, err
		}
		models[id] = params
	}

	used := map[uint64]bool{}
	for _, l := range PlutusLanguages {
		if _, ok := witnessSet.Get(l.WitnessKey); ok {
			used[l.ID] = true
		}
	}
	if len(used) == 0 {
		if usedLanguages == nil {
			return nil, ErrCannotInferPlutusLanguages
		}
		if len(usedLanguages) == 0 {
			return nil, ErrUsedLanguagesEmpty
		}
		for _, name := range usedLanguages {
			id, err := languageID(name)
			if err != nil {
				return nil, err
			}
			used[id] = true
		}
	}
	for id := range used {
		if _, ok := models[id]; !ok {
			return nil, ErrMissingCostModelForLanguage
		}
	}

	var views []cbor.Entry
	for id, params := range models {
		if !used[id] {
			continue
		}
		if id == 0 {
			// PlutusV1 is "double bagged": the key is the bytes of
			// serialize(0) and the value the bytes of an indefinite list
			list := []byte{0x9f}
			for _, p := range params {
				list = append(list, cbor.EncodeCanonical(cbor.NewInt(p))...)
			}
			list = append(list, 0xff)
			views = append(views, cbor.Entry{Key: cbor.NewBytes([]byte{0}), Value: cbor.NewBytes(list)})
			continue
		}
		items := make([]cbor.Value, len(params))
		for i, p := range params {
			items[i] = cbor.NewInt(p)
		}
		views = append(views, cbor.Entry{Key: cbor.NewUint(id), Value: cbor.NewArray(items...)})
	}

	var in []byte
	if hasRedeemers {
		in = append(in, cbor.EncodeCanonical(redeemers)...)
	} else {
		in = append(in, 0xa0)
	}
	if hasDatums {
		in = append(in, cbor.EncodeCanonical(datums)...)
	}
	in = append(in, cbor.EncodeCanonical(cbor.NewMap(views...))...)
	h := blake2b.Sum256(in)
	return h[:], nil
}
