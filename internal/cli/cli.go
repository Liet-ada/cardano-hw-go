// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package cli implements the command line of cardano-hw-go, which follows
// cardano-hw-cli's commands, options, files and exit codes.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime/debug"
	"sort"
	"strconv"

	"github.com/Liet-ada/cardano-hw-go/internal/cardano"
	"github.com/Liet-ada/cardano-hw-go/internal/hw"
	"github.com/Liet-ada/cardano-hw-go/internal/js"
	"github.com/Liet-ada/cardano-hw-go/internal/tx"
)

// Exit codes, as cardano-hw-cli uses them.
const (
	ExitSuccess            = 0
	ExitError              = 1
	ExitUnfixableIssues    = 2 // also argparse errors
	ExitFixableIssues      = 3
	exitUsage              = 2
	prog                   = "cardano-hw-cli"
	Version                = "0.1.0"
	compatibleCardanoHWCLI = "1.20.0"
)

// Errors with cardano-hw-cli's wording.
var (
	errTxContainsUnfixable   = errors.New("Transaction CBOR contains unfixable issues")
	errTxContainsFixable     = errors.New(`Transaction CBOR contains fixable issues, please run "transform" command first`)
	errCannotTransformSigned = errors.New("Transaction contains vkey witnesses, transformation would invalidate them")
)

// App runs commands. Devices are opened through Devices, so tests can
// replace them.
type App struct {
	Stdout, Stderr io.Writer
	Devices        DeviceOpener
	device         hw.Provider // open while a command runs
}

// Run runs the command line argv (without the program name) and returns the
// exit code.
func (a *App) Run(argv []string) int {
	root := rootCommand()
	parsed, err := parse(root, prog, argv)
	var help *helpRequest
	var usageErr *usageError
	switch {
	case errors.As(err, &help):
		fmt.Fprintln(a.Stdout, help.text)
		return ExitSuccess
	case errors.As(err, &usageErr):
		fmt.Fprintln(a.Stderr, usageErr.usage)
		fmt.Fprintln(a.Stderr, usageErr.msg)
		return exitUsage
	case err != nil:
		fmt.Fprintln(a.Stderr, "Error:", err)
		return ExitError
	}
	code, err := a.dispatch(root, parsed)
	if err != nil {
		fmt.Fprintln(a.Stderr, "Error:", err)
		return ExitError
	}
	return code
}

func (a *App) dispatch(root *command, p *args) (int, error) {
	switch p.cmd {
	case "":
		fmt.Fprintln(a.Stdout, help(root, prog, nil))
		return ExitSuccess, nil
	case "version":
		fmt.Fprintf(a.Stdout, "cardano-hw-go version %s (compatible with cardano-hw-cli %s)\n", Version, compatibleCardanoHWCLI)
		if c := commit(); c != "" {
			fmt.Fprintf(a.Stdout, "Commit hash: %s\n", c)
		}
		return ExitSuccess, nil
	case "transaction.validate":
		return a.validate(p)
	case "transaction.transform":
		return ExitSuccess, a.transform(p)
	}
	return a.deviceCommand(p)
}

func commit() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return ""
}

// write writes an output file the way cardano-hw-cli does, announcing it.
func (a *App) write(path string, v any) error {
	fmt.Fprintf(a.Stdout, "Writing to file '%s'.\n", path)
	data, err := cardano.MarshalOutput(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// writeRaw writes raw bytes, announcing the file.
func (a *App) writeRaw(path string, data []byte) error {
	fmt.Fprintf(a.Stdout, "Writing to file '%s'.\n", path)
	return os.WriteFile(path, data, 0o644)
}

// permittedUnfixable are the CIP-21 issues that --allow-unrestricted-mode
// lets through, silently.
var permittedUnfixable = map[string]bool{
	tx.ReasonPoolRegistrationWithOtherCertificates: true,
	tx.ReasonPoolRegistrationWithWithdrawals:       true,
	tx.ReasonPoolRegistrationWithMintEntry:         true,
	tx.ReasonPoolRegistrationWithPlutusOutputs:     true,
	tx.ReasonPoolRegistrationWithScriptDataHash:    true,
	tx.ReasonPoolRegistrationWithCollateralInputs:  true,
	tx.ReasonPoolRegistrationWithRequiredSigners:   true,
	tx.ReasonPoolRegistrationWithCollateralReturn:  true,
	tx.ReasonPoolRegistrationWithTotalCollateral:   true,
	tx.ReasonPoolRegistrationWithReferenceInputs:   true,
	tx.ReasonPoolRegistrationWithVotingProcedures:  true,
	tx.ReasonPoolRegistrationWithTreasury:          true,
	tx.ReasonPoolRegistrationWithDonation:          true,
	tx.ReasonTooManyVotersInVotingProcedures:       true,
	tx.ReasonInvalidNumberOfVotingProcedures:       true,
}

type checkResult struct {
	unfixable, fixable bool
	none               bool // no issue at all, permitted ones included
}

// checkValidation validates a transaction and prints its issues.
func (a *App) checkValidation(cbor []byte, permit, printSuccess bool) (checkResult, error) {
	issues, err := tx.Validate(cbor)
	if err != nil {
		return checkResult{}, err
	}
	var fixable, blocking []tx.ValidationError
	for _, e := range issues {
		switch {
		case e.Fixable:
			fixable = append(fixable, e)
		case permit && permittedUnfixable[e.Reason]:
		default:
			blocking = append(blocking, e)
		}
	}
	for _, g := range []struct {
		header string
		issues []tx.ValidationError
	}{
		{"The transaction contains the following unfixable issues:", blocking},
		{"The transaction contains the following fixable issues:", fixable},
	} {
		if len(g.issues) == 0 {
			continue
		}
		fmt.Fprintln(a.Stderr, g.header)
		for _, e := range g.issues {
			fmt.Fprintf(a.Stderr, "- %s (%s)\n", e.Reason, e.Position)
		}
	}
	if len(issues) == 0 && printSuccess {
		fmt.Fprintln(a.Stdout, "The transaction CBOR is valid and canonical.")
	}
	return checkResult{len(blocking) > 0, len(fixable) > 0, len(issues) == 0}, nil
}

func (a *App) validate(p *args) (int, error) {
	path, _ := p.get("txFileData")
	f, err := cardano.ReadTxFile(path)
	if err != nil {
		return 0, err
	}
	r, err := a.checkValidation(f.CBOR, p.flags["allowUnrestrictedMode"], true)
	if err != nil {
		return 0, err
	}
	switch {
	case r.unfixable:
		return ExitUnfixableIssues, nil
	case r.fixable:
		return ExitFixableIssues, nil
	}
	return ExitSuccess, nil
}

// readCostModels is cardano-hw-cli's extractCostModels: the cost models of
// a protocol parameters file, by language. Values that are not safe
// integers, which cardano-hw-cli passes on, are refused as not numbers
// (cardano-hw-cli defect cost-model-fractional).
func readCostModels(path string) (tx.CostModels, error) {
	v, err := readJSONFile(path)
	if err != nil {
		return nil, err
	}
	m := v.Get("costModels")
	models := tx.CostModels{}
	for _, e := range jsEntries(m) {
		known := false
		for _, l := range tx.PlutusLanguages {
			known = known || l.Name == e.key
		}
		if !known {
			return nil, fmt.Errorf("Unknown Plutus version in cost models: %s", e.key)
		}
		bad := fmt.Errorf("Invalid cost model values for %s: expected an array of numbers.", e.key)
		if e.value.Kind != js.Array {
			return nil, bad
		}
		params := make([]int64, len(e.value.Items))
		for i, n := range e.value.Items {
			if n.Kind != js.Number || !n.IsInteger() || math.Abs(n.Num) > 1<<53 {
				return nil, bad
			}
			params[i] = int64(n.Num)
		}
		models[e.key] = params
	}
	return models, nil
}

type jsEntry struct {
	key   string
	value js.Value
}

// jsEntries is Object.entries: keys that are array indexes first, in
// order, then the others as they were written.
func jsEntries(v js.Value) []jsEntry {
	var out []jsEntry
	switch v.Kind {
	case js.Array:
		for i, x := range v.Items {
			out = append(out, jsEntry{strconv.Itoa(i), x})
		}
	case js.Object:
		var indexes []uint64
		for _, k := range v.Keys {
			if n, err := strconv.ParseUint(k, 10, 32); err == nil && strconv.FormatUint(n, 10) == k && n < math.MaxUint32 {
				indexes = append(indexes, n)
			}
		}
		sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
		for _, n := range indexes {
			k := strconv.FormatUint(n, 10)
			out = append(out, jsEntry{k, v.Props[k]})
		}
		for _, k := range v.Keys {
			if n, err := strconv.ParseUint(k, 10, 32); err == nil && strconv.FormatUint(n, 10) == k && n < math.MaxUint32 {
				continue
			}
			out = append(out, jsEntry{k, v.Props[k]})
		}
	}
	return out
}

func (a *App) transform(p *args) error {
	path, _ := p.get("txFileData")
	f, err := cardano.ReadTxFile(path)
	if err != nil {
		return err
	}
	r, err := a.checkValidation(f.CBOR, p.flags["allowUnrestrictedMode"], true)
	if err != nil {
		return err
	}
	if r.unfixable {
		return errTxContainsUnfixable
	}
	var models tx.CostModels
	if pp, ok := p.get("protocolParamsData"); ok {
		if models, err = readCostModels(pp); err != nil {
			return err
		}
	}
	d, err := tx.Decode(f.CBOR)
	if err != nil {
		return err
	}
	var langs []string
	if l := p.all("usedCostModelLanguages"); len(l) > 0 {
		langs = l
	}
	t, err := tx.TransformTx(d.Tx, models, langs)
	if err != nil {
		return err
	}
	if r.fixable {
		// witnesses in a tagged set count too (cardano-hw-cli defect
		// transform-tagged-witnesses)
		if tx.HasVKeyWitnesses(&t) {
			return errCannotTransformSigned
		}
		fmt.Fprintln(a.Stdout, "Transformed transaction will be written to the output file.")
	}
	out, _ := p.get("outFile")
	return a.write(out, cardano.Envelope{Type: f.EnvelopeType, Description: f.Description, CBORHex: fmt.Sprintf("%x", tx.Encode(&t))})
}

func (a *App) verificationKey(p *args) error {
	in, _ := p.get("hwSigningFileData")
	sf, err := cardano.ReadSigningFile(in)
	if err != nil {
		return err
	}
	pub, chain, err := sf.XPub()
	if err != nil {
		return err
	}
	vk, err := cardano.NewVerificationKeyOutput(append(append([]byte{}, pub...), chain...), sf.Path)
	if err != nil {
		return err
	}
	out, _ := p.get("verificationKeyFile")
	return a.write(out, vk)
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
