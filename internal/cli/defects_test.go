// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Liet-ada/cardano-hw-go/internal/defects"
	"github.com/Liet-ada/cardano-hw-go/internal/hw"
	hwtrezor "github.com/Liet-ada/cardano-hw-go/internal/hw/trezor"
	"github.com/Liet-ada/cardano-hw-go/internal/ledger/ledgersim"
)

// defectCase is a command line on what a defect of cardano-hw-cli is about,
// with what cardano-hw-go does instead.
type defectCase struct {
	defect string
	args   []string
	// files is where the command runs: testdata/cli/inputs and inputs, or,
	// when ledger names a case of testdata/ledger-golden.json.gz, that
	// case's inputs, with the simulated Ledger connected
	inputs map[string]string
	ledger string
	// trezor connects a Trezor provider with no device behind it, for
	// what fails before anything is sent
	trezor bool
	exit   int
	stdout string
	stderr string
	wrote  map[string]string // files written, by name
	// hwcli is what cardano-hw-cli printed on stderr for the same command
	// line, with the simulated Ledger when ledger is set, when it was
	// recorded
	hwcli string
}

const (
	// a transaction with a fee in the 8-byte form, which transform fixes,
	// and a vkey witness in a set tagged 258
	txTaggedVKeyWitness = `{"type":"Witnessed Tx ConwayEra","description":"","cborHex":"84a400d9010281825820000000000000000000000000000000000000000000000000000000000000000000018182581d60000102030405060708090a0b0c0d0e0f101112131415161718191a1b1a001e8480021b0000000000030d40031903e8a100d90102818258200101010101010101010101010101010101010101010101010101010101010101584000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f5f6"}`
	// the same with an empty tagged set of vkey witnesses
	txTaggedNoWitness = `{"type":"Witnessed Tx ConwayEra","description":"","cborHex":"84a400d9010281825820000000000000000000000000000000000000000000000000000000000000000000018182581d60000102030405060708090a0b0c0d0e0f101112131415161718191a1b1a001e8480021b0000000000030d40031903e8a100d9010280f5f6"}`
	// the same with no vkey witness and a bootstrap witness in a tagged set
	txTaggedBootstrapWitness = `{"type":"Witnessed Tx ConwayEra","description":"","cborHex":"84a400d9010281825820000000000000000000000000000000000000000000000000000000000000000000018182581d60000102030405060708090a0b0c0d0e0f101112131415161718191a1b1a001e8480021b0000000000030d40031903e8a2008002d901028184582001010101010101010101010101010101010101010101010101010101010101015840000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005820000000000000000000000000000000000000000000000000000000000000000041a0f5f6"}`

	fixableIssues  = "The transaction contains the following fixable issues:\n- CBOR is not canonical (transaction)\n"
	errNoTransport = "Error: Error occurred while trying to find hw transport, make sure Ledger or Trezor or Keystone is connected to your computer\n"
	// how cardano-hw-cli wraps an error of ledgerjs, even one for bad input
	ledgerFailed = "Error: The requested operation failed. Check that your Ledger device is connected, unlocked and with Cardano app running.\n"
	// a transaction whose metadata is {1: x}, for the x of metadataTx
	metadataTxHead = "84a400d901028182582000000000000000000000000000000000000000000000000000000000000000000001818258" +
		"1d60000102030405060708090a0b0c0d0e0f101112131415161718191a1b1a001e8480021a00030d40031903e8a0f5a101"
	ledgerWitnessCase = "tx-ordinary_InputAndOutput@7.1.4"
	ledgerOpCertCase  = "opcert-opcert1@7.1.4"
)

// metadataTx is a transaction file whose metadata is {1: x}, x in hex.
func metadataTx(x string) string {
	return `{"type":"Unwitnessed Tx ConwayEra","description":"","cborHex":"` + metadataTxHead + x + `"}`
}

// emulatorDefects are tested against the Trezor emulator, by the
// subtests of TestEmulatorFlows named here.
var emulatorDefects = map[string]string{
	"trezor-address-not-checked":       "show address",
	"trezor-key-failure-as-cancel":     "key path refused",
	"trezor-address-cancel-as-invalid": "rejections",
}

var defectCases = []defectCase{
	{
		defect: "transform-tagged-witnesses",
		args:   []string{"transaction", "transform", "--tx-file", "tagged.json", "--out-file", "o"},
		inputs: map[string]string{"tagged.json": txTaggedVKeyWitness},
		exit:   1,
		stderr: fixableIssues + "Error: Transaction contains vkey witnesses, transformation would invalidate them\n",
		hwcli:  fixableIssues + "Error: shelleyWitnesses is not iterable\n",
	},
	{
		defect: "transform-tagged-witnesses",
		args:   []string{"transaction", "transform", "--tx-file", "tagged.json", "--out-file", "o"},
		inputs: map[string]string{"tagged.json": txTaggedBootstrapWitness},
		exit:   1,
		stderr: fixableIssues + "Error: Transaction contains vkey witnesses, transformation would invalidate them\n",
		hwcli:  fixableIssues + "Error: byronWitnesses is not iterable\n",
	},
	{
		// cardano-hw-cli crashes the same way on an empty set, but with no
		// witness to invalidate the transformation goes on
		defect: "transform-tagged-witnesses",
		args:   []string{"transaction", "transform", "--tx-file", "tagged.json", "--out-file", "o"},
		inputs: map[string]string{"tagged.json": txTaggedNoWitness},
		stdout: "Transformed transaction will be written to the output file.\nWriting to file 'o'.\n",
		stderr: fixableIssues,
		wrote:  map[string]string{"o": "{\n    \"type\": \"Witnessed Tx ConwayEra\",\n    \"description\": \"\",\n    \"cborHex\": \"84a400d9010281825820000000000000000000000000000000000000000000000000000000000000000000018182581d60000102030405060708090a0b0c0d0e0f101112131415161718191a1b1a001e8480021a00030d40031903e8a100d9010280f5f6\"\n}"},
	},
	{
		defect: "native-script-fractional-slot",
		args:   []string{"transaction", "policyid", "--script-file", "s_frac.json"},
		exit:   1,
		stderr: "Error: Invalid native script file\n",
		hwcli:  "Error: The number 1.5 cannot be converted to a BigInt because it is not an integer\n",
	},
	{
		defect: "native-script-fractional-required",
		args:   []string{"transaction", "policyid", "--script-file", "s_required.json"},
		inputs: map[string]string{"s_required.json": `{"type":"atLeast","required":1.5,"scripts":[]}`},
		exit:   1,
		stderr: "Error: Invalid native script file\n",
		hwcli:  errNoTransport,
	},
	{
		defect: "cost-model-fractional",
		args:   []string{"transaction", "transform", "--tx-file", "good.tx", "--out-file", "o", "--protocol-params-file", "pp_frac.json"},
		exit:   1,
		stdout: "The transaction CBOR is valid and canonical.\n",
		stderr: "Error: Invalid cost model values for PlutusV1: expected an array of numbers.\n",
	},
	{
		defect: "path-part-out-of-range",
		args:   []string{"address", "key-gen", "--path", "1852H/1815H/0H/0/4294967296", "--hw-signing-file", "p", "--verification-key-file", "v"},
		exit:   1,
		stderr: "Error: Can not parse path\n",
		hwcli:  errNoTransport,
	},
	{
		defect: "path-part-out-of-range",
		args:   []string{"address", "key-gen", "--path", "1852H/1815H/0H/0/4294967296", "--hw-signing-file", "p", "--verification-key-file", "v"},
		ledger: ledgerWitnessCase,
		exit:   1,
		stderr: "Error: Can not parse path\n",
		hwcli:  ledgerFailed + "Details: InvalidData: invalid path\n",
	},
	{
		defect: "testnet-magic-missing",
		args:   []string{"transaction", "witness", "--testnet-magic", "--tx-file", "tx.json", "--hw-signing-file", "payment0.hwsfile", "--out-file", "w0.witness"},
		ledger: ledgerWitnessCase,
		exit:   1,
		stderr: "Error: Testnet protocol magic is missing\n",
		hwcli:  "Error: Cannot read properties of undefined (reading 'networkId')\n",
	},
	{
		defect: "mainnet-value",
		args:   []string{"transaction", "witness", "--mainnet", "x", "--tx-file", "tx.json", "--hw-signing-file", "payment0.hwsfile", "--out-file", "w0.witness"},
		ledger: ledgerWitnessCase,
		exit:   1,
		stderr: "Error: Invalid network after --mainnet: x\n",
		hwcli:  ledgerFailed + "Details: " + ledgerFailed + "Details: InvalidData: invalid protocol magic\n",
	},
	{
		defect: "testnet-magic-not-number",
		args:   []string{"transaction", "witness", "--testnet-magic", "abc", "--tx-file", "tx.json", "--hw-signing-file", "payment0.hwsfile", "--out-file", "w0.witness"},
		ledger: ledgerWitnessCase,
		exit:   1,
		stderr: "Error: Invalid protocol magic: abc\n",
		hwcli:  ledgerFailed + "Details: " + ledgerFailed + "Details: InvalidData: invalid protocol magic\n",
	},
	{
		defect: "testnet-magic-not-number",
		args:   []string{"transaction", "witness", "--testnet-magic", "4294967296", "--tx-file", "tx.json", "--hw-signing-file", "payment0.hwsfile", "--out-file", "w0.witness"},
		ledger: ledgerWitnessCase,
		exit:   1,
		stderr: "Error: Invalid protocol magic: 4294967296\n",
		hwcli:  ledgerFailed + "Details: " + ledgerFailed + "Details: InvalidData: invalid protocol magic\n",
	},
	{
		// cardano-hw-cli takes it
		defect: "cbor-nesting-too-deep",
		args:   []string{"transaction", "validate", "--tx-file", "deep.json"},
		inputs: map[string]string{"deep.json": metadataTx(strings.Repeat("81", 600) + "00")},
		exit:   1,
		stderr: "Error: CBOR nested more than 512 levels deep\n",
	},
	{
		defect: "cbor-nesting-too-deep",
		args:   []string{"transaction", "validate", "--tx-file", "deep.json"},
		inputs: map[string]string{"deep.json": metadataTx(strings.Repeat("81", 5000) + "00")},
		exit:   1,
		stderr: "Error: CBOR nested more than 512 levels deep\n",
		hwcli:  "Error: Maximum call stack size exceeded\n",
	},
	{
		defect: "cbor-bignum-not-bytes",
		args:   []string{"transaction", "validate", "--tx-file", "bignum.json"},
		inputs: map[string]string{"bignum.json": metadataTx("c26161")},
		exit:   1,
		stderr: "Error: Bignum whose content is not a byte string\n",
		hwcli:  fixableIssues,
	},
	{
		defect: "trezor-message-hex-odd-length",
		args:   []string{"message", "sign", "--message-hex", "abc", "--signing-path-hwsfile", "good.hwsfile", "--out-file", "o"},
		trezor: true,
		exit:   1,
		stderr: "Error: Message payload must be a hexadecimal string without a \"0x\" prefix.\n",
	},
	{
		defect: "number-out-of-range",
		args:   []string{"node", "issue-op-cert", "--kes-verification-key-file", "kes.vkey", "--kes-period", "18446744073709551616", "--operational-certificate-issue-counter-file", "cold.counter", "--hw-signing-file", "poolCold0.hwsfile", "--out-file", "op.cert"},
		ledger: ledgerOpCertCase,
		exit:   1,
		stderr: "Error: Invalid KES period: 18446744073709551616\n",
		hwcli:  ledgerFailed + "Details: InvalidData: invalid operational certificate kes period\n",
	},
	{
		defect: "number-out-of-range",
		args:   []string{"node", "issue-op-cert", "--kes-verification-key-file", "kes.vkey", "--kes-period", "-1", "--operational-certificate-issue-counter-file", "cold.counter", "--hw-signing-file", "poolCold0.hwsfile", "--out-file", "op.cert"},
		ledger: ledgerOpCertCase,
		exit:   1,
		stderr: "Error: Invalid KES period: -1\n",
		hwcli:  ledgerFailed + "Details: InvalidData: invalid operational certificate kes period\n",
	},
}

type trezorNoDevice struct{}

func (trezorNoDevice) Open() (hw.Provider, error) { return hwtrezor.New(nil), nil }

// TestDefects runs every defect of cardano-hw-cli that cardano-hw-go does
// not copy, and checks that the correction of the error cardano-hw-cli
// prints is what cardano-hw-go prints.
func TestDefects(t *testing.T) {
	t.Setenv("COLUMNS", "")
	ledgerInputs := map[string]map[string]string{}
	for _, c := range readLedgerCases(t) {
		ledgerInputs[c.Name] = c.Inputs
	}
	tested := map[string]bool{}
	for _, c := range defectCases {
		d, ok := defects.Find(c.defect)
		if !ok {
			t.Errorf("unknown defect %s", c.defect)
			continue
		}
		tested[d.ID] = true
		t.Run(d.ID+" "+strings.Join(c.args, " "), func(t *testing.T) {
			if d.Shows != nil && c.hwcli != "" {
				if got := defects.Correct(c.hwcli); got != c.stderr {
					t.Errorf("cardano-hw-cli's error, corrected:\n%s\nwant:\n%s", got, c.stderr)
				}
			}
			dir := t.TempDir()
			write := func(name string, b []byte) {
				if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			app := &App{Devices: noDevice{}}
			if c.ledger != "" {
				inputs, ok := ledgerInputs[c.ledger]
				if !ok {
					t.Fatalf("no Ledger case %s", c.ledger)
				}
				for name, h := range inputs {
					b, err := hex.DecodeString(h)
					if err != nil {
						t.Fatal(err)
					}
					write(name, b)
				}
				sim, err := ledgersim.New(ledgersim.TestMnemonic, [4]byte{7, 1, 4})
				if err != nil {
					t.Fatal(err)
				}
				app.Devices = simOpener{sim}
			} else {
				if c.trezor {
					app.Devices = trezorNoDevice{}
				}
				entries, err := os.ReadDir("testdata/cli/inputs")
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range entries {
					b, err := os.ReadFile(filepath.Join("testdata/cli/inputs", e.Name()))
					if err != nil {
						t.Fatal(err)
					}
					write(e.Name(), b)
				}
			}
			for name, s := range c.inputs {
				write(name, []byte(s))
			}
			t.Chdir(dir)
			var stdout, stderr bytes.Buffer
			app.Stdout, app.Stderr = &stdout, &stderr
			if code := app.Run(c.args); code != c.exit {
				t.Errorf("exit %d, want %d", code, c.exit)
			}
			if stdout.String() != c.stdout {
				t.Errorf("stdout:\n%s\nwant:\n%s", stdout.String(), c.stdout)
			}
			if stderr.String() != c.stderr {
				t.Errorf("stderr:\n%s\nwant:\n%s", stderr.String(), c.stderr)
			}
			for name, want := range c.wrote {
				if b, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(b) != want {
					t.Errorf("file %s:\n%s\nwant:\n%s", name, b, want)
				}
			}
		})
	}
	for _, d := range defects.All {
		if _, ok := emulatorDefects[d.ID]; !tested[d.ID] && !ok {
			t.Errorf("defect %s has no test", d.ID)
		}
	}
}
