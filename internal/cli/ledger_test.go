// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Liet-ada/cardano-hw-go/internal/hw"
	hwledger "github.com/Liet-ada/cardano-hw-go/internal/hw/ledger"
	"github.com/Liet-ada/cardano-hw-go/internal/ledger"
	"github.com/Liet-ada/cardano-hw-go/internal/ledger/ledgersim"
)

// ledgerCase is a command run by cardano-hw-cli 1.20.0-beta.4 against the
// simulated Ledger, with what it printed, wrote and sent to the device.
// The cases come from cardano-hw-cli's Ledger integration tests, whose
// keys and signatures are those of a real device; testdata holds them as
// cardano-hw-cli ran them.
type ledgerCase struct {
	Name, Version string
	XS            bool
	TxHash, Fail  string
	Args          []string
	Inputs        map[string]string // name: content in hex
	Exit          int
	Stdout        string
	Stderr        string
	Outputs       map[string]string // files written or changed
	Transcript    []string          // "apdu response" in hex
}

type simOpener struct{ sim *ledgersim.Sim }

func (o simOpener) Open() (hw.Provider, error) { return hwledger.New(ledger.New(o.sim)), nil }

func readLedgerCases(t *testing.T) []ledgerCase {
	f, err := os.Open("testdata/ledger-golden.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var cases []ledgerCase
	if err := json.NewDecoder(z).Decode(&cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

func newSim(t *testing.T, c ledgerCase) *ledgersim.Sim {
	var v [4]byte
	for i, part := range strings.Split(c.Version, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || i > 2 {
			t.Fatalf("bad version %q", c.Version)
		}
		v[i] = byte(n)
	}
	if c.XS {
		v[3] |= 4
	}
	sim, err := ledgersim.New(ledgersim.TestMnemonic, v)
	if err != nil {
		t.Fatal(err)
	}
	if c.TxHash != "" {
		if sim.TxHash, err = hex.DecodeString(c.TxHash); err != nil {
			t.Fatal(err)
		}
	}
	if c.Fail != "" {
		at, sw, _ := strings.Cut(c.Fail, ":")
		n, err1 := strconv.Atoi(at)
		code, err2 := strconv.ParseUint(sw, 16, 16)
		if err1 != nil || err2 != nil {
			t.Fatalf("bad fail %q", c.Fail)
		}
		var mu sync.Mutex
		count := 0
		sim.Fail = func([]byte) uint16 {
			mu.Lock()
			defer mu.Unlock()
			count++
			if count-1 == n {
				return uint16(code)
			}
			return 0
		}
	}
	return sim
}

// TestLedgerAgainstHWCLI runs every case and checks that cardano-hw-go
// prints, writes and sends the same.
func TestLedgerAgainstHWCLI(t *testing.T) {
	t.Setenv("COLUMNS", "")
	for _, c := range readLedgerCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			dir := t.TempDir()
			for name, h := range c.Inputs {
				b, err := hex.DecodeString(h)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			t.Chdir(dir)
			sim := newSim(t, c)
			var stdout, stderr bytes.Buffer
			app := &App{Stdout: &stdout, Stderr: &stderr, Devices: simOpener{sim}}
			code := app.Run(c.Args)
			if code != c.Exit {
				t.Errorf("exit %d, want %d", code, c.Exit)
			}
			if stdout.String() != c.Stdout {
				t.Errorf("stdout:\n%s\nwant:\n%s", stdout.String(), c.Stdout)
			}
			if got := strings.TrimSpace(stderr.String()); got != c.Stderr {
				t.Errorf("stderr:\n%s\nwant:\n%s", got, c.Stderr)
			}
			var transcript []string
			for _, e := range sim.Transcript() {
				transcript = append(transcript, hex.EncodeToString(e.APDU)+" "+hex.EncodeToString(e.Response))
			}
			if strings.Join(transcript, "\n") != strings.Join(c.Transcript, "\n") {
				for i := 0; i < max(len(transcript), len(c.Transcript)); i++ {
					var got, want string
					if i < len(transcript) {
						got = transcript[i]
					}
					if i < len(c.Transcript) {
						want = c.Transcript[i]
					}
					if got != want {
						t.Errorf("APDU %d:\n got %s\nwant %s", i, got, want)
						break
					}
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			sort.Strings(names)
			for _, name := range names {
				b, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				want, written := c.Outputs[name]
				if !written {
					want = c.Inputs[name]
				}
				if hex.EncodeToString(b) != want {
					t.Errorf("file %s:\n%s\nwant:\n%s", name, b, mustHex(want))
				}
			}
			for name := range c.Outputs {
				if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
					t.Errorf("file %s not written", name)
				}
			}
		})
	}
}

func mustHex(h string) string {
	b, _ := hex.DecodeString(h)
	return string(b)
}
