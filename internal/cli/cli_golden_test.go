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
	"testing"

	"github.com/Liet-ada/cardano-hw-go/internal/defects"
	"github.com/Liet-ada/cardano-hw-go/internal/device"
	"github.com/Liet-ada/cardano-hw-go/internal/hw"
)

// cliCase is a command line run by cardano-hw-cli 1.20.0-beta.4 with no
// device connected, in a copy of the inputs of its suite.
type cliCase struct {
	Line    string
	Args    []string
	Columns string
	Exit    int
	Stdout  string
	Stderr  string
	Outputs map[string]string
}

type noDevice struct{}

func (noDevice) Open() (hw.Provider, error) { return nil, device.ErrNoDevice }

// TestCLIAgainstHWCLI runs the help at several widths, malformed command
// lines and malformed files of testdata/cli.
func TestCLIAgainstHWCLI(t *testing.T) {
	// directories, which git does not keep empty
	runSuite(t, "testdata/cli/cli-golden.json.gz", "testdata/cli/inputs", "dir.json", "adir")
}

// TestTransactionsAgainstHWCLI runs validate and transform, with and
// without protocol parameters, on the transactions of testdata/txs: real
// ones of mainnet and preprod, with their witnesses and without, and
// synthetic ones (testdata/txs/sources.txt).
func TestTransactionsAgainstHWCLI(t *testing.T) {
	runSuite(t, "testdata/txs/txs-golden.json.gz", "testdata/txs/inputs")
}

// runSuite runs every case of a golden file, each in a copy of inputs and
// of the empty directories dirs, and checks that cardano-hw-go prints,
// writes and returns what cardano-hw-cli did.
func runSuite(t *testing.T, golden, inputs string, dirs ...string) {
	f, err := os.Open(golden)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var cases []cliCase
	if err := json.NewDecoder(z).Decode(&cases); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(inputs)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, e := range entries {
		if files[e.Name()], err = os.ReadFile(filepath.Join(inputs, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range cases {
		t.Run(c.Line, func(t *testing.T) {
			t.Setenv("COLUMNS", c.Columns)
			dir := t.TempDir()
			for name, b := range files {
				if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for _, d := range dirs {
				if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			t.Chdir(dir)
			var stdout, stderr bytes.Buffer
			app := &App{Stdout: &stdout, Stderr: &stderr, Devices: noDevice{}}
			if code := app.Run(c.Args); code != c.Exit {
				t.Errorf("exit %d, want %d", code, c.Exit)
			}
			if stdout.String() != c.Stdout {
				t.Errorf("stdout:\n%s\nwant:\n%s", stdout.String(), c.Stdout)
			}
			// what cardano-hw-cli printed, but for its defects
			if want := defects.Correct(c.Stderr); stderr.String() != want {
				t.Errorf("stderr:\n%s\nwant:\n%s", stderr.String(), want)
			}
			after, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range after {
				if e.IsDir() {
					continue
				}
				b, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				want, written := c.Outputs[e.Name()]
				if !written {
					want = hex.EncodeToString(files[e.Name()])
				}
				if hex.EncodeToString(b) != want {
					t.Errorf("file %s:\n%s\nwant:\n%s", e.Name(), b, mustHex(want))
				}
			}
		})
	}
}
