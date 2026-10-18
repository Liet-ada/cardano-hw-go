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

	"github.com/Liet-ada/cardano-hw-go/internal/device"
	"github.com/Liet-ada/cardano-hw-go/internal/hw"
)

// cliCase is a command line run by cardano-hw-cli 1.20.0-beta.4 with no
// device connected, in a copy of testdata/cli/inputs: help at several
// widths, malformed command lines and malformed files.
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

func TestCLIAgainstHWCLI(t *testing.T) {
	f, err := os.Open("testdata/cli/cli-golden.json.gz")
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
	inputs, err := filepath.Abs("testdata/cli/inputs")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(inputs)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.Line, func(t *testing.T) {
			t.Setenv("COLUMNS", c.Columns)
			dir := t.TempDir()
			before := map[string]string{}
			for _, e := range entries {
				b, err := os.ReadFile(filepath.Join(inputs, e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o644); err != nil {
					t.Fatal(err)
				}
				before[e.Name()] = hex.EncodeToString(b)
			}
			// directories, which git does not keep empty
			for _, d := range []string{"dir.json", "adir"} {
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
			if stderr.String() != c.Stderr {
				t.Errorf("stderr:\n%s\nwant:\n%s", stderr.String(), c.Stderr)
			}
			files, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range files {
				if e.IsDir() {
					continue
				}
				b, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				want, written := c.Outputs[e.Name()]
				if !written {
					want = before[e.Name()]
				}
				if hex.EncodeToString(b) != want {
					t.Errorf("file %s:\n%s\nwant:\n%s", e.Name(), b, mustHex(want))
				}
			}
		})
	}
}
