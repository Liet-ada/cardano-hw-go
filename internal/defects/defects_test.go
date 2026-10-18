// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package defects

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var validID = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func TestList(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range All {
		if !validID.MatchString(d.ID) || seen[d.ID] {
			t.Errorf("ID %q is not a new lowercase name", d.ID)
		}
		seen[d.ID] = true
		if d.HWCLI == "" || d.Here == "" {
			t.Errorf("%s: says neither what cardano-hw-cli does nor what is done here", d.ID)
		}
		if (d.Shows == nil) != (d.Says == "") {
			t.Errorf("%s: Shows and Says go together", d.ID)
		}
	}
}

// mention is how code names a defect, maybe across a comment line break.
var mention = regexp.MustCompile(`cardano-hw-cli\s+(?://\s*)?defect\s+(?://\s*)?([a-z0-9-]*[a-z0-9])`)

// TestMentions checks that the code names every defect where it departs
// from cardano-hw-cli, and only known ones.
func TestMentions(t *testing.T) {
	named := map[string]bool{}
	err := filepath.WalkDir("../..", func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() && (e.Name() == ".git" || e.Name() == "testdata") {
			return filepath.SkipDir
		}
		if e.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, "defects.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range mention.FindAllStringSubmatch(string(b), -1) {
			if _, ok := Find(m[1]); !ok {
				t.Errorf("%s names unknown defect %s", path, m[1])
			}
			named[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range All {
		if !named[d.ID] {
			t.Errorf("no code names defect %s", d.ID)
		}
	}
}

func TestCorrect(t *testing.T) {
	in := "The transaction contains the following fixable issues:\n- CBOR is not canonical (transaction)\nError: byronWitnesses is not iterable\n"
	want := "The transaction contains the following fixable issues:\n- CBOR is not canonical (transaction)\nError: Transaction contains vkey witnesses, transformation would invalidate them\n"
	if got := Correct(in); got != want {
		t.Errorf("Correct:\n%s\nwant:\n%s", got, want)
	}
	if got := Correct("Error: Can not parse path\n"); got != "Error: Can not parse path\n" {
		t.Errorf("Correct changed an error that is no defect: %q", got)
	}
}
