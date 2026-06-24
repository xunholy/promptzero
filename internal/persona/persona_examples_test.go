// SPDX-License-Identifier: AGPL-3.0-or-later

package persona

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExamplePersonasLoad guards the shipped examples/personas/*.yaml
// templates against drift. Operators copy these into
// ~/.promptzero/personas/, but nothing else loads them — so a YAML typo,
// a missing `name`, or a renamed struct tag would ship silently. (That
// is the same drift class that left SECURITY.md recommending a persona
// which didn't resolve on a fresh install.)
//
// Each file is loaded through the real registry with per-file Load,
// which surfaces errors — LoadDir deliberately swallows them (logs +
// continues), so it would mask exactly the breakage this test exists to
// catch. Every example must parse and be retrievable by its declared
// name.
func TestExamplePersonasLoad(t *testing.T) {
	dir := filepath.Join("..", "..", "examples", "personas")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	// The names these examples declare; renaming or deleting one without
	// updating dependent docs is the regression we want to catch.
	want := []string{"blue-team-audit", "ctf-shelf", "explorer", "hw-lab", "red-team-day"}

	r := NewRegistry()
	loaded := 0
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || (!strings.HasSuffix(n, ".yaml") && !strings.HasSuffix(n, ".yml")) {
			continue
		}
		loaded++
		if err := r.Load(filepath.Join(dir, n)); err != nil {
			t.Errorf("example persona %s failed to load: %v", n, err)
		}
	}
	if loaded == 0 {
		t.Fatalf("no example persona YAMLs found in %s — moved or deleted?", dir)
	}
	for _, name := range want {
		if _, ok := r.Get(name); !ok {
			t.Errorf("example persona %q did not load / not retrievable by name", name)
		}
	}
}
