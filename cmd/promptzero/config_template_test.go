// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/xunholy/promptzero/internal/config"
)

// strictDecodeConfig decodes YAML into a fresh config.Config with
// KnownFields(true): any key that does not map to a struct field is an
// error. The runtime loader uses lenient yaml.Unmarshal, which silently
// ignores unknown keys — so without this guard a renamed field or a typo
// in a hand-maintained template would ship as a setting that quietly
// does nothing.
func strictDecodeConfig(t *testing.T, label string, data []byte) {
	t.Helper()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var c config.Config
	if err := dec.Decode(&c); err != nil {
		t.Errorf("%s: a key no longer maps to config.Config (drift): %v", label, err)
	}
}

// TestConfigTemplatesDecodeAgainstStruct pins the two hand-maintained
// config templates — the repo-root config.example.yaml reference and the
// configTemplate that `--init` writes (kept in sync by hand, per the
// comment on the const) — to the current config.Config. A drifted key in
// either would otherwise be silently ignored by the lenient loader.
//
// The two intentionally differ in scope (config.example.yaml is
// exhaustive; the --init template is a minimal starter), so this does
// NOT assert they have the same keys — only that every key each one sets
// is real.
func TestConfigTemplatesDecodeAgainstStruct(t *testing.T) {
	exData, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("read config.example.yaml: %v", err)
	}
	strictDecodeConfig(t, "config.example.yaml", exData)
	strictDecodeConfig(t, "configTemplate (--init)", []byte(configTemplate))
}
