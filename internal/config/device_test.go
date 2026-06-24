// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"bytes"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestDeviceUnmarshal_BothForms pins that a devices: entry parses in both
// the bare-string shorthand the docs teach and the full mapping form.
// Before Device.UnmarshalYAML the shorthand failed (string -> struct), so
// an operator copying the scenario docs got a config that wouldn't load.
func TestDeviceUnmarshal_BothForms(t *testing.T) {
	const y = `
devices:
  garage: /ext/subghz/garage.sub
  tv:
    type: infrared
    file: /ext/infrared/tv.ir
    commands:
      power: /ext/infrared/tv_power.ir
`
	dec := yaml.NewDecoder(bytes.NewReader([]byte(y)))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Shorthand: File set from the scalar, Type/Commands empty.
	g, ok := c.Devices["garage"]
	if !ok {
		t.Fatal("garage device missing")
	}
	if g.File != "/ext/subghz/garage.sub" {
		t.Errorf("garage.File = %q, want /ext/subghz/garage.sub", g.File)
	}
	if g.Type != "" || len(g.Commands) != 0 {
		t.Errorf("garage shorthand should leave Type/Commands empty, got type=%q commands=%v", g.Type, g.Commands)
	}

	// Full mapping form: every field populated.
	tv, ok := c.Devices["tv"]
	if !ok {
		t.Fatal("tv device missing")
	}
	if tv.Type != "infrared" || tv.File != "/ext/infrared/tv.ir" {
		t.Errorf("tv = %+v, want type=infrared file=/ext/infrared/tv.ir", tv)
	}
	if tv.Commands["power"] != "/ext/infrared/tv_power.ir" {
		t.Errorf("tv.Commands[power] = %q", tv.Commands["power"])
	}
}
