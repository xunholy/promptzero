// SPDX-License-Identifier: AGPL-3.0-or-later

package cyfral

import "testing"

func TestDecodeValidFrame(t *testing.T) {
	// Hand-traced: start 1 + data E D B 7 E D B 7 + stop 1 -> key 0xE4E4.
	r, err := Decode("1edb7edb71")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Key != 0xE4E4 || r.KeyHex != "E4E4" {
		t.Errorf("key = 0x%04X / %q, want 0xE4E4 / E4E4", r.Key, r.KeyHex)
	}
}

func TestDecodeAllSameNibble(t *testing.T) {
	// all data nibbles 0x7 (-> 00) -> key 0x0000; start/stop 1.
	r, err := Decode("1777777771")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Key != 0x0000 {
		t.Errorf("key = 0x%04X, want 0x0000", r.Key)
	}
	// all data nibbles 0xE (-> 11) -> key 0xFFFF.
	r2, err := Decode("1eeeeeeee1")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r2.Key != 0xFFFF {
		t.Errorf("key = 0x%04X, want 0xFFFF", r2.Key)
	}
}

func TestStructuralRejection(t *testing.T) {
	cases := map[string]string{
		"bad start":       "2edb7edb71", // start nibble 2
		"bad stop":        "1edb7edb72", // stop nibble 2
		"bad data nibble": "1edb0edb71", // data nibble 0 not in {7,B,D,E}
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: Decode(%q) expected error", name, in)
		}
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz", "1edb7edb7", "1edb7edb7100"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
