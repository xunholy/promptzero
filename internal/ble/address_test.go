// SPDX-License-Identifier: AGPL-3.0-or-later

package ble

import (
	"strings"
	"testing"
)

func TestClassifyAddress_RandomSubtypes(t *testing.T) {
	cases := []struct {
		addr, want string
	}{
		{"C0:AA:BB:CC:DD:EE", "static random"},            // 0xC0 = 0b11......
		{"F1:AA:BB:CC:DD:EE", "static random"},            // 0xF1 top2 = 11
		{"40:AA:BB:CC:DD:EE", "resolvable private (RPA)"}, // 0x40 = 0b01......
		{"7F:AA:BB:CC:DD:EE", "resolvable private (RPA)"}, // 0x7F top2 = 01
		{"00:AA:BB:CC:DD:EE", "non-resolvable private"},   // 0x00 = 0b00......
		{"3F:AA:BB:CC:DD:EE", "non-resolvable private"},   // 0x3F top2 = 00
		{"80:AA:BB:CC:DD:EE", "reserved"},                 // 0x80 = 0b10......
	}
	for _, c := range cases {
		r, err := ClassifyAddress(c.addr, "random")
		if err != nil {
			t.Fatalf("%s: %v", c.addr, err)
		}
		if r.RandomSubtype != c.want {
			t.Errorf("%s: subtype = %q, want %q", c.addr, r.RandomSubtype, c.want)
		}
		if r.OUI != "" {
			t.Errorf("%s: random address should not surface an OUI", c.addr)
		}
	}
}

func TestClassifyAddress_Public(t *testing.T) {
	r, err := ClassifyAddress("00:1A:2B:3C:4D:5E", "public")
	if err != nil {
		t.Fatal(err)
	}
	if r.OUI != "00:1A:2B" {
		t.Errorf("OUI = %s, want 00:1A:2B", r.OUI)
	}
	if r.RandomSubtype != "" {
		t.Errorf("public address should not report a random subtype, got %q", r.RandomSubtype)
	}
	if !strings.Contains(r.Trackability, "public") {
		t.Errorf("trackability = %q", r.Trackability)
	}
}

func TestClassifyAddress_Unspecified(t *testing.T) {
	r, err := ClassifyAddress("40:AA:BB:CC:DD:EE", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.DeclaredType != "unspecified" {
		t.Errorf("declared type = %q, want unspecified", r.DeclaredType)
	}
	if r.RandomSubtype != "resolvable private (RPA)" {
		t.Errorf("subtype = %q", r.RandomSubtype)
	}
	if len(r.Notes) == 0 || !strings.Contains(r.Notes[0], "TxAdd") {
		t.Errorf("expected a public/random ambiguity note, got %v", r.Notes)
	}
}

func TestClassifyAddress_Normalization(t *testing.T) {
	for _, a := range []string{"c0aabbccddee", "c0-aa-bb-cc-dd-ee", "C0AA.BBCC.DDEE"} {
		r, err := ClassifyAddress(a, "random")
		if err != nil {
			t.Fatalf("%s: %v", a, err)
		}
		if r.Address != "C0:AA:BB:CC:DD:EE" {
			t.Errorf("%s normalised to %s", a, r.Address)
		}
	}
}

func TestClassifyAddress_Errors(t *testing.T) {
	if _, err := ClassifyAddress("C0:AA:BB", "random"); err == nil {
		t.Error("short address: expected error")
	}
	if _, err := ClassifyAddress("ZZ:AA:BB:CC:DD:EE", "random"); err == nil {
		t.Error("non-hex: expected error")
	}
	if _, err := ClassifyAddress("C0:AA:BB:CC:DD:EE", "bogus"); err == nil {
		t.Error("bad address_type: expected error")
	}
}
