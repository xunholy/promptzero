// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import "testing"

func TestEncodeRawNECRoundTrip(t *testing.T) {
	for _, c := range []struct{ a, cmd int }{{0x04, 0x08}, {0, 0}, {255, 255}, {0x1A, 0x7F}} {
		s, err := EncodeRaw("NEC", c.a, c.cmd, EncodeOptions{})
		if err != nil {
			t.Fatalf("EncodeRaw NEC %d/%d: %v", c.a, c.cmd, err)
		}
		r, err := DecodeRaw(s)
		if err != nil {
			t.Fatalf("DecodeRaw(NEC %d/%d): %v", c.a, c.cmd, err)
		}
		if r.Protocol != "NEC" || r.Address != c.a || r.Command != c.cmd || !r.ChecksumValid {
			t.Errorf("NEC round-trip %d/%d -> %s %d/%d valid=%v", c.a, c.cmd, r.Protocol, r.Address, r.Command, r.ChecksumValid)
		}
	}
}

func TestEncodeRawSamsungRoundTrip(t *testing.T) {
	s, err := EncodeRaw("Samsung32", 0x07, 0x02, EncodeOptions{})
	if err != nil {
		t.Fatalf("EncodeRaw Samsung: %v", err)
	}
	r, err := DecodeRaw(s)
	if err != nil {
		t.Fatalf("DecodeRaw(Samsung): %v", err)
	}
	if r.Protocol != "Samsung32" || r.Address != 0x07 || r.Command != 0x02 {
		t.Errorf("Samsung round-trip -> %s %d/%d", r.Protocol, r.Address, r.Command)
	}
}

func TestEncodeRawSIRCRoundTrip(t *testing.T) {
	for _, bits := range []int{12, 15, 20} {
		ext := 0
		if bits == 20 {
			ext = 0x3
		}
		s, err := EncodeRaw("SIRC", 0x12, 0x05, EncodeOptions{SIRCBits: bits, Ext: ext})
		if err != nil {
			t.Fatalf("EncodeRaw SIRC %d: %v", bits, err)
		}
		r, err := DecodeRaw(s)
		if err != nil {
			t.Fatalf("DecodeRaw(SIRC %d): %v", bits, err)
		}
		if r.Command != 0x05 || r.Bits != bits {
			t.Errorf("SIRC%d round-trip -> cmd %d bits %d", bits, r.Command, r.Bits)
		}
	}
}

func TestEncodeRawRC5RoundTrip(t *testing.T) {
	// classic RC5 (command <= 63) and RC5X (command > 63)
	for _, c := range []struct {
		a, cmd, tog int
		proto       string
	}{
		{0x14, 0x01, 0, "RC5"},
		{0x00, 0x40, 1, "RC5X"},
	} {
		s, err := EncodeRaw("RC5", c.a, c.cmd, EncodeOptions{Toggle: c.tog})
		if err != nil {
			t.Fatalf("EncodeRaw RC5 %d/%d: %v", c.a, c.cmd, err)
		}
		r, err := DecodeRaw(s)
		if err != nil {
			t.Fatalf("DecodeRaw(RC5 %d/%d): %v", c.a, c.cmd, err)
		}
		if r.Protocol != c.proto || r.Address != c.a || r.Command != c.cmd {
			t.Errorf("RC5 round-trip %d/%d -> %s %d/%d", c.a, c.cmd, r.Protocol, r.Address, r.Command)
		}
	}
}

func TestEncodeRawKaseikyoRoundTrip(t *testing.T) {
	// Reproduce the v0.613 Kaseikyo decode vector: Panasonic 0x2002, addr 0x123,
	// cmd 0x45 -> the kaseikyoOK timing string.
	s, err := EncodeRaw("Kaseikyo", 0x123, 0x45, EncodeOptions{Vendor: 0x2002})
	if err != nil {
		t.Fatalf("EncodeRaw Kaseikyo: %v", err)
	}
	if s != kaseikyoOK {
		t.Errorf("Kaseikyo encode != kaseikyoOK vector\n got: %s\nwant: %s", s, kaseikyoOK)
	}
	r, err := DecodeRaw(s)
	if err != nil {
		t.Fatalf("DecodeRaw(Kaseikyo): %v", err)
	}
	if r.Protocol != "Kaseikyo" || r.Vendor != 0x2002 || r.Address != 0x123 || r.Command != 0x45 || !r.ChecksumValid {
		t.Errorf("Kaseikyo round-trip -> %s vendor=0x%04X %d/%d valid=%v", r.Protocol, r.Vendor, r.Address, r.Command, r.ChecksumValid)
	}
	// default vendor (0) -> Panasonic
	s2, err := EncodeRaw("Kaseikyo", 0x123, 0x45, EncodeOptions{})
	if err != nil || s2 != s {
		t.Errorf("default vendor should be Panasonic 0x2002")
	}
}

func TestEncodeRawErrors(t *testing.T) {
	cases := []struct {
		proto  string
		a, cmd int
		opt    EncodeOptions
	}{
		{"NEC", 256, 0, EncodeOptions{}},            // address out of range
		{"NEC", 0, 999, EncodeOptions{}},            // command out of range
		{"SIRC", 0, 0, EncodeOptions{SIRCBits: 13}}, // bad width
		{"RC5", 99, 0, EncodeOptions{}},             // address > 31
		{"BOGUS", 0, 0, EncodeOptions{}},            // unknown protocol
	}
	for _, c := range cases {
		if _, err := EncodeRaw(c.proto, c.a, c.cmd, c.opt); err == nil {
			t.Errorf("EncodeRaw(%s,%d,%d,%+v) expected error", c.proto, c.a, c.cmd, c.opt)
		}
	}
}
