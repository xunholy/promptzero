// SPDX-License-Identifier: AGPL-3.0-or-later

package rds

import (
	"strings"
	"testing"
)

// The vectors are taken from the redsea reference test suite
// (test/components-hex.cc): each group is four 16-bit blocks
// (A'B'C'D), and the expected Programme Service / RadioText / call sign
// strings are redsea's own CHECK() assertions.

func TestProgrammeServiceYLE(t *testing.T) {
	// PI 0x6204, group 0A, PTY "Varied", TP false, TA true, PS "YLE X3M ".
	in := "6204 0130 966B 594C  6204 0131 93CD 4520  6204 0132 E472 5833  6204 0137 966B 4D20"
	r, err := Decode(in, Options{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProgrammeService != "YLE X3M" { // trailing blank trimmed
		t.Errorf("PS = %q, want %q", r.ProgrammeService, "YLE X3M")
	}
	if r.PI != "0x6204" {
		t.Errorf("PI = %q, want 0x6204", r.PI)
	}
	g0 := r.Groups[0]
	if g0.GroupType != "0A" || g0.PTYName != "Varied" || g0.TP {
		t.Errorf("group0 = %+v, want 0A/Varied/TP=false", g0)
	}
	if g0.TA == nil || !*g0.TA {
		t.Errorf("TA = %v, want true", g0.TA)
	}
}

func TestProgrammeServiceKRKA(t *testing.T) {
	in := "9423 0800 0000 2020  9423 0801 0000 4B52  9423 0802 0000 4B41  9423 0807 0000 2020"
	r, err := Decode(in, Options{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// "  KRKA  " — leading blanks kept, trailing trimmed.
	if r.ProgrammeService != "  KRKA" {
		t.Errorf("PS = %q, want %q", r.ProgrammeService, "  KRKA")
	}
}

func TestRadioTextJACK(t *testing.T) {
	in := "C954 24F0 4A41 434B  C954 24F1 2039 362E  C954 24F2 390D 0000"
	r, err := Decode(in, Options{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RadioText != "JACK 96.9" {
		t.Errorf("RadioText = %q, want %q", r.RadioText, "JACK 96.9")
	}
}

func TestRadioTextRobbieWilliams(t *testing.T) {
	in := "A540 2540 526F 6262  A540 2541 6965 2057  A540 2542 696C 6C69  " +
		"A540 2543 616D 7320  A540 2544 2D20 4665  A540 2545 656C 2020"
	r, err := Decode(in, Options{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RadioText != "Robbie Williams - Feel" {
		t.Errorf("RadioText = %q, want %q", r.RadioText, "Robbie Williams - Feel")
	}
}

// TestRadioTextCharset exercises the G0 charset (0x91 -> ä).
func TestRadioTextCharset(t *testing.T) {
	in := "6205 2440 5665 6761  6205 2441 204B 7691  6205 2442 6C6C 2020"
	r, err := Decode(in, Options{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RadioText != "Vega Kväll" {
		t.Errorf("RadioText = %q, want %q", r.RadioText, "Vega Kväll")
	}
}

func TestRBDSCallsign(t *testing.T) {
	r, err := Decode("4569 00C8 CDCD 416E", Options{RBDS: true})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Callsign != "KUFX" {
		t.Errorf("callsign = %q, want KUFX", r.Callsign)
	}
	// Without RBDS, no call sign is emitted.
	r2, _ := Decode("4569 00C8 CDCD 416E", Options{})
	if r2.Callsign != "" {
		t.Errorf("non-RBDS callsign = %q, want empty", r2.Callsign)
	}
}

func TestPTYTablesDiffer(t *testing.T) {
	// PTY 5: RDS "Education" vs RBDS "Rock".
	if ptyName(5, false) != "Education" || ptyName(5, true) != "Rock" {
		t.Errorf("PTY 5 = %q / %q", ptyName(5, false), ptyName(5, true))
	}
}

func TestDecodeRejectsBadLength(t *testing.T) {
	if _, err := Decode("6204 0130 966B", Options{}); err == nil {
		t.Error("expected error for non-16-hex group")
	}
	if _, err := Decode("", Options{}); err == nil {
		t.Error("expected error for empty input")
	}
}

// TestHexFormats confirms the redsea 0x...'...' form and plain hex both parse.
func TestHexFormats(t *testing.T) {
	a, err := Decode("0x6204'0130'966B'594C", Options{})
	if err != nil {
		t.Fatalf("apostrophe form: %v", err)
	}
	b, err := Decode("62040130966B594C", Options{})
	if err != nil {
		t.Fatalf("plain form: %v", err)
	}
	if a.Groups[0].BlocksHex != b.Groups[0].BlocksHex || !strings.HasPrefix(a.PI, "0x6204") {
		t.Errorf("format mismatch: %q vs %q", a.Groups[0].BlocksHex, b.Groups[0].BlocksHex)
	}
}

// FuzzDecode asserts the parser never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	f.Add("6204013 0966B594C")
	f.Add("C95424F04A41434B")
	f.Add("")
	f.Add("zzzz")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s, Options{})
		_, _ = Decode(s, Options{RBDS: true})
	})
}
