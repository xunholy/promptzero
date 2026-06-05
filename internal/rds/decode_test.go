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

func TestGroup1ProgItemAndCountry(t *testing.T) {
	// YLE Yksi (fi) 2016-09-15 — group 1A, variant 0 (ECC).
	r, err := Decode("6201 10E0 00E1 7C54", Options{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	g := r.Groups[0]
	if g.GroupType != "1A" {
		t.Fatalf("group type = %s, want 1A", g.GroupType)
	}
	if g.ProgItemNumber == nil || *g.ProgItemNumber != 31828 {
		t.Errorf("prog_item_number = %v, want 31828", g.ProgItemNumber)
	}
	if g.ProgItemDay == nil || *g.ProgItemDay != 15 {
		t.Errorf("prog_item_day = %v, want 15", g.ProgItemDay)
	}
	if g.ProgItemTime != "17:20" {
		t.Errorf("prog_item_time = %q, want 17:20", g.ProgItemTime)
	}
	if g.ECC != "0xE1" {
		t.Errorf("ECC = %q, want 0xE1", g.ECC)
	}
	if g.CountryCodeNibble == nil || *g.CountryCodeNibble != 6 {
		t.Errorf("country nibble = %v, want 6", g.CountryCodeNibble)
	}
}

func TestGroup1Language(t *testing.T) {
	// Group 1A, variant 3 — language code 0x27 = Finnish.
	r, err := Decode("6201 10E0 3027 7C54", Options{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Groups[0].Language != "Finnish" {
		t.Errorf("language = %q, want Finnish", r.Groups[0].Language)
	}
}

func TestGroup1SLCBroadcasterBits(t *testing.T) {
	// RTL 102.5 (it) — group 1A, variant 6.
	r, err := Decode("5218 1520 6DAB 0000", Options{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Groups[0].SLCBroadcasterBits != "0x5AB" {
		t.Errorf("slc_broadcaster_bits = %q, want 0x5AB", r.Groups[0].SLCBroadcasterBits)
	}
}

func TestProgrammeTypeName(t *testing.T) {
	// CRI Poland 2019-05-04 — group 10A PTYN "CRI.CN " (trailing space kept).
	in := "3ABC A750 4352 492E  3ABC A751 434E 0D0D"
	r, err := Decode(in, Options{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProgrammeTypeName != "CRI.CN " {
		t.Errorf("programme_type_name = %q, want %q", r.ProgrammeTypeName, "CRI.CN ")
	}
}

func TestAlternativeFrequenciesMethodA(t *testing.T) {
	// YLE Yksi (fi) — group 0A AF Method A. redsea expects the flat list
	// {87900, 90900, 89800, 89200, 93200, 88500, 89500} kHz; the leading
	// 0xE7 (231) code is the "7 alternative frequencies follow" count.
	in := "6201 00F7 E704 5349  6201 00F0 2217 594C  " +
		"6201 00F1 1139 4520  6201 00F2 0A14 594B"
	r, err := Decode(in, Options{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	want := []int{87900, 90900, 89800, 89200, 93200, 88500, 89500}
	if len(r.AltFrequenciesKHz) != len(want) {
		t.Fatalf("AF = %v, want %v", r.AltFrequenciesKHz, want)
	}
	for i := range want {
		if r.AltFrequenciesKHz[i] != want[i] {
			t.Errorf("AF[%d] = %d, want %d", i, r.AltFrequenciesKHz[i], want[i])
		}
	}
	if r.AFCount == nil || *r.AFCount != 7 {
		t.Errorf("af_count = %v, want 7", r.AFCount)
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
