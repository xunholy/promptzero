// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import "testing"

// TestDecodeAFL_HandVector decodes a two-entry AFL. SFI = byte>>3 is
// hand-checkable: 0x08>>3 = 1, 0x10>>3 = 2.
func TestDecodeAFL_HandVector(t *testing.T) {
	afl, err := DecodeAFLHex("08010100 10010401")
	if err != nil {
		t.Fatal(err)
	}
	if len(afl.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(afl.Entries))
	}
	e0, e1 := afl.Entries[0], afl.Entries[1]
	if e0.SFI != 1 || e0.FirstRecord != 1 || e0.LastRecord != 1 || e0.ODARecords != 0 {
		t.Errorf("entry0 = %+v, want SFI1 rec1-1 oda0", e0)
	}
	if e1.SFI != 2 || e1.FirstRecord != 1 || e1.LastRecord != 4 || e1.ODARecords != 1 {
		t.Errorf("entry1 = %+v, want SFI2 rec1-4 oda1", e1)
	}
	// Total records: 1 (SFI1) + 4 (SFI2) = 5.
	if afl.TotalRecords != 5 {
		t.Errorf("total records = %d, want 5", afl.TotalRecords)
	}
	if len(afl.ReadRecords) != 5 {
		t.Fatalf("read records = %d, want 5", len(afl.ReadRecords))
	}
	// The expanded READ RECORD list must start (SFI1,1) then (SFI2,1..4).
	want := []ReadRecord{{1, 1}, {2, 1}, {2, 2}, {2, 3}, {2, 4}}
	for i, w := range want {
		if afl.ReadRecords[i] != w {
			t.Errorf("read record %d = %+v, want %+v", i, afl.ReadRecords[i], w)
		}
	}
}

func TestDecodeAFL_SingleEntry(t *testing.T) {
	// SFI 2 (0x10>>3), records 1-3, all 3 used for ODA.
	afl, err := DecodeAFLHex("10010303")
	if err != nil {
		t.Fatal(err)
	}
	e := afl.Entries[0]
	if e.SFI != 2 || e.FirstRecord != 1 || e.LastRecord != 3 || e.ODARecords != 3 {
		t.Errorf("entry = %+v, want SFI2 rec1-3 oda3", e)
	}
	if len(e.Records) != 3 || e.Records[2] != 3 {
		t.Errorf("records = %v, want [1 2 3]", e.Records)
	}
}

func TestDecodeAFL_Errors(t *testing.T) {
	bad := []string{
		"",         // empty
		"080101",   // not a multiple of 4
		"00010100", // SFI 0 (byte 0x00>>3 = 0) out of range
		"F8010100", // SFI 31 (0xF8>>3) out of range
		"08000100", // first record 0
		"08040100", // last (1) < first (4)
		"08010104", // ODA count 4 > range (1)
		"09010100", // low 3 bits of SFI byte non-zero
	}
	for i, s := range bad {
		if _, err := DecodeAFLHex(s); err == nil {
			t.Errorf("case %d (%q): expected error", i, s)
		}
	}
}

// TestDecodeAFL_RoundTrip builds AFL bytes from fields and confirms recovery
// across SFIs and record ranges.
func TestDecodeAFL_RoundTrip(t *testing.T) {
	cases := []struct {
		sfi, first, last, oda int
	}{
		{1, 1, 1, 0},
		{2, 1, 4, 2},
		{11, 1, 2, 0},
		{30, 5, 9, 1},
	}
	for _, c := range cases {
		raw := []byte{byte(c.sfi << 3), byte(c.first), byte(c.last), byte(c.oda)}
		afl, err := DecodeAFL(raw)
		if err != nil {
			t.Fatalf("sfi %d: %v", c.sfi, err)
		}
		e := afl.Entries[0]
		if e.SFI != c.sfi || e.FirstRecord != c.first || e.LastRecord != c.last || e.ODARecords != c.oda {
			t.Errorf("sfi %d: got %+v", c.sfi, e)
		}
	}
}
