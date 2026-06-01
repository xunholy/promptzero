// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import "testing"

// TestDecodeDOL_VisaPDOL decodes the canonical Visa PDOL. Each (tag, length)
// pair is hand-verifiable; the lengths sum to the 33-byte GPO command data.
func TestDecodeDOL_VisaPDOL(t *testing.T) {
	// 9F66/04 9F02/06 9F03/06 9F1A/02 95/05 5F2A/02 9A/03 9C/01 9F37/04
	dol, err := DecodeDOLHex("9F66049F02069F03069F1A0295055F2A029A039C019F3704")
	if err != nil {
		t.Fatal(err)
	}
	if dol.Count != 9 {
		t.Fatalf("count = %d, want 9", dol.Count)
	}
	if dol.TotalLength != 33 {
		t.Errorf("total length = %d, want 33", dol.TotalLength)
	}
	want := []struct {
		tagHex string
		length int
	}{
		{"9F66", 4}, {"9F02", 6}, {"9F03", 6}, {"9F1A", 2}, {"95", 5},
		{"5F2A", 2}, {"9A", 3}, {"9C", 1}, {"9F37", 4},
	}
	for i, w := range want {
		if dol.Entries[i].TagHex != w.tagHex || dol.Entries[i].Length != w.length {
			t.Errorf("entry %d = %s/%d, want %s/%d", i, dol.Entries[i].TagHex, dol.Entries[i].Length, w.tagHex, w.length)
		}
	}
	// Amount Authorised (9F02) is in the curated tag table — its name must resolve.
	if dol.Entries[1].Name == "" {
		t.Error("9F02 should resolve to a tag name from the curated table")
	}
}

// TestDecodeDOL_RoundTrip builds a DOL from (tag,length) pairs and confirms
// the decoder recovers the entries and the total length.
func TestDecodeDOL_RoundTrip(t *testing.T) {
	// CDOL1-style list with single- and multi-byte tags, 1-byte lengths.
	raw := []byte{
		0x9F, 0x02, 0x06, // Amount Authorised, 6
		0x9F, 0x03, 0x06, // Amount Other, 6
		0x9C, 0x01, // Transaction Type, 1
		0x9F, 0x37, 0x04, // Unpredictable Number, 4
	}
	dol, err := DecodeDOL(raw)
	if err != nil {
		t.Fatal(err)
	}
	if dol.Count != 4 || dol.TotalLength != 17 {
		t.Fatalf("count/total = %d/%d, want 4/17", dol.Count, dol.TotalLength)
	}
	if dol.Entries[0].Tag != 0x9F02 || dol.Entries[3].Tag != 0x9F37 {
		t.Errorf("tags = %X..%X, want 9F02..9F37", dol.Entries[0].Tag, dol.Entries[3].Tag)
	}
}

func TestDecodeDOL_LongFormLength(t *testing.T) {
	// A tag requesting 0x81 0x80 = 128 bytes (long-form length).
	dol, err := DecodeDOL([]byte{0x9F, 0x02, 0x81, 0x80})
	if err != nil {
		t.Fatal(err)
	}
	if dol.Count != 1 || dol.TotalLength != 128 {
		t.Errorf("count/total = %d/%d, want 1/128", dol.Count, dol.TotalLength)
	}
}

func TestDecodeDOL_Errors(t *testing.T) {
	bad := [][]byte{
		{},           // empty
		{0x9F, 0x02}, // tag with no length byte
		{0x9F},       // truncated multi-byte tag
		{0x9F, 0x82}, // multi-byte tag continuation (0x82 high bit set) runs off the end
	}
	for i, b := range bad {
		if _, err := DecodeDOL(b); err == nil {
			t.Errorf("case %d (%X): expected error", i, b)
		}
	}
}

func TestIsDOLTag(t *testing.T) {
	for _, tag := range []uint32{0x9F38, 0x8C, 0x8D, 0x9F49, 0x97} {
		if !IsDOLTag(tag) {
			t.Errorf("%X should be a DOL tag", tag)
		}
	}
	for _, tag := range []uint32{0x57, 0x5A, 0x9F02, 0x82} {
		if IsDOLTag(tag) {
			t.Errorf("%X should not be a DOL tag", tag)
		}
	}
}
