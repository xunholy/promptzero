// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// TestEncode_HandVectors pins exact bytes built from TLV structs, the
// external anchor independent of Parse.
func TestEncode_HandVectors(t *testing.T) {
	// Primitive 5A, value 12 34 56 78 → "5A 04 12345678".
	if b, _ := Encode([]TLV{{Tag: 0x5A, Value: []byte{0x12, 0x34, 0x56, 0x78}}}); strings.ToUpper(hex.EncodeToString(b)) != "5A0412345678" {
		t.Errorf("primitive 5A = %X, want 5A0412345678", b)
	}
	// Multi-byte tag 9F02 (Amount), value 00 00 00 00 10 00.
	if b, _ := Encode([]TLV{{Tag: 0x9F02, Value: []byte{0, 0, 0, 0, 0x10, 0}}}); strings.ToUpper(hex.EncodeToString(b)) != "9F0206000000001000" {
		t.Errorf("9F02 = %X, want 9F0206000000001000", b)
	}
	// Constructed 70 { 9F02 = 05 } → inner 9F020105 (4 bytes) → 70 04 9F020105.
	if b, _ := Encode([]TLV{{Tag: 0x70, Constructed: true, Children: []TLV{{Tag: 0x9F02, Value: []byte{0x05}}}}}); strings.ToUpper(hex.EncodeToString(b)) != "70049F020105" {
		t.Errorf("constructed 70 = %X, want 70049F020105", b)
	}
}

// TestEncode_ParseRoundTrip parses minimally-encoded blobs and re-encodes
// them, expecting the original bytes back (the inverse property).
func TestEncode_ParseRoundTrip(t *testing.T) {
	blobs := []string{
		"5A081234567890123456",                   // primitive PAN
		"9F0206000000001000",                     // multi-byte tag
		"5A0812345678901234569F0206000000001000", // two flat TLVs
	}
	for _, in := range blobs {
		tlvs, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%s): %v", in, err)
		}
		b, err := Encode(tlvs)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if got := strings.ToUpper(hex.EncodeToString(b)); got != strings.ToUpper(in) {
			t.Errorf("round-trip:\n got=%s\nwant=%s", got, in)
		}
	}
}

// TestEncode_Idempotent builds a nested tree (incl. a long-form length),
// encodes it, parses it back, and re-encodes — the two encodings must be
// byte-identical, and Parse must recover the structure.
func TestEncode_Idempotent(t *testing.T) {
	tree := []TLV{
		{Tag: 0x70, Constructed: true, Children: []TLV{
			{Tag: 0x57, Value: []byte{0x12, 0x34, 0x56, 0x78, 0x90}}, // track2-ish
			{Tag: 0x5A, Value: make([]byte, 130)},                    // forces long-form length
			{Tag: 0x9F1A, Value: []byte{0x08, 0x40}},                 // country code
		}},
	}
	b1, err := Encode(tree)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parsed, err := Parse(strings.ToUpper(hex.EncodeToString(b1)))
	if err != nil {
		t.Fatalf("Parse(encoded): %v", err)
	}
	b2, err := Encode(parsed)
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !reflect.DeepEqual(b1, b2) {
		t.Errorf("Encode→Parse→Encode not idempotent:\n%X\n%X", b1, b2)
	}
	// Structure recovered: one constructed 70 with three children.
	if len(parsed) != 1 || !parsed[0].Constructed || len(parsed[0].Children) != 3 {
		t.Errorf("parsed structure = %+v", parsed)
	}
}

func TestEncode_RejectsZeroTag(t *testing.T) {
	if _, err := Encode([]TLV{{Tag: 0, Value: []byte{1}}}); err == nil {
		t.Error("expected error for zero tag")
	}
}
