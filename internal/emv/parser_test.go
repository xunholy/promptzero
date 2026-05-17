package emv

import (
	"strings"
	"testing"
)

// EMV test vectors. Most come from EMVCo Books 3 + 4 worked
// examples; the FCI/AFL records are reconstructed from the on-card
// data layout in EMV Book 3 §B Annex B. The exact bytes are public
// and the same across Visa / Mastercard / EMV CCD test cards.

// TestParse_SinglePrimitive pins a single, non-constructed TLV.
// PAN tag 0x5A, length 8, value 16 hex chars (8 BCD bytes carrying
// "4012001037141112" — a Visa test PAN from EMV Co's contactless
// reference set).
func TestParse_SinglePrimitive(t *testing.T) {
	got, err := Parse("5A084012001037141112")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 top-level TLV, got %d", len(got))
	}
	if got[0].Tag != 0x5A {
		t.Errorf("Tag = 0x%X; want 0x5A", got[0].Tag)
	}
	if got[0].TagHex != "5A" {
		t.Errorf("TagHex = %q; want '5A'", got[0].TagHex)
	}
	if got[0].Name != "Application Primary Account Number (PAN)" {
		t.Errorf("Name = %q", got[0].Name)
	}
	if got[0].Constructed {
		t.Error("PAN must not be marked constructed")
	}
	if got[0].ValueHex != "4012001037141112" {
		t.Errorf("ValueHex = %q", got[0].ValueHex)
	}
	if len(got[0].Children) != 0 {
		t.Error("primitive TLV should have no children")
	}
}

// TestParse_MultiByteTag pins a 2-byte tag with a 2-byte name.
// 0x9F02 = Amount Authorised, 6 bytes BCD (= GBP 1.00 in
// "000000000100" form).
func TestParse_MultiByteTag(t *testing.T) {
	got, err := Parse("9F0206000000000100")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 TLV, got %d", len(got))
	}
	if got[0].Tag != 0x9F02 {
		t.Errorf("Tag = 0x%X; want 0x9F02", got[0].Tag)
	}
	if got[0].TagHex != "9F02" {
		t.Errorf("TagHex = %q; want '9F02'", got[0].TagHex)
	}
	if got[0].Name != "Amount Authorised" {
		t.Errorf("Name = %q", got[0].Name)
	}
	if got[0].ValueHex != "000000000100" {
		t.Errorf("ValueHex = %q", got[0].ValueHex)
	}
}

// TestParse_ConstructedTemplate pins a constructed tag (FCI
// template 0x6F) carrying a DF Name 0x84 + an FCI Proprietary
// Template 0xA5 which itself contains an Application Label 0x50.
// Two layers of nesting — verifies recursive descent.
func TestParse_ConstructedTemplate(t *testing.T) {
	// Body bytes inside 6F: 84 (1) + 07 (1) + AID (7) + A5 (1) + 0F (1) + label-block (15) = 26 = 0x1A
	// Body bytes inside A5: 50 (1) + 0D (1) + "VISA CREDIT  " (13) = 15 = 0x0F
	// 6F 1A
	//   84 07 A0000000031010                  (DF Name = Visa AID)
	//   A5 0F
	//     50 0D 56495341204352454449542020    ("VISA CREDIT  " — 13 chars)
	got, err := Parse("6F1A8407A0000000031010A50F500D56495341204352454449542020")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 top-level TLV, got %d", len(got))
	}
	fci := got[0]
	if fci.Tag != 0x6F {
		t.Fatalf("Tag = 0x%X; want 0x6F", fci.Tag)
	}
	if !fci.Constructed {
		t.Fatal("0x6F must be constructed")
	}
	if len(fci.Children) != 2 {
		t.Fatalf("expected 2 children inside FCI, got %d", len(fci.Children))
	}
	// Child 0: DF Name (AID).
	if fci.Children[0].Tag != 0x84 {
		t.Errorf("child 0 Tag = 0x%X; want 0x84", fci.Children[0].Tag)
	}
	if fci.Children[0].ValueHex != "A0000000031010" {
		t.Errorf("child 0 ValueHex = %q; want A0000000031010", fci.Children[0].ValueHex)
	}
	// Child 1: FCI Proprietary Template.
	if fci.Children[1].Tag != 0xA5 {
		t.Errorf("child 1 Tag = 0x%X; want 0xA5", fci.Children[1].Tag)
	}
	if !fci.Children[1].Constructed {
		t.Fatal("0xA5 must be constructed")
	}
	if len(fci.Children[1].Children) != 1 {
		t.Fatalf("expected 1 grandchild inside A5, got %d", len(fci.Children[1].Children))
	}
	label := fci.Children[1].Children[0]
	if label.Tag != 0x50 {
		t.Errorf("grandchild Tag = 0x%X; want 0x50", label.Tag)
	}
	if label.Name != "Application Label" {
		t.Errorf("grandchild Name = %q", label.Name)
	}
	if string(label.Value) != "VISA CREDIT  " {
		t.Errorf("grandchild Value = %q; want 'VISA CREDIT  '", string(label.Value))
	}
}

// TestParse_LongFormLength pins the 0x81/0x82/0x84 length encoding
// branch — values whose length exceeds 127 use the multi-byte form.
func TestParse_LongFormLength(t *testing.T) {
	// 0x50 (Application Label) with length 0x81 0x80 (128 bytes of
	// 0xAA filler). Constructed/primitive distinction doesn't apply
	// here — we just verify the length walker.
	body := strings.Repeat("AA", 128)
	in := "508180" + body
	got, err := Parse(in)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 || len(got[0].Value) != 128 {
		t.Fatalf("expected one TLV of len 128, got %v", got)
	}
}

// TestParse_PaddingZeroesSkipped pins the documented behaviour:
// 0x00 bytes between top-level TLVs are inter-TLV padding (some
// readers round responses to a record boundary). They get skipped.
func TestParse_PaddingZeroesSkipped(t *testing.T) {
	got, err := Parse("000050050102030405000050050A0B0C0D0E00")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 TLVs, got %d", len(got))
	}
	if got[0].ValueHex != "0102030405" || got[1].ValueHex != "0A0B0C0D0E" {
		t.Errorf("values = %q / %q; want '0102030405' / '0A0B0C0D0E'",
			got[0].ValueHex, got[1].ValueHex)
	}
}

// TestParse_OperatorSeparatorsTolerated pins the input cleaning —
// whitespace, ':', '-', '_' all stripped so pasted captures decode
// without preprocessing.
func TestParse_OperatorSeparatorsTolerated(t *testing.T) {
	cases := []string{
		"5A 08 4012 0010 3714 1112",
		"5A:08:40:12:00:10:37:14:11:12",
		"5A-08-40-12-00-10-37-14-11-12",
		"5A_08_4012001037141112",
		"  5A 08 4012001037141112  \n",
	}
	for _, in := range cases {
		got, err := Parse(in)
		if err != nil {
			t.Errorf("Parse(%q): %v", in, err)
			continue
		}
		if len(got) != 1 || got[0].Tag != 0x5A || got[0].ValueHex != "4012001037141112" {
			t.Errorf("Parse(%q) = %+v", in, got)
		}
	}
}

func TestParse_Errors(t *testing.T) {
	cases := []struct {
		in   string
		want string // substring expected in error message
	}{
		{"", "empty"},
		{"5A", "no length"}, // tag without length
		{"5A05010203", "exceeds remaining buffer"}, // length > available
		{"5A80", "indefinite-length"},              // 0x80 is forbidden in EMV
		{"5A8500", "long-form length > 4 bytes"},   // > 4-byte length forbidden
		{"5F", "truncated multi-byte tag"},         // 0x5F flags multi-byte but stream ends
		{"GGGG", "invalid hex"},                    // non-hex
		{"9F", "truncated multi-byte tag"},         // same — 0x9F starts a 2-byte tag
		{"5A0240", "exceeds remaining buffer"},     // length=2 with only 1 byte
	}
	for _, c := range cases {
		_, err := Parse(c.in)
		if err == nil {
			t.Errorf("Parse(%q) = nil; want error containing %q", c.in, c.want)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("Parse(%q) err = %v; want substring %q", c.in, err, c.want)
		}
	}
}

func TestTagName_UnknownReturnsEmpty(t *testing.T) {
	if got := TagName(0xDFAA12); got != "" {
		t.Errorf("TagName(unknown) = %q; want empty", got)
	}
	if got := TagName(0x5A); got != "Application Primary Account Number (PAN)" {
		t.Errorf("TagName(0x5A) = %q", got)
	}
}

func TestFormatTag(t *testing.T) {
	cases := map[uint32]string{
		0x5A:       "5A",
		0x9F02:     "9F02",
		0x5F2A:     "5F2A",
		0x5F1234:   "5F1234",
		0xDF010203: "DF010203",
	}
	for tag, want := range cases {
		if got := formatTag(tag); got != want {
			t.Errorf("formatTag(0x%X) = %q; want %q", tag, got, want)
		}
	}
}
