package ndef

import (
	"strings"
	"testing"
)

// TestDecode_URIRecord_HTTPS pins the canonical NFC Forum
// worked example: a single URI record with prefix 0x04
// (https://) and tail "example.com".
//
// Wire bytes:
//
//	D1     header (MB=1 ME=1 SR=1 IL=0 TNF=1)
//	01     type length = 1
//	0C     payload length = 12 (1-byte prefix + 11-byte tail)
//	55     type = "U"
//	04     URI prefix code (https://)
//	"example.com"
func TestDecode_URIRecord_HTTPS(t *testing.T) {
	// "example.com" = 65 78 61 6D 70 6C 65 2E 63 6F 6D
	got, err := Decode("D1 01 0C 55 04 65 78 61 6D 70 6C 65 2E 63 6F 6D")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Count != 1 {
		t.Fatalf("Count = %d; want 1", got.Count)
	}
	r := got.Records[0]
	if !r.MessageBegin || !r.MessageEnd {
		t.Errorf("MB / ME = %v / %v; want both true", r.MessageBegin, r.MessageEnd)
	}
	if !r.ShortRecord {
		t.Error("ShortRecord should be true")
	}
	if r.TNF != int(TNFWellKnown) || r.TNFName != "Well-Known" {
		t.Errorf("TNF = %d (%q); want 1 (Well-Known)", r.TNF, r.TNFName)
	}
	if r.Type != "U" {
		t.Errorf("Type = %q; want 'U'", r.Type)
	}
	if r.Decoded["uri"] != "https://example.com" {
		t.Errorf("uri = %v; want 'https://example.com'", r.Decoded["uri"])
	}
	if r.Decoded["prefix_code"] != 0x04 {
		t.Errorf("prefix_code = %v; want 0x04", r.Decoded["prefix_code"])
	}
}

// TestDecode_URIRecord_EveryPrefix walks a handful of prefix
// codes from the 36-entry NFC Forum table to confirm they're
// looked up correctly.
func TestDecode_URIRecord_EveryPrefix(t *testing.T) {
	cases := []struct {
		code byte
		want string
	}{
		{0x00, ""}, // no prefix
		{0x01, "http://www."},
		{0x05, "tel:"},
		{0x06, "mailto:"},
		{0x13, "urn:"},
		{0x1D, "file://"},
		{0x23, "urn:nfc:"},
	}
	for _, c := range cases {
		// Single URI record with no tail (just the prefix).
		// D1 01 01 55 <prefix>
		hex := []byte("D101015500")
		hex[8] = "0123456789ABCDEF"[c.code>>4]
		hex[9] = "0123456789ABCDEF"[c.code&0x0F]
		got, err := Decode(string(hex))
		if err != nil {
			t.Errorf("Decode(prefix=%02X): %v", c.code, err)
			continue
		}
		if got.Records[0].Decoded["prefix"] != c.want {
			t.Errorf("prefix code 0x%02X → %v; want %q",
				c.code, got.Records[0].Decoded["prefix"], c.want)
		}
	}
}

// TestDecode_URIRecord_OutOfRangePrefix surfaces a warning when
// the prefix code is outside the documented 0x00-0x23 range.
func TestDecode_URIRecord_OutOfRangePrefix(t *testing.T) {
	// D1 01 02 55 FF 41 — prefix 0xFF (invalid), tail "A"
	got, err := Decode("D1 01 02 55 FF 41")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	r := got.Records[0]
	if _, ok := r.Decoded["warning"].(string); !ok {
		t.Errorf("expected warning for invalid prefix code; got %v", r.Decoded["warning"])
	}
}

// TestDecode_TextRecord_UTF8 pins a Text record carrying "hello"
// in English (lang="en", UTF-8 encoding).
//
// Status byte: bit 7=0 (UTF-8), bits 5-0=0x02 (lang length = 2)
// = 0x02. Payload: 02 65 6E 68 65 6C 6C 6F (status + "en" +
// "hello").
func TestDecode_TextRecord_UTF8(t *testing.T) {
	// D1 01 08 54 02 65 6E 68 65 6C 6C 6F
	got, err := Decode("D1 01 08 54 02 65 6E 68 65 6C 6C 6F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	r := got.Records[0]
	if r.Type != "T" {
		t.Errorf("Type = %q; want 'T'", r.Type)
	}
	if r.Decoded["text"] != "hello" {
		t.Errorf("text = %v; want 'hello'", r.Decoded["text"])
	}
	if r.Decoded["language"] != "en" {
		t.Errorf("language = %v; want 'en'", r.Decoded["language"])
	}
	if r.Decoded["encoding"] != "UTF-8" {
		t.Errorf("encoding = %v; want 'UTF-8'", r.Decoded["encoding"])
	}
}

// TestDecode_TextRecord_UTF16 pins a UTF-16 BE Text record
// carrying "AB" in English (lang="en"). Status = 0x82 (UTF-16 +
// lang length 2). Payload: 82 65 6E [00 41 00 42].
func TestDecode_TextRecord_UTF16(t *testing.T) {
	got, err := Decode("D1 01 07 54 82 65 6E 00 41 00 42")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	r := got.Records[0]
	if r.Decoded["encoding"] != "UTF-16" {
		t.Errorf("encoding = %v; want 'UTF-16'", r.Decoded["encoding"])
	}
	if r.Decoded["text"] != "AB" {
		t.Errorf("text = %v; want 'AB'", r.Decoded["text"])
	}
}

// TestDecode_MultipleRecords walks an NDEF message with two
// records — URI (with MB=1) and Text (with ME=1).
func TestDecode_MultipleRecords(t *testing.T) {
	// Record 1: 91 01 0C 55 04 example.com (MB=1, ME=0, SR=1)
	// Record 2: 51 01 08 54 02 65 6E "hello" (MB=0, ME=1, SR=1)
	got, err := Decode("91 01 0C 55 04 6578616D706C652E636F6D" +
		"51 01 08 54 02 65 6E 68656C6C6F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Count != 2 {
		t.Fatalf("Count = %d; want 2", got.Count)
	}
	if !got.Records[0].MessageBegin || got.Records[0].MessageEnd {
		t.Errorf("Records[0]: MB=%v ME=%v; want true, false",
			got.Records[0].MessageBegin, got.Records[0].MessageEnd)
	}
	if got.Records[1].MessageBegin || !got.Records[1].MessageEnd {
		t.Errorf("Records[1]: MB=%v ME=%v; want false, true",
			got.Records[1].MessageBegin, got.Records[1].MessageEnd)
	}
	if got.Records[0].Type != "U" || got.Records[1].Type != "T" {
		t.Errorf("types = %q, %q; want 'U', 'T'", got.Records[0].Type, got.Records[1].Type)
	}
}

// TestDecode_MIMERecord parses a MIME-type record (TNF=2). The
// payload semantics are vendor-defined; we surface the
// MIME-type field + payload size.
func TestDecode_MIMERecord(t *testing.T) {
	// Header: D2 (MB=1 ME=1 SR=1 IL=0 TNF=2)
	// Type length 10, payload length 5
	// Type: "text/plain"  (74 65 78 74 2F 70 6C 61 69 6E)
	// Payload: "hello" (68 65 6C 6C 6F)
	got, err := Decode("D2 0A 05 746578742F706C61696E 68656C6C6F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	r := got.Records[0]
	if r.TNF != int(TNFMIME) {
		t.Errorf("TNF = %d; want 2 (MIME)", r.TNF)
	}
	if r.Type != "text/plain" {
		t.Errorf("Type = %q; want 'text/plain'", r.Type)
	}
	if r.Decoded["mime_type"] != "text/plain" {
		t.Errorf("mime_type = %v", r.Decoded["mime_type"])
	}
	if r.Decoded["payload_size"] != 5 {
		t.Errorf("payload_size = %v; want 5", r.Decoded["payload_size"])
	}
}

// TestDecode_LongRecord exercises the non-short-record path
// (SR=0; payload length is 4 bytes big-endian, not 1 byte).
func TestDecode_LongRecord(t *testing.T) {
	// Header: C1 (MB=1 ME=1 SR=0 IL=0 TNF=1)
	// Type length 1, payload length (4 bytes BE) = 12
	// Type: U; URI prefix 0x04 + "example.com"
	got, err := Decode("C1 01 0000000C 55 04 6578616D706C652E636F6D")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	r := got.Records[0]
	if r.ShortRecord {
		t.Error("ShortRecord should be false for long-record header")
	}
	if r.Decoded["uri"] != "https://example.com" {
		t.Errorf("uri = %v", r.Decoded["uri"])
	}
}

// TestDecode_IDLength exercises the IL=1 path (ID-length byte
// present + ID bytes consumed).
func TestDecode_IDLength(t *testing.T) {
	// Header: D9 (MB=1 ME=1 SR=1 IL=1 TNF=1)
	// Type len 1, payload len 1, ID len 2
	// Type: U; ID: "AB" (41 42); payload: 00 (no prefix, empty URI)
	got, err := Decode("D9 01 01 02 55 41 42 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	r := got.Records[0]
	if !r.IDLength {
		t.Error("IDLength should be true")
	}
	if r.ID != "AB" {
		t.Errorf("ID = %q; want 'AB'", r.ID)
	}
}

// TestDecode_SmartPosterRecursive — a Smart Poster contains a
// nested NDEF message with a URI + Text record. Confirms the
// recursive walker decodes the nested records.
func TestDecode_SmartPosterRecursive(t *testing.T) {
	// Inner message: 91 01 0C 55 04 example.com 51 01 08 54 02 65 6E hello
	// Inner bytes (33 = 0x21): 91 01 0C 55 04 6578616D706C652E636F6D 51 01 08 54 02 65 6E 68656C6C6F
	//   That's: 1+1+1+1+1+11=16 for URI + 1+1+1+1+1+2+5=12 for Text = 28 bytes total
	// Outer Smart Poster: D1 02 1C 5370 <28-byte inner>
	const inner = "91010C5504" + "6578616D706C652E636F6D" + "5101085402656E" + "68656C6C6F"
	const outer = "D1 02 1C 5370 " + inner
	got, err := Decode(outer)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	r := got.Records[0]
	if r.Type != "Sp" {
		t.Errorf("Type = %q; want 'Sp'", r.Type)
	}
	nested, ok := r.Decoded["nested"].(Message)
	if !ok {
		t.Fatalf("nested missing or wrong type: %T", r.Decoded["nested"])
	}
	if nested.Count != 2 {
		t.Errorf("nested.Count = %d; want 2", nested.Count)
	}
	if nested.Records[0].Decoded["uri"] != "https://example.com" {
		t.Errorf("nested URI = %v", nested.Records[0].Decoded["uri"])
	}
	if nested.Records[1].Decoded["text"] != "hello" {
		t.Errorf("nested text = %v", nested.Records[1].Decoded["text"])
	}
}

// TestDecode_TruncatedHeader returns operator-facing errors when
// the header field lengths declare more bytes than the buffer
// holds.
func TestDecode_TruncatedHeader(t *testing.T) {
	// Header says payload length 100 but only 2 bytes follow.
	_, err := Decode("D1 01 64 55 04 41")
	if err == nil {
		t.Fatal("want error for truncated payload")
	}
	if !strings.Contains(err.Error(), "exceed") {
		t.Errorf("error = %q; want 'exceed' wording", err.Error())
	}
}

// TestDecode_EmptyAndInvalidHex — input validation.
func TestDecode_BadInput(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecode_NoMBOnFirstRecordWarns surfaces a warning when the
// first record's MB flag is not set (malformed or
// partial-buffer input).
func TestDecode_NoMBOnFirstRecordWarns(t *testing.T) {
	// 51 = MB=0 ME=1 SR=1 IL=0 TNF=1
	got, err := Decode("51 01 0C 55 04 6578616D706C652E636F6D")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.Warnings) == 0 {
		t.Error("expected MB-missing warning")
	}
}

// TestDecode_ToleratesSeparators — ':' / '-' / '_' / whitespace
// all stripped.
func TestDecode_ToleratesSeparators(t *testing.T) {
	for _, in := range []string{
		"D1:01:0C:55:04:65:78:61:6D:70:6C:65:2E:63:6F:6D",
		"D1-01-0C-55-04-65-78-61-6D-70-6C-65-2E-63-6F-6D",
		"  D1 01 0C 55 04 65 78 61 6D 70 6C 65 2E 63 6F 6D  ",
	} {
		got, err := Decode(in)
		if err != nil {
			t.Errorf("Decode(%q): %v", in, err)
			continue
		}
		if got.Records[0].Decoded["uri"] != "https://example.com" {
			t.Errorf("Decode(%q): uri = %v", in, got.Records[0].Decoded["uri"])
		}
	}
}

// TestTNFNames pins the human-readable names for every TNF code.
func TestTNFNames(t *testing.T) {
	cases := map[TNF]string{
		TNFEmpty:       "Empty",
		TNFWellKnown:   "Well-Known",
		TNFMIME:        "MIME",
		TNFAbsoluteURI: "Absolute URI",
		TNFExternal:    "External",
		TNFUnknown:     "Unknown",
		TNFUnchanged:   "Unchanged",
		TNFReserved:    "Reserved",
	}
	for tnf, want := range cases {
		if got := tnf.String(); got != want {
			t.Errorf("TNF(%d).String() = %q; want %q", tnf, got, want)
		}
	}
}
