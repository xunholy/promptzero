// SPDX-License-Identifier: AGPL-3.0-or-later

package ndef

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestEncode_RoundTrip is the primary check: a message built by Encode must
// decode back to the same records via the independent Decode path, with the
// MB/ME flags and well-known field decodes intact.
func TestEncode_RoundTrip(t *testing.T) {
	recs := []EncodeRecord{
		{Kind: "uri", URI: "https://example.com/p?x=1"},
		{Kind: "text", Text: "hello pager", Lang: "en"},
		{Kind: "uri", URI: "tel:+15551234567"},
	}
	b, err := Encode(recs)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	msg, err := DecodeBytes(b)
	if err != nil {
		t.Fatalf("DecodeBytes(%X): %v", b, err)
	}
	if msg.Count != 3 {
		t.Fatalf("decoded %d records, want 3", msg.Count)
	}
	if !msg.Records[0].MessageBegin {
		t.Error("first record missing MB")
	}
	if !msg.Records[2].MessageEnd {
		t.Error("last record missing ME")
	}
	if got := msg.Records[0].Decoded["uri"]; got != recs[0].URI {
		t.Errorf("URI[0] round-trips to %v, want %q", got, recs[0].URI)
	}
	if got := msg.Records[1].Decoded["text"]; got != recs[1].Text {
		t.Errorf("text round-trips to %v, want %q", got, recs[1].Text)
	}
	if got := msg.Records[1].Decoded["language"]; got != "en" {
		t.Errorf("lang round-trips to %v, want en", got)
	}
	if got := msg.Records[2].Decoded["uri"]; got != recs[2].URI {
		t.Errorf("URI[2] round-trips to %v, want %q", got, recs[2].URI)
	}
}

// TestEncode_URIFixedBytes hand-verifies the exact bytes for a single URI
// record against the canonical NDEF shape: header 0xD1 (MB+ME+SR, TNF=1),
// type-length 1, payload-length, type 'U', prefix code 0x04 (https://),
// then the tail.
func TestEncode_URIFixedBytes(t *testing.T) {
	b, err := Encode([]EncodeRecord{{Kind: "uri", URI: "https://example.com"}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// D1 01 0C 55 04 + "example.com"
	want := "D1010C5504" + strings.ToUpper(hex.EncodeToString([]byte("example.com")))
	if got := strings.ToUpper(hex.EncodeToString(b)); got != want {
		t.Errorf("encoded = %s, want %s", got, want)
	}
}

// TestEncode_LongestPrefix confirms the abbreviation picks the longest
// matching prefix (https://www. = 0x02, not https:// = 0x04).
func TestEncode_LongestPrefix(t *testing.T) {
	b, err := Encode([]EncodeRecord{{Kind: "uri", URI: "https://www.foo.com"}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// payload starts after header(1)+typelen(1)+payloadlen(1)+type(1) = byte 4
	if b[4] != 0x02 {
		t.Errorf("prefix code = 0x%02X, want 0x02 (https://www.)", b[4])
	}
	msg, _ := DecodeBytes(b)
	if got := msg.Records[0].Decoded["uri"]; got != "https://www.foo.com" {
		t.Errorf("round-trip uri = %v", got)
	}
}

// TestEncode_SmartPosterRoundTrip builds a Smart Poster (URI + title +
// action) and confirms Decode recovers it as an "Sp" record whose nested
// message carries the URI and title.
func TestEncode_SmartPosterRoundTrip(t *testing.T) {
	b, err := Encode([]EncodeRecord{{
		Kind: "smartposter", URI: "https://example.com/promo", Text: "Tap me", Lang: "en", Action: "do",
	}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	msg, err := DecodeBytes(b)
	if err != nil {
		t.Fatalf("DecodeBytes(%X): %v", b, err)
	}
	if msg.Count != 1 || msg.Records[0].Type != "Sp" {
		t.Fatalf("outer record = %+v, want one Sp record", msg.Records)
	}
	nested, ok := msg.Records[0].Decoded["nested"].(Message)
	if !ok {
		t.Fatalf("Sp Decoded has no nested Message: %+v", msg.Records[0].Decoded)
	}
	var gotURI, gotTitle any
	for _, r := range nested.Records {
		switch r.Type {
		case "U":
			gotURI = r.Decoded["uri"]
		case "T":
			gotTitle = r.Decoded["text"]
		}
	}
	if gotURI != "https://example.com/promo" {
		t.Errorf("nested URI = %v, want https://example.com/promo", gotURI)
	}
	if gotTitle != "Tap me" {
		t.Errorf("nested title = %v, want 'Tap me'", gotTitle)
	}
}

func TestEncode_SmartPosterRejectsBad(t *testing.T) {
	if _, err := Encode([]EncodeRecord{{Kind: "smartposter", Text: "no uri"}}); err == nil {
		t.Error("expected error: smartposter without uri")
	}
	if _, err := Encode([]EncodeRecord{{Kind: "smartposter", URI: "x", Action: "bogus"}}); err == nil {
		t.Error("expected error: invalid action")
	}
}

// TestEncode_MIMEAndExternalRoundTrip builds a MIME record and an External
// record (an Android Application Record) and confirms Decode recovers their
// TNF, type, and payload.
func TestEncode_MIMEAndExternalRoundTrip(t *testing.T) {
	b, err := Encode([]EncodeRecord{
		{Kind: "mime", Type: "text/vcard", Text: "BEGIN:VCARD\nEND:VCARD"},
		{Kind: "external", Type: "android.com:pkg", Text: "com.evil.app"},
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// First record (MIME, TNF 2) gets MB+SR (not ME): 0x80|0x10|0x02 = 0x92.
	if b[0] != 0x92 {
		t.Errorf("MIME header = 0x%02X, want 0x92 (MB+SR+TNF2)", b[0])
	}
	msg, err := DecodeBytes(b)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if msg.Count != 2 {
		t.Fatalf("decoded %d records, want 2", msg.Count)
	}
	if msg.Records[0].TNF != int(TNFMIME) || msg.Records[0].Type != "text/vcard" {
		t.Errorf("MIME record = TNF %d type %q", msg.Records[0].TNF, msg.Records[0].Type)
	}
	if want := strings.ToUpper(hex.EncodeToString([]byte("BEGIN:VCARD\nEND:VCARD"))); msg.Records[0].PayloadHex != want {
		t.Errorf("MIME payload hex = %q, want %q", msg.Records[0].PayloadHex, want)
	}
	if msg.Records[1].TNF != int(TNFExternal) || msg.Records[1].Type != "android.com:pkg" {
		t.Errorf("External record = TNF %d type %q", msg.Records[1].TNF, msg.Records[1].Type)
	}
	if want := strings.ToUpper(hex.EncodeToString([]byte("com.evil.app"))); msg.Records[1].PayloadHex != want {
		t.Errorf("AAR payload hex = %q, want %q (com.evil.app)", msg.Records[1].PayloadHex, want)
	}
}

func TestEncode_MIMEExternalRejectBad(t *testing.T) {
	if _, err := Encode([]EncodeRecord{{Kind: "mime", Text: "x"}}); err == nil {
		t.Error("expected error: mime without type")
	}
	if _, err := Encode([]EncodeRecord{{Kind: "external", Type: "nopackagename", Text: "x"}}); err == nil {
		t.Error("expected error: external type without domain:type colon")
	}
}

func TestEncode_RejectsBadInput(t *testing.T) {
	if _, err := Encode(nil); err == nil {
		t.Error("expected error for empty records")
	}
	if _, err := Encode([]EncodeRecord{{Kind: "smartposter"}}); err == nil {
		t.Error("expected error for unsupported kind")
	}
	if _, err := Encode([]EncodeRecord{{Kind: "text", Text: "x", Lang: strings.Repeat("a", 64)}}); err == nil {
		t.Error("expected error for over-long language code")
	}
}
