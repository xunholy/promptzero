package fileformat

import (
	"reflect"
	"strings"
	"testing"
)

const rfidFixture = `Filetype: Flipper RFID key
Version: 1
Key type: EM4100
Data: 08 12 A3 C5 D6
`

func TestParseRFID(t *testing.T) {
	r, err := ParseRFID([]byte(rfidFixture))
	if err != nil {
		t.Fatalf("ParseRFID: %v", err)
	}
	if r.KeyType != "EM4100" || r.Data != "08 12 A3 C5 D6" {
		t.Fatalf("fields: %+v", r)
	}
}

func TestRFID_RoundTrip(t *testing.T) {
	assertRFIDRoundTrip(t, rfidFixture)
}

func TestRFID_CRLF(t *testing.T) {
	assertRFIDRoundTrip(t, strings.ReplaceAll(rfidFixture, "\n", "\r\n"))
}

func TestRFID_MissingFinalNewline(t *testing.T) {
	assertRFIDRoundTrip(t, strings.TrimRight(rfidFixture, "\n"))
}

func TestRFID_Edits(t *testing.T) {
	r, err := ParseRFID([]byte(rfidFixture))
	if err != nil {
		t.Fatal(err)
	}
	if err := applyRFIDEdits(r, map[string]interface{}{"key_type": "HIDProx", "data": "AA BB CC"}); err != nil {
		t.Fatalf("applyRFIDEdits: %v", err)
	}
	if r.KeyType != "HIDProx" || r.Data != "AA BB CC" {
		t.Fatalf("edits not applied: %+v", r)
	}
	if err := applyRFIDEdits(r, map[string]interface{}{"nope": "x"}); err == nil {
		t.Fatalf("expected error for unknown key")
	}
}

func assertRFIDRoundTrip(t *testing.T, fixture string) {
	t.Helper()
	a, err := ParseRFID([]byte(fixture))
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	b, err := ParseRFID(a.Marshal())
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("round-trip mismatch\nA: %+v\nB: %+v", a, b)
	}
}
