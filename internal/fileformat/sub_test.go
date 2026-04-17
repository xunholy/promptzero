package fileformat

import (
	"reflect"
	"strings"
	"testing"
)

const subFixtureKey = `Filetype: Flipper SubGhz Key File
Version: 1
Frequency: 433920000
Preset: FuriHalSubGhzPresetOok650Async
Protocol: Princeton
Bit: 24
Key: 00 00 00 4B 4F 73
TE: 415
`

const subFixtureRAW = `Filetype: Flipper SubGhz RAW File
Version: 1
Frequency: 868350000
Preset: FuriHalSubGhzPresetOok650Async
Protocol: RAW
RAW_Data: 415 -415 830 -415 415 -830
RAW_Data: 415 -415 415 -415
`

func TestParseSub_Key(t *testing.T) {
	s, err := ParseSub([]byte(subFixtureKey))
	if err != nil {
		t.Fatalf("ParseSub: %v", err)
	}
	if s.Frequency != 433920000 || s.Protocol != "Princeton" || s.Bit != 24 || s.TE != 415 {
		t.Fatalf("unexpected fields: %+v", s)
	}
	if s.Key != "00 00 00 4B 4F 73" {
		t.Fatalf("key: %q", s.Key)
	}
}

func TestSub_RoundTrip_Key(t *testing.T) {
	assertSubRoundTrip(t, subFixtureKey)
}

func TestSub_RoundTrip_RAW(t *testing.T) {
	assertSubRoundTrip(t, subFixtureRAW)
}

func TestSub_CRLFAndComments(t *testing.T) {
	crlf := strings.ReplaceAll(subFixtureKey, "\n", "\r\n")
	crlf = "# captured 2026-04-18\r\n\r\n" + crlf
	assertSubRoundTrip(t, crlf)
}

func TestSub_MissingFinalNewline(t *testing.T) {
	s := strings.TrimRight(subFixtureKey, "\n")
	assertSubRoundTrip(t, s)
}

func TestSub_UnknownHeaderPreserved(t *testing.T) {
	custom := subFixtureKey + "Custom_Field: hello world\n"
	s, err := ParseSub([]byte(custom))
	if err != nil {
		t.Fatalf("ParseSub: %v", err)
	}
	if s.Headers["Custom_Field"] != "hello world" {
		t.Fatalf("expected Custom_Field preserved, got %+v", s.Headers)
	}
	out := s.Marshal()
	if !strings.Contains(string(out), "Custom_Field: hello world") {
		t.Fatalf("Marshal dropped custom header:\n%s", out)
	}
}

func TestSub_EditAndRejectUnknown(t *testing.T) {
	s, err := ParseSub([]byte(subFixtureKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := applySubEdits(s, map[string]interface{}{"frequency": float64(868350000), "te": 400}); err != nil {
		t.Fatalf("applySubEdits: %v", err)
	}
	if s.Frequency != 868350000 || s.TE != 400 {
		t.Fatalf("edits didn't apply: %+v", s)
	}
	if err := applySubEdits(s, map[string]interface{}{"bogus": "x"}); err == nil {
		t.Fatalf("expected error for unknown edit key")
	}
}

func assertSubRoundTrip(t *testing.T, fixture string) {
	t.Helper()
	a, err := ParseSub([]byte(fixture))
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	b, err := ParseSub(a.Marshal())
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("round-trip mismatch\nA: %+v\nB: %+v", a, b)
	}
}
