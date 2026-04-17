package fileformat

import (
	"strings"
	"testing"
)

func TestLoadFile_Dispatch(t *testing.T) {
	cases := []struct {
		path   string
		data   string
		format Format
	}{
		{"/ext/subghz/x.sub", subFixtureKey, FormatSub},
		{"/ext/nfc/x.nfc", nfcFixture, FormatNFC},
		{"/ext/infrared/x.ir", irFixture, FormatIR},
		{"/ext/lfrfid/x.rfid", rfidFixture, FormatRFID},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			model, format, err := LoadFile(tc.path, []byte(tc.data))
			if err != nil {
				t.Fatalf("LoadFile: %v", err)
			}
			if format != tc.format {
				t.Fatalf("format: want %q got %q", tc.format, format)
			}
			if model == nil {
				t.Fatalf("nil model")
			}
			out, err := SaveFile(format, model)
			if err != nil {
				t.Fatalf("SaveFile: %v", err)
			}
			if len(out) == 0 {
				t.Fatalf("SaveFile returned empty")
			}
		})
	}
}

func TestLoadFile_UnknownExtension(t *testing.T) {
	if _, _, err := LoadFile("x.unknown", []byte("ignored")); err == nil {
		t.Fatalf("expected error for unknown extension")
	}
}

func TestApplyEdits_EmptyMap(t *testing.T) {
	s, _ := ParseSub([]byte(subFixtureKey))
	if err := ApplyEdits(FormatSub, s, nil); err == nil {
		t.Fatalf("expected error for empty edit map")
	}
}

func TestDiff_Sub(t *testing.T) {
	a, _ := ParseSub([]byte(subFixtureKey))
	b, _ := ParseSub([]byte(subFixtureKey))
	b.Frequency = 868350000
	d, err := Diff(FormatSub, a, FormatSub, b)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !d.SameFormat {
		t.Fatalf("expected same format")
	}
	found := false
	for _, e := range d.Entries {
		if e.Field == "frequency" {
			if e.Same {
				t.Fatalf("expected frequency diff, got Same=true")
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("frequency diff entry missing")
	}
}

func TestDiff_FormatMismatch(t *testing.T) {
	s, _ := ParseSub([]byte(subFixtureKey))
	r, _ := ParseRFID([]byte(rfidFixture))
	d, err := Diff(FormatSub, s, FormatRFID, r)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if d.SameFormat {
		t.Fatalf("expected SameFormat=false")
	}
	if len(d.Entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(d.Entries))
	}
}

func TestDiff_IR(t *testing.T) {
	a, _ := ParseIR([]byte(irFixture))
	b, _ := ParseIR([]byte(irFixture))
	b.Signals[0].Command = "FF 00 00 00"
	d, err := Diff(FormatIR, a, FormatIR, b)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	var sawCmd bool
	for _, e := range d.Entries {
		if strings.HasSuffix(e.Field, "command") && !e.Same {
			sawCmd = true
		}
	}
	if !sawCmd {
		t.Fatalf("expected a command diff entry")
	}
}
