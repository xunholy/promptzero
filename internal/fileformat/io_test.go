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

// TestToInt_GoNativeNumericTypes pins the v0.159 contract: toInt
// accepts the full {float64, float32, int, int32, int64, string}
// set. Mirrors v0.157 tools.intOr and v0.158 workflows.paramInt —
// any Go-native numeric type a non-JSON caller might pass should
// coerce cleanly rather than erroring with "expected integer, got
// int32".
func TestToInt_GoNativeNumericTypes(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want int
	}{
		{"float64", float64(42), 42},
		{"float32", float32(3.7), 3}, // truncates toward zero
		{"int", int(-5), -5},
		{"int32", int32(7), 7},
		{"int64", int64(123456), 123456},
		{"numeric_string", "100", 100},
		{"trimmed_string", "  42  ", 42},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := toInt(tc.in)
			if err != nil {
				t.Fatalf("toInt(%v) error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("toInt(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestToInt_NonNumericRejected verifies the unrecognised-type
// error path: bool / nil / slice / non-numeric string surface as
// errors rather than silently returning zero.
func TestToInt_NonNumericRejected(t *testing.T) {
	for _, in := range []any{true, nil, []int{1}, "not-a-number"} {
		if _, err := toInt(in); err == nil {
			t.Errorf("toInt(%v) returned nil error; want failure for non-numeric input", in)
		}
	}
}

// TestToUint32_GoNativeNumericTypes pins the same v0.159 set for
// the unsigned variant.
func TestToUint32_GoNativeNumericTypes(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want uint32
	}{
		{"float64", float64(42), 42},
		{"float32", float32(3.7), 3},
		{"int", int(7), 7},
		{"int32", int32(123), 123},
		{"int64", int64(987654), 987654},
		{"numeric_string", "100", 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := toUint32(tc.in)
			if err != nil {
				t.Fatalf("toUint32(%v) error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("toUint32(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestToUint32_NegativesRejected pins the negative-value rejection
// across every Go-native input type added in v0.159. A negative
// int32 / float32 / int64 must still surface as an error so a
// future caller passing -1 as a "sentinel" can't silently land at
// 0xFFFFFFFF.
func TestToUint32_NegativesRejected(t *testing.T) {
	for _, in := range []any{int32(-1), float32(-1.5), int(-100), int64(-1), float64(-0.5)} {
		if _, err := toUint32(in); err == nil {
			t.Errorf("toUint32(%v) returned nil error; want negative-value rejection", in)
		}
	}
}
