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

func TestDiff_NFC(t *testing.T) {
	a, err := ParseNFC([]byte(nfcFixture))
	if err != nil {
		t.Fatalf("ParseNFC a: %v", err)
	}
	b, err := ParseNFC([]byte(nfcFixture))
	if err != nil {
		t.Fatalf("ParseNFC b: %v", err)
	}
	// Mutate one scalar (UID) and one block.
	b.UID = "AA BB CC DD EE FF 00"
	b.Blocks[1] = "11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11"

	d, err := Diff(FormatNFC, a, FormatNFC, b)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !d.SameFormat {
		t.Fatalf("SameFormat = false; want true")
	}
	// All scalar fields + every block index that exists in either side
	// must surface — diff must not silently drop a missing block.
	var sawUID, sawBlock0, sawBlock1, sawBlock4 bool
	for _, e := range d.Entries {
		switch e.Field {
		case "uid":
			if e.Same {
				t.Error("uid entry Same=true after mutation")
			}
			sawUID = true
		case "block_0":
			sawBlock0 = true
			if !e.Same {
				t.Errorf("block_0 Same=false; values unchanged should match")
			}
		case "block_1":
			sawBlock1 = true
			if e.Same {
				t.Error("block_1 Same=true after mutation")
			}
		case "block_4":
			sawBlock4 = true
		}
	}
	for name, ok := range map[string]bool{"uid": sawUID, "block_0": sawBlock0, "block_1": sawBlock1, "block_4": sawBlock4} {
		if !ok {
			t.Errorf("entry %q missing from diff result", name)
		}
	}
}

func TestDiff_NFC_BlockOnlyInOne(t *testing.T) {
	a, _ := ParseNFC([]byte(nfcFixture))
	b, _ := ParseNFC([]byte(nfcFixture))
	// Add a block to b that doesn't exist in a — diff must still
	// emit an entry for it with a's value empty.
	b.Blocks[7] = "FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00"
	d, err := Diff(FormatNFC, a, FormatNFC, b)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	var sawBlock7 bool
	for _, e := range d.Entries {
		if e.Field == "block_7" {
			sawBlock7 = true
			if e.Same {
				t.Error("block_7 Same=true; only b has it")
			}
			if e.AField != "" {
				t.Errorf("block_7 a side = %q; want empty (block not in a)", e.AField)
			}
		}
	}
	if !sawBlock7 {
		t.Error("block_7 entry missing for block-only-in-b case")
	}
}

func TestDiff_RFID(t *testing.T) {
	a, err := ParseRFID([]byte(rfidFixture))
	if err != nil {
		t.Fatalf("ParseRFID a: %v", err)
	}
	b, err := ParseRFID([]byte(rfidFixture))
	if err != nil {
		t.Fatalf("ParseRFID b: %v", err)
	}
	b.Data = "FF FF FF FF FF"
	b.KeyType = "HIDProx"

	d, err := Diff(FormatRFID, a, FormatRFID, b)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !d.SameFormat {
		t.Fatalf("SameFormat = false; want true")
	}
	var sawData, sawKeyType bool
	for _, e := range d.Entries {
		switch e.Field {
		case "data":
			if e.Same {
				t.Error("data Same=true after mutation")
			}
			sawData = true
		case "key_type":
			if e.Same {
				t.Error("key_type Same=true after mutation")
			}
			sawKeyType = true
		}
	}
	if !sawData || !sawKeyType {
		t.Errorf("missing entries: data=%v key_type=%v", sawData, sawKeyType)
	}
}

func TestDiff_RFID_Identical(t *testing.T) {
	a, _ := ParseRFID([]byte(rfidFixture))
	b, _ := ParseRFID([]byte(rfidFixture))
	d, err := Diff(FormatRFID, a, FormatRFID, b)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	for _, e := range d.Entries {
		if !e.Same {
			t.Errorf("identical files but entry %q differs: %q vs %q", e.Field, e.AField, e.BField)
		}
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
