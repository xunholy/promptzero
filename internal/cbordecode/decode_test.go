package cbordecode

import (
	"math"
	"strings"
	"testing"
)

// TestDecode_UnsignedInt_Direct pins direct unsigned ints
// 0..23 (encoded in a single byte).
func TestDecode_UnsignedInt_Direct(t *testing.T) {
	cases := []struct {
		hex  string
		want uint64
	}{
		{"00", 0},
		{"01", 1},
		{"0A", 10},
		{"17", 23},
	}
	for _, c := range cases {
		got, err := Decode(c.hex)
		if err != nil {
			t.Fatalf("Decode(%q): %v", c.hex, err)
		}
		if got.MajorType != 0 {
			t.Errorf("%s: MajorType = %d", c.hex, got.MajorType)
		}
		if got.Uint == nil || *got.Uint != c.want {
			t.Errorf("%s: Uint = %v; want %d", c.hex, got.Uint, c.want)
		}
	}
}

// TestDecode_UnsignedInt_MultiByte pins 1/2/4/8-byte
// arguments per RFC 8949 Appendix A.
func TestDecode_UnsignedInt_MultiByte(t *testing.T) {
	cases := []struct {
		hex  string
		want uint64
	}{
		{"1818", 24},                          // 1-byte
		{"1864", 100},                         // 1-byte
		{"190100", 256},                       // 2-byte
		{"1903E8", 1000},                      // 2-byte 1000
		{"1A000F4240", 1000000},               // 4-byte 1M
		{"1B000000E8D4A51000", 1000000000000}, // 8-byte 1T
	}
	for _, c := range cases {
		got, err := Decode(c.hex)
		if err != nil {
			t.Fatalf("Decode(%q): %v", c.hex, err)
		}
		if *got.Uint != c.want {
			t.Errorf("%s: Uint = %d; want %d", c.hex, *got.Uint, c.want)
		}
	}
}

// TestDecode_NegativeInt pins negative integers per RFC 8949
// Appendix A: -1 = 0x20, -100 = 0x3863, -1000 = 0x3903E7.
func TestDecode_NegativeInt(t *testing.T) {
	cases := []struct {
		hex  string
		want int64
	}{
		{"20", -1},
		{"29", -10},
		{"3863", -100},
		{"3903E7", -1000},
	}
	for _, c := range cases {
		got, err := Decode(c.hex)
		if err != nil {
			t.Fatalf("Decode(%q): %v", c.hex, err)
		}
		if got.MajorType != 1 {
			t.Errorf("%s: MajorType = %d", c.hex, got.MajorType)
		}
		if got.Int == nil || *got.Int != c.want {
			t.Errorf("%s: Int = %v; want %d", c.hex, got.Int, c.want)
		}
	}
}

// TestDecode_ByteString pins byte strings of various lengths.
func TestDecode_ByteString(t *testing.T) {
	got, err := Decode("4401020304") // h'01020304'
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MajorType != 2 {
		t.Errorf("MajorType = %d", got.MajorType)
	}
	if got.Bytes != "01020304" {
		t.Errorf("Bytes = %q", got.Bytes)
	}
}

// TestDecode_TextString pins UTF-8 text strings.
func TestDecode_TextString(t *testing.T) {
	// "IETF" = 0x49 (text len 4) + bytes
	got, err := Decode("6449455446")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MajorType != 3 {
		t.Errorf("MajorType = %d", got.MajorType)
	}
	if got.Text != "IETF" {
		t.Errorf("Text = %q", got.Text)
	}
}

// TestDecode_Array pins a definite-length array of small ints.
func TestDecode_Array(t *testing.T) {
	// [1, 2, 3] = 0x83 + 01 + 02 + 03
	got, err := Decode("83010203")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MajorType != 4 {
		t.Errorf("MajorType = %d", got.MajorType)
	}
	if len(got.Array) != 3 {
		t.Fatalf("Array count = %d", len(got.Array))
	}
	for i, elem := range got.Array {
		want := uint64(i + 1)
		if elem.Uint == nil || *elem.Uint != want {
			t.Errorf("Array[%d] = %v; want %d", i, elem.Uint, want)
		}
	}
}

// TestDecode_NestedArray pins a recursive array.
func TestDecode_NestedArray(t *testing.T) {
	// [1, [2, 3], [4, 5]]
	got, err := Decode("8301820203820405")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.Array) != 3 {
		t.Fatalf("Array count = %d", len(got.Array))
	}
	if got.Array[1].MajorType != 4 || len(got.Array[1].Array) != 2 {
		t.Errorf("nested array[1] = %+v", got.Array[1])
	}
}

// TestDecode_Map pins a definite-length map with text-string
// keys and int values.
func TestDecode_Map(t *testing.T) {
	// {"a": 1, "b": [2, 3]} = A2 61 61 01 61 62 82 02 03
	got, err := Decode("A26161016162820203")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MajorType != 5 {
		t.Errorf("MajorType = %d", got.MajorType)
	}
	if len(got.Map) != 2 {
		t.Fatalf("Map entry count = %d", len(got.Map))
	}
	if got.Map[0].Key.Text != "a" {
		t.Errorf("Map[0].Key.Text = %q", got.Map[0].Key.Text)
	}
	if got.Map[0].Value.Uint == nil || *got.Map[0].Value.Uint != 1 {
		t.Errorf("Map[0].Value = %v", got.Map[0].Value.Uint)
	}
	if got.Map[1].Key.Text != "b" {
		t.Errorf("Map[1].Key.Text = %q", got.Map[1].Key.Text)
	}
	if len(got.Map[1].Value.Array) != 2 {
		t.Errorf("Map[1].Value.Array count = %d", len(got.Map[1].Value.Array))
	}
}

// TestDecode_TaggedValue pins a tagged date-time string
// (tag 0).
func TestDecode_TaggedValue(t *testing.T) {
	// tag(0, "2013-03-21T20:04:00Z") =
	// C0 74 32 30 31 33 2D 30 33 2D 32 31 54 32 30 3A 30 34 3A 30 30 5A
	got, err := Decode("C07432303133" + "2D30332D32315432303A30343A30305A")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MajorType != 6 {
		t.Errorf("MajorType = %d", got.MajorType)
	}
	if got.Tag == nil || *got.Tag != 0 {
		t.Errorf("Tag = %v", got.Tag)
	}
	if !strings.Contains(got.TagName, "RFC 3339") {
		t.Errorf("TagName = %q", got.TagName)
	}
	if got.TagValue.Text != "2013-03-21T20:04:00Z" {
		t.Errorf("TagValue.Text = %q", got.TagValue.Text)
	}
}

// TestDecode_TaggedValue_COSE pins a COSE_Sign1 tag (18).
func TestDecode_TaggedValue_COSE(t *testing.T) {
	// tag(18, []) — minimal COSE_Sign1 envelope. D2 is the
	// tag-18 header byte, 80 is an empty array.
	got, err := Decode("D280")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if *got.Tag != 18 {
		t.Errorf("Tag = %d", *got.Tag)
	}
	if !strings.Contains(got.TagName, "COSE_Sign1") {
		t.Errorf("TagName = %q", got.TagName)
	}
}

// TestDecode_SimpleValues pins false / true / null /
// undefined.
func TestDecode_SimpleValues(t *testing.T) {
	cases := []struct {
		hex  string
		want string
	}{
		{"F4", "false"},
		{"F5", "true"},
		{"F6", "null"},
		{"F7", "undefined"},
	}
	for _, c := range cases {
		got, err := Decode(c.hex)
		if err != nil {
			t.Fatalf("Decode(%q): %v", c.hex, err)
		}
		if got.SimpleName != c.want {
			t.Errorf("%s: SimpleName = %q; want %q", c.hex, got.SimpleName, c.want)
		}
	}
}

// TestDecode_Float16 pins a half-precision float (1.5).
func TestDecode_Float16(t *testing.T) {
	// 1.5 in float16 = 0x3E00
	got, err := Decode("F93E00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Float == nil || *got.Float != 1.5 {
		t.Errorf("Float = %v", got.Float)
	}
}

// TestDecode_Float16_Special pins NaN / Inf detection.
func TestDecode_Float16_Special(t *testing.T) {
	// +Inf in float16 = 0x7C00
	got, err := Decode("F97C00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !math.IsInf(*got.Float, 1) {
		t.Errorf("Float = %v; want +Inf", *got.Float)
	}
	if got.FloatSpec != "+Inf" {
		t.Errorf("FloatSpec = %q", got.FloatSpec)
	}
	// NaN = 0x7E00
	got, err = Decode("F97E00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !math.IsNaN(*got.Float) {
		t.Errorf("Float should be NaN")
	}
	if got.FloatSpec != "NaN" {
		t.Errorf("FloatSpec = %q", got.FloatSpec)
	}
}

// TestDecode_Float32 pins a single-precision float (3.14).
func TestDecode_Float32(t *testing.T) {
	// 3.14 float32 = 0x4048F5C3
	got, err := Decode("FA4048F5C3")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Float == nil {
		t.Fatal("Float nil")
	}
	if math.Abs(*got.Float-3.14) > 1e-5 {
		t.Errorf("Float = %f; want ~3.14", *got.Float)
	}
}

// TestDecode_Float64 pins a double-precision float (3.14).
func TestDecode_Float64(t *testing.T) {
	// 3.14 float64 = 0x40091EB851EB851F
	got, err := Decode("FB40091EB851EB851F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if math.Abs(*got.Float-3.14) > 1e-9 {
		t.Errorf("Float = %f; want 3.14", *got.Float)
	}
}

// TestDecode_Indefinite_Array pins an indefinite-length array.
func TestDecode_Indefinite_Array(t *testing.T) {
	// [_ 1, 2, 3] = 9F 01 02 03 FF
	got, err := Decode("9F010203FF")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Indefinite {
		t.Error("Indefinite = false")
	}
	if len(got.Array) != 3 {
		t.Errorf("Array count = %d", len(got.Array))
	}
}

// TestDecode_Indefinite_Map pins an indefinite-length map.
func TestDecode_Indefinite_Map(t *testing.T) {
	// {_ "a": 1, "b": 2} = BF 61 61 01 61 62 02 FF
	got, err := Decode("BF6161016162 02 FF")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Indefinite {
		t.Error("Indefinite = false")
	}
	if len(got.Map) != 2 {
		t.Errorf("Map count = %d", len(got.Map))
	}
}

// TestDecode_Indefinite_TextString pins an indefinite text
// string with chunks "stream"+"ing" = "streaming".
func TestDecode_Indefinite_TextString(t *testing.T) {
	// 7F (start indef text) + 66 (text len 6) + "stream"
	// (73 74 72 65 61 6D) + 63 (text len 3) + "ing" (69 6E
	// 67) + FF (break) = 13 bytes total.
	got, err := Decode("7F6673747265616D63696E67FF")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Indefinite {
		t.Error("Indefinite = false")
	}
	if got.Text != "streaming" {
		t.Errorf("Text = %q", got.Text)
	}
}

// TestDecode_TrailingBytes rejects extra bytes after the
// first complete item.
func TestDecode_TrailingBytes(t *testing.T) {
	// Two consecutive 0x01 bytes — the first is a complete
	// item; the second is junk.
	if _, err := Decode("0101"); err == nil {
		t.Error("trailing bytes: want error")
	}
}

// TestDecode_Truncated rejects buffers that end mid-item.
func TestDecode_Truncated(t *testing.T) {
	// Major 0 with additional 24 needs 1 more byte
	if _, err := Decode("18"); err == nil {
		t.Error("truncated 1-byte arg: want error")
	}
	// Major 2 declared length 4 but only 2 bytes follow
	if _, err := Decode("440102"); err == nil {
		t.Error("truncated byte string: want error")
	}
}

// TestDecode_BadHex rejects garbage.
func TestDecode_BadHex(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
	if _, err := Decode("ZZ"); err == nil {
		t.Error("garbage hex: want error")
	}
}

// TestDecode_SelfDescribe pins the self-describe magic tag
// (55799) wrapping a small int.
func TestDecode_SelfDescribe(t *testing.T) {
	// tag(55799, 0)
	// 55799 = 0xD9D9F7
	got, err := Decode("D9D9F700")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if *got.Tag != 55799 {
		t.Errorf("Tag = %d", *got.Tag)
	}
	if !strings.Contains(got.TagName, "Self-describe") {
		t.Errorf("TagName = %q", got.TagName)
	}
	if got.TagValue.Uint == nil || *got.TagValue.Uint != 0 {
		t.Errorf("TagValue = %v", got.TagValue.Uint)
	}
}

// TestMajorTypeNameTable spot-checks the table.
func TestMajorTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0: "Unsigned Integer",
		1: "Negative Integer",
		2: "Byte String",
		3: "Text String",
		4: "Array",
		5: "Map",
		6: "Tagged Value",
		7: "Float / Simple",
	}
	for v, want := range cases {
		if got := majorTypeName(v); got != want {
			t.Errorf("majorTypeName(%d) = %q; want %q", v, got, want)
		}
	}
}

// TestTagNameTable spot-checks well-known tag names.
func TestTagNameTable(t *testing.T) {
	cases := map[uint64]string{
		0:     "Standard date/time string (RFC 3339)",
		1:     "Epoch-based date/time (numeric)",
		16:    "COSE_Encrypt0 (RFC 9052)",
		17:    "COSE_Mac0 (RFC 9052)",
		18:    "COSE_Sign1 (RFC 9052)",
		32:    "URI (RFC 3986)",
		55799: "Self-describe CBOR magic",
	}
	for v, want := range cases {
		if got := tagName(v); got != want {
			t.Errorf("tagName(%d) = %q; want %q", v, got, want)
		}
	}
}

// TestDecodeBytes_NestedBombBounded feeds a deeply-nested "CBOR bomb" (0x81 =
// array-of-one repeated) far past maxDepth and asserts DecodeBytes returns an
// error instead of overflowing the goroutine stack. Before the maxDepth guard
// this recursed one frame per level and hit a fatal, uncatchable stack overflow
// at ~1M frames. A within-limit nesting still decodes.
func TestDecodeBytes_NestedBombBounded(t *testing.T) {
	bomb := make([]byte, 2_000_000)
	for i := range bomb {
		bomb[i] = 0x81 // array of 1 element
	}
	bomb[len(bomb)-1] = 0x00 // innermost: integer 0
	if _, err := DecodeBytes(bomb); err == nil {
		t.Errorf("expected depth-limit error on CBOR bomb")
	} else if !strings.Contains(err.Error(), "max depth") {
		t.Errorf("expected max-depth error, got: %v", err)
	}
	// Within the limit, nesting is still reconstructed.
	small := make([]byte, 10)
	for i := range small {
		small[i] = 0x81
	}
	small[len(small)-1] = 0x00
	v, err := DecodeBytes(small)
	if err != nil {
		t.Fatalf("within-limit nest: %v", err)
	}
	depth := 0
	for v != nil && len(v.Array) == 1 {
		depth++
		v = v.Array[0]
	}
	if depth < 5 {
		t.Errorf("within-limit nest not reconstructed: depth=%d", depth)
	}
}

// TestValue_AsInt covers the shared integer accessor used by COSE / CWT label
// maps: unsigned and negative ints decode; non-integers, nil, and an unsigned
// value past MaxInt64 report ok=false.
func TestValue_AsInt(t *testing.T) {
	mk := func(hex string) *Value {
		v, err := Decode(hex)
		if err != nil {
			t.Fatalf("Decode(%s): %v", hex, err)
		}
		return v
	}
	if n, ok := mk("0a").AsInt(); !ok || n != 10 { // uint 10
		t.Errorf("uint: got %d,%v", n, ok)
	}
	if n, ok := mk("29").AsInt(); !ok || n != -10 { // negint -10
		t.Errorf("negint: got %d,%v", n, ok)
	}
	if _, ok := mk("6161").AsInt(); ok { // text "a"
		t.Error("text string should not decode as int")
	}
	if _, ok := mk("43010203").AsInt(); ok { // byte string
		t.Error("byte string should not decode as int")
	}
	if _, ok := (*Value)(nil).AsInt(); ok {
		t.Error("nil value should report ok=false")
	}
	if _, ok := mk("1bffffffffffffffff").AsInt(); ok { // uint 2^64-1 > MaxInt64
		t.Error("uint past MaxInt64 should report ok=false")
	}
}
