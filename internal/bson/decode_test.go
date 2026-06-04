// SPDX-License-Identifier: AGPL-3.0-or-later

package bson

import "testing"

func decodeDoc(t *testing.T, h string) []*Field {
	t.Helper()
	r, err := Decode(h)
	if err != nil {
		t.Fatalf("Decode(%s): %v", h, err)
	}
	if r.TrailingCount != 0 {
		t.Fatalf("Decode(%s): unexpected trailing %d bytes", h, r.TrailingCount)
	}
	return r.Document
}

// one returns the sole field's value, asserting the name.
func one(t *testing.T, h, name string) *Value {
	t.Helper()
	d := decodeDoc(t, h)
	if len(d) != 1 || d[0].Name != name {
		t.Fatalf("expected single field %q, got %+v", name, d)
	}
	return d[0].Value
}

// All vectors are produced by the reference PyMongo `bson` library.

func TestString(t *testing.T) {
	v := one(t, "160000000268656c6c6f0006000000776f726c640000", "hello")
	if v.Type != "string" || v.Str == nil || *v.Str != "world" {
		t.Errorf("string: %+v", v)
	}
}

func TestNumbers(t *testing.T) {
	if v := one(t, "0c0000001061000500000000", "a"); v.Int32 == nil || *v.Int32 != 5 {
		t.Errorf("int32: %+v", v)
	}
	if v := one(t, "1000000012610000f2052a0100000000", "a"); v.Int64 == nil || *v.Int64 != 5000000000 {
		t.Errorf("int64: %+v", v)
	}
	if v := one(t, "10000000017800000000000000f83f00", "x"); v.Double == nil || *v.Double != 1.5 {
		t.Errorf("double: %+v", v)
	}
}

func TestBoolNull(t *testing.T) {
	d := decodeDoc(t, "1000000008740001086600000a6e0000") // {t:true,f:false,n:null}
	if len(d) != 3 {
		t.Fatalf("want 3 fields: %+v", d)
	}
	if d[0].Name != "t" || d[0].Value.Bool == nil || !*d[0].Value.Bool {
		t.Errorf("t: %+v", d[0])
	}
	if d[1].Name != "f" || d[1].Value.Bool == nil || *d[1].Value.Bool {
		t.Errorf("f: %+v", d[1])
	}
	if d[2].Name != "n" || d[2].Value.Type != "null" {
		t.Errorf("n: %+v", d[2])
	}
}

func TestArray(t *testing.T) {
	v := one(t, "220000000461001a0000001030000100000010310002000000103200030000000000", "a")
	if v.Type != "array" || len(v.Array) != 3 {
		t.Fatalf("array: %+v", v)
	}
	for i, want := range []int32{1, 2, 3} {
		if v.Array[i].Int32 == nil || *v.Array[i].Int32 != want {
			t.Errorf("array[%d] = %+v, want %d", i, v.Array[i], want)
		}
	}
}

func TestNested(t *testing.T) {
	// {doc:{k:v}, arr:[true,null]}
	d := decodeDoc(t, "2900000003646f63000e000000026b000200000076000004617272000c000000083000010a31000000")
	if len(d) != 2 || d[0].Name != "doc" || d[1].Name != "arr" {
		t.Fatalf("nested fields: %+v", d)
	}
	doc := d[0].Value
	if doc.Type != "document" || len(doc.Doc) != 1 || doc.Doc[0].Name != "k" || *doc.Doc[0].Value.Str != "v" {
		t.Errorf("nested doc: %+v", doc)
	}
	arr := d[1].Value
	if arr.Type != "array" || len(arr.Array) != 2 || !*arr.Array[0].Bool || arr.Array[1].Type != "null" {
		t.Errorf("nested arr: %+v", arr)
	}
}

func TestObjectID(t *testing.T) {
	v := one(t, "16000000075f696400507f1f77bcf86cd79943901100", "_id")
	if v.Type != "objectId" || v.ObjectID != "507f1f77bcf86cd799439011" {
		t.Errorf("objectId: %+v", v)
	}
}

func TestDateTime(t *testing.T) {
	v := one(t, "10000000096400009004af6001000000", "d")
	if v.Type != "datetime" || v.DateTime != "2018-01-01T00:00:00Z" || v.DateUnixMS == nil || *v.DateUnixMS != 1514764800000 {
		t.Errorf("datetime: %+v", v)
	}
}

func TestBinary(t *testing.T) {
	v := one(t, "10000000056200030000000001020300", "b")
	if v.Type != "binary" || v.BinarySubtype == nil || *v.BinarySubtype != 0 || v.BytesHex != "010203" {
		t.Errorf("binary: %+v", v)
	}
	u := one(t, "1d00000005750010000000040000000000000000000000000000000000", "u")
	if *u.BinarySubtype != 4 || u.BinarySubtypeName != "UUID" || len(u.BytesHex) != 32 {
		t.Errorf("uuid binary: %+v", u)
	}
}

func TestRegex(t *testing.T) {
	v := one(t, "0f0000000b720061622e2a00690000", "r")
	if v.Type != "regex" || v.RegexPattern == nil || *v.RegexPattern != "ab.*" || *v.RegexOptions != "i" {
		t.Errorf("regex: %+v", v)
	}
}

func TestTimestamp(t *testing.T) {
	v := one(t, "110000001174730001000000007a495a00", "ts")
	if v.Type != "timestamp" || v.TimestampIncrement == nil || *v.TimestampIncrement != 1 ||
		v.TimestampSeconds == nil || *v.TimestampSeconds != 1514764800 {
		t.Errorf("timestamp: %+v", v)
	}
}

// TestDecimal128 anchors the IEEE 754-2008 BID decode against PyMongo
// Decimal128 vectors: sign, coefficient, exponent, plain value, and the
// NaN / ±Infinity special forms. The full BSON element wrappers are
// "18000000136d00" + <16 bytes LE> + "00".
func TestDecimal128(t *testing.T) {
	cases := []struct {
		bytesLE, wantCoeff, wantPlain string
		wantExp                       int
	}{
		{"96000000000000000000000000003c30", "150", "1.50", -2},
		{"00000000000000000000000000004030", "0", "0", 0},
		{"000000000000000000000000000040b0", "0", "-0", 0},
		{"01000000000000000000000000004030", "1", "1", 0},
		{"010000000000000000000000000040b0", "1", "-1", 0},
		{"01000000000000000000000000004c30", "1", "1000000", 6},
		{"d2040000000000000000000000002630", "1234", "0.0000000001234", -13},
		{"0a000000000000000000000000004030", "10", "10", 0},
		{"ee0200000000000000000000000042b0", "750", "-7500", 1},
		{"d20a3f4eeee073c3f60fe98e01004030", "123456789012345678901234567890", "123456789012345678901234567890", 0},
	}
	for _, c := range cases {
		v := one(t, "18000000136d00"+c.bytesLE+"00", "m")
		if v.Type != "decimal128" {
			t.Errorf("%s: type %q", c.bytesLE, v.Type)
		}
		if v.Decimal128Coefficient != c.wantCoeff {
			t.Errorf("%s: coeff = %q, want %q", c.bytesLE, v.Decimal128Coefficient, c.wantCoeff)
		}
		if v.Decimal128Exponent == nil || *v.Decimal128Exponent != c.wantExp {
			t.Errorf("%s: exp = %v, want %d", c.bytesLE, v.Decimal128Exponent, c.wantExp)
		}
		if v.Decimal128 != c.wantPlain {
			t.Errorf("%s: plain = %q, want %q", c.bytesLE, v.Decimal128, c.wantPlain)
		}
	}
}

func TestDecimal128Special(t *testing.T) {
	cases := map[string]string{
		"0000000000000000000000000000007c": "NaN",
		"00000000000000000000000000000078": "Infinity",
		"000000000000000000000000000000f8": "-Infinity",
	}
	for le, want := range cases {
		v := one(t, "18000000136d00"+le+"00", "m")
		if v.Decimal128 != want {
			t.Errorf("%s: decimal128 = %q, want %q", le, v.Decimal128, want)
		}
		if v.Decimal128Coefficient != "" {
			t.Errorf("%s: special should have no coefficient, got %q", le, v.Decimal128Coefficient)
		}
	}
}

func TestMinMaxKey(t *testing.T) {
	d := decodeDoc(t, "0d000000ff6d6e007f6d780000") // {mn:MinKey, mx:MaxKey}
	if len(d) != 2 || d[0].Value.Type != "minKey" || d[1].Value.Type != "maxKey" {
		t.Errorf("min/max key: %+v", d)
	}
}

func TestTrailingBytes(t *testing.T) {
	r, err := Decode("0c0000001061000500000000ff") // valid doc + 1 stray byte
	if err != nil {
		t.Fatal(err)
	}
	if r.TrailingCount != 1 || r.TrailingHex != "FF" {
		t.Errorf("trailing: %d %s", r.TrailingCount, r.TrailingHex)
	}
}

// TestEmptyDocument confirms a minimal empty document (length 5 + terminator)
// decodes to zero fields.
func TestEmptyDocument(t *testing.T) {
	d := decodeDoc(t, "0500000000")
	if len(d) != 0 {
		t.Errorf("empty document should have 0 fields, got %+v", d)
	}
}

func TestRejectsMalformed(t *testing.T) {
	for _, c := range []string{
		"",                         // empty
		"04000000",                 // fewer than 5 bytes
		"ff0000001061000500000000", // declared length far exceeds the buffer
		"0c0000001061000500000001", // not NUL-terminated
		"0c0000000c61000500000000", // type 0x0c (DBPointer) but truncated value
		"zz",                       // not hex
	} {
		if _, err := Decode(c); err == nil {
			t.Errorf("Decode(%q): want error, got nil", c)
		}
	}
}
