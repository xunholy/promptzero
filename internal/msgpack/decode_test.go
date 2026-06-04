// SPDX-License-Identifier: AGPL-3.0-or-later

package msgpack

import "testing"

func mustDecode(t *testing.T, h string) *Value {
	t.Helper()
	r, err := Decode(h)
	if err != nil {
		t.Fatalf("Decode(%s): %v", h, err)
	}
	if r.TrailingCount != 0 {
		t.Fatalf("Decode(%s): unexpected trailing %d bytes", h, r.TrailingCount)
	}
	return r.Value
}

// TestScalarVectors anchors every scalar family against the reference msgpack
// Python library's output.
func TestScalarVectors(t *testing.T) {
	if v := mustDecode(t, "c0"); v.Type != "nil" {
		t.Errorf("nil: %+v", v)
	}
	if v := mustDecode(t, "c2"); v.Bool == nil || *v.Bool {
		t.Errorf("false: %+v", v)
	}
	if v := mustDecode(t, "c3"); v.Bool == nil || !*v.Bool {
		t.Errorf("true: %+v", v)
	}
	if v := mustDecode(t, "00"); v.Uint == nil || *v.Uint != 0 || v.Format != "positive fixint" {
		t.Errorf("0: %+v", v)
	}
	if v := mustDecode(t, "7f"); v.Uint == nil || *v.Uint != 127 {
		t.Errorf("127: %+v", v)
	}
	if v := mustDecode(t, "ff"); v.Int == nil || *v.Int != -1 || v.Format != "negative fixint" {
		t.Errorf("-1: %+v", v)
	}
	if v := mustDecode(t, "e0"); v.Int == nil || *v.Int != -32 {
		t.Errorf("-32: %+v", v)
	}
	if v := mustDecode(t, "ccff"); v.Uint == nil || *v.Uint != 255 || v.Format != "uint8" {
		t.Errorf("255: %+v", v)
	}
	if v := mustDecode(t, "cd0100"); v.Uint == nil || *v.Uint != 256 || v.Format != "uint16" {
		t.Errorf("256: %+v", v)
	}
	if v := mustDecode(t, "ce00010000"); v.Uint == nil || *v.Uint != 65536 || v.Format != "uint32" {
		t.Errorf("65536: %+v", v)
	}
	if v := mustDecode(t, "d080"); v.Int == nil || *v.Int != -128 || v.Format != "int8" {
		t.Errorf("-128: %+v", v)
	}
	if v := mustDecode(t, "d18000"); v.Int == nil || *v.Int != -32768 || v.Format != "int16" {
		t.Errorf("-32768: %+v", v)
	}
	if v := mustDecode(t, "cb3ff8000000000000"); v.Float == nil || *v.Float != 1.5 || v.Format != "float64" {
		t.Errorf("1.5 f64: %+v", v)
	}
	if v := mustDecode(t, "ca3fc00000"); v.Float == nil || *v.Float != 1.5 || v.Format != "float32" {
		t.Errorf("1.5 f32: %+v", v)
	}
}

func TestStrBinVectors(t *testing.T) {
	if v := mustDecode(t, "a26869"); v.Str == nil || *v.Str != "hi" || v.Format != "fixstr" {
		t.Errorf("fixstr hi: %+v", v)
	}
	// str8, 40 'a's.
	v := mustDecode(t, "d92861616161616161616161616161616161616161616161616161616161616161616161616161616161")
	if v.Str == nil || len(*v.Str) != 40 || v.Format != "str8" {
		t.Errorf("str8: %+v", v)
	}
	if b := mustDecode(t, "c403010203"); b.Type != "bin" || b.BytesHex != "010203" || b.Format != "bin8" {
		t.Errorf("bin8: %+v", b)
	}
}

func TestArrayMapVectors(t *testing.T) {
	a := mustDecode(t, "93010203") // [1,2,3]
	if a.Type != "array" || len(a.Array) != 3 || *a.Array[0].Uint != 1 || *a.Array[2].Uint != 3 {
		t.Errorf("array: %+v", a)
	}
	m := mustDecode(t, "82a16101a16202") // {"a":1,"b":2}
	if m.Type != "map" || len(m.Map) != 2 {
		t.Fatalf("map: %+v", m)
	}
	if *m.Map[0].Key.Str != "a" || *m.Map[0].Value.Uint != 1 {
		t.Errorf("map entry 0: %+v / %+v", m.Map[0].Key, m.Map[0].Value)
	}
	if *m.Map[1].Key.Str != "b" || *m.Map[1].Value.Uint != 2 {
		t.Errorf("map entry 1: %+v / %+v", m.Map[1].Key, m.Map[1].Value)
	}
}

// TestNested anchors a nested map/array/bool/nil vector: {"x":[1,true,nil],"y":"z"}.
func TestNested(t *testing.T) {
	v := mustDecode(t, "82a1789301c3c0a179a17a")
	if len(v.Map) != 2 {
		t.Fatalf("nested map len: %+v", v)
	}
	x := v.Map[0]
	if *x.Key.Str != "x" || x.Value.Type != "array" || len(x.Value.Array) != 3 {
		t.Fatalf("nested x: %+v", x)
	}
	if *x.Value.Array[0].Uint != 1 || !*x.Value.Array[1].Bool || x.Value.Array[2].Type != "nil" {
		t.Errorf("nested array elems: %+v", x.Value.Array)
	}
	if *v.Map[1].Key.Str != "y" || *v.Map[1].Value.Str != "z" {
		t.Errorf("nested y: %+v", v.Map[1])
	}
}

func TestExtVector(t *testing.T) {
	v := mustDecode(t, "d60501020304") // fixext4, type 5, data 01020304
	if v.Type != "ext" || v.Format != "fixext4" || v.ExtType == nil || *v.ExtType != 5 || v.ExtData != "01020304" {
		t.Errorf("ext: %+v", v)
	}
}

func TestTimestampExtNote(t *testing.T) {
	// fixext4, type -1 (0xff) — the Timestamp ext; surfaced raw with a note.
	v := mustDecode(t, "d6ff5a4af600")
	if v.ExtType == nil || *v.ExtType != -1 || v.Note == "" {
		t.Errorf("timestamp ext should be raw with a note: %+v", v)
	}
}

func TestTrailingBytes(t *testing.T) {
	r, err := Decode("c0c2") // nil, then a stray false
	if err != nil {
		t.Fatal(err)
	}
	if r.Value.Type != "nil" || r.TrailingCount != 1 || r.TrailingHex != "C2" {
		t.Errorf("trailing: value=%+v trailing=%d hex=%s", r.Value, r.TrailingCount, r.TrailingHex)
	}
}

func TestRejectsMalformed(t *testing.T) {
	for _, c := range []string{
		"",       // empty
		"c1",     // reserved tag
		"cc",     // uint8 missing its byte
		"a2",     // fixstr len 2, no payload
		"dcffff", // array16 of 65535 with no elements
		"93",     // fixarray 3, no elements
		"xyz",    // not hex
	} {
		if _, err := Decode(c); err == nil {
			t.Errorf("Decode(%q): want error, got nil", c)
		}
	}
}
