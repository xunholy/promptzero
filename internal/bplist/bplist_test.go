package bplist

import (
	"encoding/base64"
	"reflect"
	"testing"
)

// Vectors are produced by Python's stdlib plistlib.dumps(obj, FMT_BINARY) — the
// reference encoder this package is checked against.
const (
	vDict      = "YnBsaXN0MDDUAQIDBAUGAQdVYWRtaW5SaWRUbmFtZVVyYXRpbwkQByM/+AAAAAAAAAgRFxofJSYoAAAAAAAAAQEAAAAAAAAACAAAAAAAAAAAAAAAAAAAADE="
	vArray     = "YnBsaXN0MDCkAQIDBBABU3R3bwgjQAgAAAAAAAAIDQ8TFAAAAAAAAAEBAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAd"
	vNested    = "YnBsaXN0MDDSAQIDBFVjb3VudFV1c2VycxACogUI0QYHUXVRYdEGCVFiCA0TGRseISMlKAAAAAAAAAEBAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAq"
	vDate      = "YnBsaXN0MDDRAQJXY3JlYXRlZDNBwzMsYAAAAAgLEwAAAAAAAAEBAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAc"
	vData      = "YnBsaXN0MDDRAQJUYmxvYkQBAgP/CAsQAAAAAAAAAQEAAAAAAAAAAwAAAAAAAAAAAAAAAAAAABU="
	vIntWidths = "YnBsaXN0MDDTAQIDBAUGU2JpZ1NuZWdVc21hbGwTAAAAAQAAAAAT//////////sQAQgPExcdJi8AAAAAAAABAQAAAAAAAAAHAAAAAAAAAAAAAAAAAAAAMQ=="
)

func decode(t *testing.T, b64 string) *Result {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	r, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return r
}

func TestDecode_Dict(t *testing.T) {
	r := decode(t, vDict)
	m, ok := r.Root.(map[string]any)
	if !ok {
		t.Fatalf("root = %T, want map", r.Root)
	}
	if m["name"] != "admin" || m["id"] != int64(7) || m["admin"] != true || m["ratio"] != 1.5 {
		t.Errorf("dict = %+v", m)
	}
}

func TestDecode_Array(t *testing.T) {
	r := decode(t, vArray)
	got, ok := r.Root.([]any)
	if !ok {
		t.Fatalf("root = %T, want array", r.Root)
	}
	want := []any{int64(1), "two", false, float64(3.0)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("array = %+v, want %+v", got, want)
	}
}

func TestDecode_Nested(t *testing.T) {
	r := decode(t, vNested)
	m := r.Root.(map[string]any)
	if m["count"] != int64(2) {
		t.Errorf("count = %v", m["count"])
	}
	users, ok := m["users"].([]any)
	if !ok || len(users) != 2 {
		t.Fatalf("users = %+v", m["users"])
	}
	u0 := users[0].(map[string]any)
	if u0["u"] != "a" {
		t.Errorf("users[0] = %+v", u0)
	}
}

func TestDecode_Date(t *testing.T) {
	r := decode(t, vDate)
	m := r.Root.(map[string]any)
	if m["created"] != "2021-06-01T12:00:00Z" {
		t.Errorf("created = %v, want 2021-06-01T12:00:00Z", m["created"])
	}
}

func TestDecode_Data(t *testing.T) {
	r := decode(t, vData)
	m := r.Root.(map[string]any)
	if m["blob"] != "010203ff" {
		t.Errorf("blob = %v, want 010203ff", m["blob"])
	}
}

func TestDecode_IntWidths(t *testing.T) {
	r := decode(t, vIntWidths)
	m := r.Root.(map[string]any)
	if m["small"] != int64(1) || m["big"] != int64(4294967296) || m["neg"] != int64(-5) {
		t.Errorf("ints = %+v", m)
	}
}

func TestDecode_Errors(t *testing.T) {
	cases := map[string][]byte{
		"empty":     {},
		"short":     []byte("bplist00"),
		"bad magic": append([]byte("XXXXXXXX"), make([]byte, 40)...),
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{vDict, vArray, vNested, vDate, vData, vIntWidths} {
		if b, err := base64.StdEncoding.DecodeString(s); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("bplist00"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, in []byte) {
		_, _ = Decode(in)
	})
}
