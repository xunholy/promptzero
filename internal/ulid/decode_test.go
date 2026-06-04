// SPDX-License-Identifier: AGPL-3.0-or-later

package ulid

import "testing"

// Anchored to python-ulid (and hand-verified Crockford decode).
func TestDecode(t *testing.T) {
	r, err := Decode("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.UnixMillis != 1469922850259 {
		t.Errorf("unix_millis = %d, want 1469922850259", r.UnixMillis)
	}
	if r.TimestampUTC != "2016-07-30T23:54:10.259Z" {
		t.Errorf("timestamp = %q, want 2016-07-30T23:54:10.259Z", r.TimestampUTC)
	}
	if r.RandomnessHex != "d6764c61efb99302bd5b" {
		t.Errorf("randomness = %q, want d6764c61efb99302bd5b", r.RandomnessHex)
	}
}

func TestDecodeZero(t *testing.T) {
	r, err := Decode("00000000000000000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.UnixMillis != 0 || r.TimestampUTC != "1970-01-01T00:00:00Z" {
		t.Errorf("zero ULID = %d/%q, want 0/epoch", r.UnixMillis, r.TimestampUTC)
	}
}

func TestCaseInsensitive(t *testing.T) {
	a, _ := Decode("01arz3ndektsv4rrffq69g5fav")
	if a == nil || a.UnixMillis != 1469922850259 {
		t.Errorf("lowercase ULID not decoded equally: %+v", a)
	}
}

func TestRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"01ARZ3NDEKTSV4RRFFQ69G5FA",   // 25 chars
		"01ARZ3NDEKTSV4RRFFQ69G5FAVX", // 27 chars
		"81ARZ3NDEKTSV4RRFFQ69G5FAV",  // first char 8 -> overflow
		"01ARZ3NDEKTSV4RRFFQ69G5FAI",  // 'I' not in alphabet
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) = nil error, want rejection", in)
		}
	}
}
