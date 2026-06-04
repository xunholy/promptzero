// SPDX-License-Identifier: AGPL-3.0-or-later

package objectid

import "testing"

// Timestamps are pymongo's ObjectId.generation_time.
func TestDecode(t *testing.T) {
	cases := []struct {
		in      string
		secs    int64
		ts      string
		counter int
		randhex string
	}{
		{"507f1f77bcf86cd799439011", 1350508407, "2012-10-17T21:13:27Z", 0x439011, "bcf86cd799"},
		{"65a1b2c3d4e5f60718293a4b", 1705095875, "2024-01-12T21:44:35Z", 0x293a4b, "d4e5f60718"},
		{"000000000000000000000000", 0, "1970-01-01T00:00:00Z", 0, "0000000000"},
	}
	for _, c := range cases {
		r, err := Decode(c.in)
		if err != nil {
			t.Errorf("Decode(%s): %v", c.in, err)
			continue
		}
		if r.UnixSeconds != c.secs || r.TimestampUTC != c.ts {
			t.Errorf("Decode(%s) ts = %d/%q, want %d/%q", c.in, r.UnixSeconds, r.TimestampUTC, c.secs, c.ts)
		}
		if r.Counter != c.counter {
			t.Errorf("Decode(%s) counter = %d, want %d", c.in, r.Counter, c.counter)
		}
		if r.RandomHex != c.randhex {
			t.Errorf("Decode(%s) random = %q, want %q", c.in, r.RandomHex, c.randhex)
		}
	}
}

func TestWrappedForms(t *testing.T) {
	for _, s := range []string{
		`ObjectId("507f1f77bcf86cd799439011")`,
		`"507f1f77bcf86cd799439011"`,
		"507F1F77BCF86CD799439011",
	} {
		r, err := Decode(s)
		if err != nil || r.ObjectID != "507f1f77bcf86cd799439011" {
			t.Errorf("Decode(%q) = %q (%v)", s, r.ObjectID, err)
		}
	}
}

func TestRejects(t *testing.T) {
	for _, in := range []string{"", "507f1f77", "zzzzzzzzzzzzzzzzzzzzzzzz", "507f1f77bcf86cd79943901"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) = nil error, want rejection", in)
		}
	}
}
