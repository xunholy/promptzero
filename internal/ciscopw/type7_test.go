// SPDX-License-Identifier: AGPL-3.0-or-later

package ciscopw

import "testing"

// TestDecodeType7_Vectors pins the key + algorithm against published vectors:
// "02050D480809" (salt 02) and "060506324F41" (salt 06) both decode to "cisco".
func TestDecodeType7_Vectors(t *testing.T) {
	cases := []struct{ enc, want string }{
		{"02050D480809", "cisco"},
		{"060506324F41", "cisco"},
	}
	for _, c := range cases {
		got, err := DecodeType7(c.enc)
		if err != nil {
			t.Fatalf("%s: %v", c.enc, err)
		}
		if got != c.want {
			t.Errorf("DecodeType7(%s) = %q, want %q", c.enc, got, c.want)
		}
	}
}

// TestType7_RoundTrip: Encode then Decode recovers the plaintext, across salts.
func TestType7_RoundTrip(t *testing.T) {
	plains := []string{"cisco", "Password123", "enable!secret", ""}
	for _, p := range plains {
		for _, salt := range []int{0, 2, 9, 15, 52} {
			enc, err := EncodeType7(p, salt)
			if err != nil {
				t.Fatalf("encode %q salt %d: %v", p, salt, err)
			}
			got, err := DecodeType7(enc)
			if err != nil {
				t.Fatalf("decode %q: %v", enc, err)
			}
			if got != p {
				t.Errorf("round-trip %q (salt %d) -> %q", p, salt, got)
			}
		}
	}
}

func TestDecodeType7_Errors(t *testing.T) {
	bad := []string{
		"",             // empty
		"0",            // too short
		"020",          // odd length
		"99050D480809", // salt 99 out of range (>= key length 53)
		"02ZZ0D480809", // non-hex byte
	}
	for _, s := range bad {
		if _, err := DecodeType7(s); err == nil {
			t.Errorf("%q: expected error", s)
		}
	}
}
