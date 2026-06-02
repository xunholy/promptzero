// SPDX-License-Identifier: AGPL-3.0-or-later

package otp

import (
	"crypto/sha1" //nolint:gosec // RFC test vectors are HMAC-SHA1.
	"testing"
	"time"
)

// rfcSeed is the ASCII seed used by the RFC 4226 / 6238 test vectors.
var rfcSeed = []byte("12345678901234567890")

// TestHOTP_RFC4226 is the verification gate for HOTP: the Appendix D vectors.
func TestHOTP_RFC4226(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for c, w := range want {
		if got := HOTP(rfcSeed, uint64(c), 6, sha1.New); got != w {
			t.Errorf("HOTP(counter=%d) = %s, want %s", c, got, w)
		}
	}
}

// TestTOTP_RFC6238 is the verification gate for TOTP: the Appendix B SHA-1
// vectors (8 digits, 30-second step).
func TestTOTP_RFC6238(t *testing.T) {
	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, c := range cases {
		got := TOTP(rfcSeed, time.Unix(c.unix, 0), 30, 8, sha1.New)
		if got != c.want {
			t.Errorf("TOTP(T=%d) = %s, want %s", c.unix, got, c.want)
		}
	}
}

// TestDecodeSecret round-trips the RFC seed through base32 (its base32 form,
// padded and unpadded, lowercase and spaced, must all decode to the seed).
func TestDecodeSecret(t *testing.T) {
	// base32("12345678901234567890") = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
	const b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, in := range []string{
		b32,
		"gezdgnbvgy3tqojqgezdgnbvgy3tqojq", // lowercase
		"GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ", // spaced (Authenticator display form)
	} {
		got, err := DecodeSecret(in)
		if err != nil {
			t.Fatalf("DecodeSecret(%q): %v", in, err)
		}
		if string(got) != string(rfcSeed) {
			t.Errorf("DecodeSecret(%q) = %q, want %q", in, got, rfcSeed)
		}
	}
	if _, err := DecodeSecret(""); err == nil {
		t.Error("empty secret should error")
	}
	if _, err := DecodeSecret("0189"); err == nil {
		t.Error("invalid base32 (0/1/8/9) should error")
	}
}

func TestHashFor(t *testing.T) {
	for _, a := range []string{"", "SHA1", "sha256", "SHA-512"} {
		if _, err := HashFor(a); err != nil {
			t.Errorf("HashFor(%q): %v", a, err)
		}
	}
	if _, err := HashFor("md5"); err == nil {
		t.Error("md5 should be unsupported")
	}
}
