// SPDX-License-Identifier: AGPL-3.0-or-later

package hmacutil

import (
	"encoding/hex"
	"testing"
)

// TestRFC4231 is the verification gate: the RFC 4231 published HMAC vectors.
func TestRFC4231(t *testing.T) {
	// Test Case 2 (ASCII key + data) across SHA-1/256/512.
	key := []byte("Jefe")
	data := []byte("what do ya want for nothing?")
	cases := []struct {
		algo, want string
	}{
		{"SHA1", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"},
		{"SHA256", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
		{"SHA512", "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"},
	}
	for _, c := range cases {
		got, err := Compute(c.algo, key, data)
		if err != nil {
			t.Fatalf("%s: %v", c.algo, err)
		}
		if hex.EncodeToString(got) != c.want {
			t.Errorf("HMAC-%s = %s, want %s", c.algo, hex.EncodeToString(got), c.want)
		}
	}
}

// TestRFC4231_Case1 uses the binary key (0x0b x20) over "Hi There" (SHA256).
func TestRFC4231_Case1(t *testing.T) {
	key := make([]byte, 20)
	for i := range key {
		key[i] = 0x0b
	}
	got, _ := Compute("SHA256", key, []byte("Hi There"))
	want := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	if hex.EncodeToString(got) != want {
		t.Errorf("HMAC-SHA256(case1) = %s, want %s", hex.EncodeToString(got), want)
	}
}

func TestVerify(t *testing.T) {
	key := []byte("Jefe")
	data := []byte("what do ya want for nothing?")
	const want = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	ok, err := Verify("SHA256", key, data, want)
	if err != nil || !ok {
		t.Errorf("Verify should pass: ok=%v err=%v", ok, err)
	}
	if ok, _ := Verify("SHA256", key, data, "00"+want[2:]); ok {
		t.Error("Verify should fail for a tampered MAC")
	}
	if _, err := Verify("SHA256", key, data, "zz"); err == nil {
		t.Error("Verify should error on non-hex expected")
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
