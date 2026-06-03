// SPDX-License-Identifier: AGPL-3.0-or-later

package pgpassword

import "testing"

// Oracle vectors: "md5"+md5(password+username), cross-checked with python
// hashlib (PostgreSQL's documented pg_md5_encrypt construction).
const (
	fooSecret = "md54ab2c5d00339c4b2a4e921d2dc4edec7" // password "secret", role "foo"
	pgX       = "md56e7189985da2d1f589ec12116dc39fd8" // password "x", role "postgres"
)

func TestComputeVectors(t *testing.T) {
	if got := Compute("secret", "foo"); got != fooSecret {
		t.Errorf("Compute(secret,foo) = %q, want %q", got, fooSecret)
	}
	if got := Compute("x", "postgres"); got != pgX {
		t.Errorf("Compute(x,postgres) = %q, want %q", got, pgX)
	}
}

// TestSaltedByUsername confirms the username salts the hash (same password,
// different role → different value).
func TestSaltedByUsername(t *testing.T) {
	if Compute("secret", "foo") == Compute("secret", "bar") {
		t.Error("same password under different roles must not collide")
	}
}

func TestComputeShape(t *testing.T) {
	h := Compute("p", "u")
	if len(h) != 35 || h[:3] != "md5" {
		t.Errorf("shape wrong: %q (len %d)", h, len(h))
	}
}

func TestVerify(t *testing.T) {
	ok, err := Verify("secret", "foo", fooSecret)
	if err != nil || !ok {
		t.Errorf("Verify(correct) = %v, %v; want true, nil", ok, err)
	}
	// Wrong password.
	if ok, _ := Verify("Secret", "foo", fooSecret); ok {
		t.Error("wrong password matched")
	}
	// Right password, wrong role (salt) → must not match.
	if ok, _ := Verify("secret", "bar", fooSecret); ok {
		t.Error("correct password under wrong role matched")
	}
}

// TestVerifyAcceptsBareAndUppercase ensures the "md5" prefix is optional and
// hex case is ignored.
func TestVerifyAcceptsBareAndUppercase(t *testing.T) {
	bare := "4AB2C5D00339C4B2A4E921D2DC4EDEC7" // no prefix, uppercase
	ok, err := Verify("secret", "foo", bare)
	if err != nil || !ok {
		t.Errorf("Verify(bare uppercase) = %v, %v; want true, nil", ok, err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"",                                     // empty
		"md5",                                  // prefix only
		"md5XYZ",                               // too short / non-hex
		"md54ab2c5d00339c4b2a4e921d2dc4edec",   // 31 hex
		"md54ab2c5d00339c4b2a4e921d2dc4edec77", // 33 hex
		"md5ZZb2c5d00339c4b2a4e921d2dc4edec7",  // non-hex digit
	} {
		if _, err := Verify("secret", "foo", bad); err == nil {
			t.Errorf("Verify(_, _, %q): want error, got nil", bad)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	for _, pw := range []string{"", "a", "hunter2", "p@ss:w0rd!", "naïve"} {
		for _, user := range []string{"postgres", "app_user", ""} {
			h := Compute(pw, user)
			ok, err := Verify(pw, user, h)
			if err != nil || !ok {
				t.Errorf("round-trip %q/%q: %v, %v", pw, user, ok, err)
			}
			if ok, _ := Verify(pw+"x", user, h); ok {
				t.Errorf("round-trip %q/%q: wrong password matched", pw, user)
			}
		}
	}
}
