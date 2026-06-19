// SPDX-License-Identifier: AGPL-3.0-or-later

package webpass

import "testing"

// Reference hashes from the Django and Werkzeug libraries (the oracle), for
// password "password".
const (
	djangoHash   = "pbkdf2_sha256$1200000$saltsalt$ixcAVOgO1rOjuLHwUbM7+4k4ePLglGvBvsA2GWsip3Y="
	werkzeugHash = "pbkdf2:sha256:600000$AIev4LSg$7a3fee5aaefe578e6195d2c3c82400f06e48e980e4eb613e3c695c639124cff0"
)

func TestVerify_Django(t *testing.T) {
	if ok, err := Verify(djangoHash, "password"); err != nil || !ok {
		t.Errorf("django verify: ok=%v err=%v", ok, err)
	}
	if ok, _ := Verify(djangoHash, "wrong"); ok {
		t.Error("wrong password must not verify (django)")
	}
	if Scheme(djangoHash) != "django" {
		t.Error("scheme detection (django)")
	}
}

func TestVerify_Werkzeug(t *testing.T) {
	if ok, err := Verify(werkzeugHash, "password"); err != nil || !ok {
		t.Errorf("werkzeug verify: ok=%v err=%v", ok, err)
	}
	if ok, _ := Verify(werkzeugHash, "wrong"); ok {
		t.Error("wrong password must not verify (werkzeug)")
	}
	if Scheme(werkzeugHash) != "werkzeug" {
		t.Error("scheme detection (werkzeug)")
	}
}

// TestComputeRoundTrip computes then verifies (low iterations for speed) and
// confirms the format matches what Verify accepts.
func TestComputeRoundTrip(t *testing.T) {
	for _, scheme := range []string{"django", "werkzeug"} {
		h, err := Compute(scheme, "sha256", 1000, "saltsalt", "hunter2")
		if err != nil {
			t.Fatalf("%s compute: %v", scheme, err)
		}
		if Scheme(h) != scheme {
			t.Errorf("%s: computed hash has wrong scheme: %q", scheme, h)
		}
		if ok, err := Verify(h, "hunter2"); err != nil || !ok {
			t.Errorf("%s round-trip verify failed: %v", scheme, err)
		}
		if ok, _ := Verify(h, "nope"); ok {
			t.Errorf("%s wrong password verified", scheme)
		}
	}
}

func TestVerify_Errors(t *testing.T) {
	for _, bad := range []string{
		"", "plaintext", "$2y$10$bcrypt", "pbkdf2_sha256$x$salt$aGk=",
		"pbkdf2:sha256:600000$salt", "pbkdf2_md5$1$s$aGk=",
	} {
		if _, err := Verify(bad, "x"); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

// TestPBKDF2_IterationCap verifies an untrusted hash (or compute call) with an
// absurd iteration count is rejected BEFORE the (unbounded) PBKDF2 runs — so a
// crafted "pbkdf2_sha256$999999999999$…" cannot hang the host on verify. The
// guard must return promptly; a missing cap would instead spin ~10^12 HMACs.
func TestPBKDF2_IterationCap(t *testing.T) {
	hostile := []string{
		"pbkdf2_sha256$999999999999$somesalt$c29tZWRpZ2VzdA==", // Django
		"pbkdf2:sha256:999999999999$somesalt$abcdef",           // Werkzeug
	}
	for _, h := range hostile {
		if _, err := Verify(h, "x"); err == nil {
			t.Errorf("Verify(%q): expected rejection of absurd iteration count, got nil (would hang)", h)
		}
	}

	// Compute with an over-cap iteration count is rejected.
	if _, err := Compute("django", "sha256", 1<<30, "salt", "pw"); err == nil {
		t.Error("Compute: expected rejection of iter=2^30, got nil")
	}

	// A legitimate iteration count still computes.
	if _, err := Compute("django", "sha256", 1000, "salt", "pw"); err != nil {
		t.Errorf("legitimate Compute rejected: %v", err)
	}
}
