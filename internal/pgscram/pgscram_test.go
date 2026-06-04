// SPDX-License-Identifier: AGPL-3.0-or-later

package pgscram

import (
	"encoding/base64"
	"strings"
	"testing"
)

// rfc7677Verifier is the PostgreSQL SCRAM-SHA-256 stored verifier for password
// "pencil" with the RFC 7677 §3 salt (W22ZaJ0SNY7soEsUEjb6gQ==) and i=4096.
// The StoredKey and ServerKey are derived from the RFC-anchored chain — the
// same SaltedPassword/ClientKey/StoredKey/ServerKey that reproduce the RFC's
// ClientProof (p=) and ServerSignature (v=) byte-for-byte.
const (
	rfc7677Salt     = "W22ZaJ0SNY7soEsUEjb6gQ=="
	rfc7677Verifier = "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$" +
		"WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:" +
		"wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="
)

// TestComputeMatchesRFC7677 pins the verifier string for "pencil" + the RFC
// salt against the RFC-anchored StoredKey/ServerKey, byte-for-byte.
func TestComputeMatchesRFC7677(t *testing.T) {
	salt, _ := base64.StdEncoding.DecodeString(rfc7677Salt)
	got, err := Compute("pencil", salt, 4096)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if got != rfc7677Verifier {
		t.Errorf("Compute mismatch:\n got  %q\n want %q", got, rfc7677Verifier)
	}
}

// TestVerifyRFC7677 confirms the correct password verifies and a wrong one does
// not, against the RFC-anchored verifier.
func TestVerifyRFC7677(t *testing.T) {
	r, err := Verify("pencil", rfc7677Verifier)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !r.Matched {
		t.Error("correct password 'pencil' did not verify")
	}
	if r.Iterations != 4096 {
		t.Errorf("iterations = %d, want 4096", r.Iterations)
	}
	if r.SaltLen != 16 {
		t.Errorf("salt_len = %d, want 16", r.SaltLen)
	}
	wrong, err := Verify("Pencil", rfc7677Verifier) // wrong case
	if err != nil {
		t.Fatalf("Verify wrong: %v", err)
	}
	if wrong.Matched {
		t.Error("wrong password 'Pencil' matched")
	}
}

// TestComputeVerifyRoundTrip round-trips compute → verify with a random salt
// and a non-default iteration count.
func TestComputeVerifyRoundTrip(t *testing.T) {
	for _, iter := range []int{0, 4096, 10000} {
		h, err := Compute("hunter2", nil, iter)
		if err != nil {
			t.Fatalf("Compute(iter=%d): %v", iter, err)
		}
		r, err := Verify("hunter2", h)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !r.Matched {
			t.Errorf("iter=%d: round-trip did not match", iter)
		}
		if bad, _ := Verify("wrong", h); bad.Matched {
			t.Errorf("iter=%d: wrong password matched", iter)
		}
	}
}

// TestComputeDefaultIterations confirms iterations<=0 selects PostgreSQL's 4096.
func TestComputeDefaultIterations(t *testing.T) {
	h, err := Compute("x", []byte("0123456789abcdef"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "SCRAM-SHA-256$4096:") {
		t.Errorf("default iterations not 4096: %q", h)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"md5abc",                            // wrong scheme
		"SCRAM-SHA-256$4096:" + rfc7677Salt, // missing key part
		"SCRAM-SHA-256$abc:" + rfc7677Salt + "$a:b",        // bad iterations
		"SCRAM-SHA-256$4096:@@@$a:b",                       // bad salt base64
		"SCRAM-SHA-256$4096:" + rfc7677Salt + "$@@@:b",     // bad StoredKey base64
		"SCRAM-SHA-256$4096:" + rfc7677Salt + "$YWJj:YWJj", // StoredKey wrong length
	}
	for _, c := range cases {
		if _, err := Parse(c); err == nil {
			t.Errorf("Parse(%q): want error, got nil", c)
		}
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	if _, err := Verify("x", "not-a-verifier"); err == nil {
		t.Fatal("Verify should error on a malformed verifier")
	}
}

func TestComputeRejectsHugeIterations(t *testing.T) {
	if _, err := Compute("x", []byte("salt"), maxIterations+1); err == nil {
		t.Fatal("Compute should reject iterations beyond the sane maximum")
	}
}
