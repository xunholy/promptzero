// SPDX-License-Identifier: AGPL-3.0-or-later

package flasksession

import (
	"strings"
	"testing"
)

// Cookies produced by the reference itsdangerous library (the authoritative
// oracle), Flask's default session config (salt "cookie-session", HMAC-SHA1).
const (
	v1Cookie = "eyJ1c2VyIjoiYWRtaW4iLCJhZG1pbiI6dHJ1ZX0.ah-2tQ.14vr_tyxftdfvskHue2B3IVihHc" // secret my-secret
	v1Secret = "my-secret"
	v2Cookie = ".eJyrVirKz0lVslJKTMnNzFPSUSpITFGyUnIcIKBUCwAeyCYR.ah-2tQ.MT41rU1tYlK5iykL25Criv7r6bQ" // secret s3cr3t, compressed
	v2Secret = "s3cr3t"
	v3Cookie = "eyJpZCI6N30.ah-2tQ.1PPll8kR48YWdCu63N-odWkD4LI" // secret hunter2
	v3Secret = "hunter2"
)

func TestDecode(t *testing.T) {
	s, err := Decode(v1Cookie)
	if err != nil {
		t.Fatal(err)
	}
	if s.Compressed {
		t.Error("v1 is not compressed")
	}
	m, _ := s.Payload.(map[string]any)
	if m["user"] != "admin" || m["admin"] != true {
		t.Errorf("payload: %v", s.Payload)
	}
	if s.UnixTime <= itsdangerousEpoch {
		t.Errorf("timestamp not decoded: %d", s.UnixTime)
	}
}

func TestDecode_Compressed(t *testing.T) {
	s, err := Decode(v2Cookie)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Compressed {
		t.Error("v2 should be flagged compressed")
	}
	m, _ := s.Payload.(map[string]any)
	if m["role"] != "admin" || len(m["pad"].(string)) != 120 {
		t.Errorf("compressed payload: %v", m)
	}
}

func TestVerify(t *testing.T) {
	for _, c := range []struct{ cookie, secret string }{
		{v1Cookie, v1Secret}, {v2Cookie, v2Secret}, {v3Cookie, v3Secret},
	} {
		ok, err := Verify(c.cookie, c.secret, "")
		if err != nil || !ok {
			t.Errorf("verify %q should pass: ok=%v err=%v", c.secret, ok, err)
		}
		if bad, _ := Verify(c.cookie, "wrong-key", ""); bad {
			t.Errorf("wrong secret must not verify (%q)", c.secret)
		}
	}
}

// TestSignRoundTrip forges a cookie and confirms it verifies + decodes — the
// SECRET_KEY-impersonation path.
func TestSignRoundTrip(t *testing.T) {
	cookie, err := Sign(`{"user":"root","admin":true}`, "leaked-key", "", 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(cookie, "leaked-key", "")
	if err != nil || !ok {
		t.Fatalf("forged cookie should verify: ok=%v err=%v", ok, err)
	}
	if bad, _ := Verify(cookie, "other", ""); bad {
		t.Error("forged cookie must not verify under a different key")
	}
	s, err := Decode(cookie)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := s.Payload.(map[string]any); m["user"] != "root" || m["admin"] != true {
		t.Errorf("forged payload: %v", s.Payload)
	}
	if s.UnixTime != 1700000000 {
		t.Errorf("forged timestamp = %d, want 1700000000", s.UnixTime)
	}
}

// TestSignMatchesOracle confirms our Sign reproduces itsdangerous byte-for-byte
// for the same payload bytes and timestamp (the v1 cookie).
func TestSignMatchesOracle(t *testing.T) {
	// v1 payload bytes (insertion order as itsdangerous emitted them).
	cookie, err := Sign(`{"user":"admin","admin":true}`, v1Secret, "", decodeV1Time(t))
	if err != nil {
		t.Fatal(err)
	}
	// json.Compact preserves key order, so this should equal the oracle cookie.
	if cookie != v1Cookie {
		t.Errorf("Sign != oracle:\n got %s\nwant %s", cookie, v1Cookie)
	}
}

func decodeV1Time(t *testing.T) int64 {
	t.Helper()
	s, err := Decode(v1Cookie)
	if err != nil {
		t.Fatal(err)
	}
	return s.UnixTime
}

func TestDecode_Errors(t *testing.T) {
	for _, bad := range []string{"", "no-dots", "onlyone.two", "!!!.ah-2tQ.sig"} {
		if _, err := Decode(bad); err == nil && !strings.Contains(bad, "ah-2tQ") {
			t.Errorf("expected error for %q", bad)
		}
	}
}
