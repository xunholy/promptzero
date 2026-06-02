// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func runBcrypt(t *testing.T, args map[string]any) map[string]any {
	t.Helper()
	out, err := bcryptHandler(context.Background(), nil, args)
	if err != nil {
		t.Fatalf("bcryptHandler: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	return m
}

// TestBcryptHandler_VerifyPublishedVectors gates verify against the canonical
// OpenBSD / jBCrypt published test vectors (cost 6) — the authoritative bcrypt
// reference suite.
func TestBcryptHandler_VerifyPublishedVectors(t *testing.T) {
	cases := []struct{ pw, hash string }{
		{"", "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."},
		{"abc", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"},
		{"abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"},
	}
	for _, c := range cases {
		m := runBcrypt(t, map[string]any{"password": c.pw, "hash": c.hash})
		if m["matched"] != true || m["mode"] != "verify" {
			t.Errorf("vector pw=%q should verify: %+v", c.pw, m)
		}
		if m["cost"].(float64) != 6 {
			t.Errorf("pw=%q cost = %v, want 6", c.pw, m["cost"])
		}
		// Wrong password must not verify.
		if bad := runBcrypt(t, map[string]any{"password": c.pw + "x", "hash": c.hash}); bad["matched"] != false {
			t.Errorf("pw=%q+x must not verify", c.pw)
		}
	}
}

// TestBcryptHandler_RoundTrip computes then verifies, at a low cost for speed.
func TestBcryptHandler_RoundTrip(t *testing.T) {
	c := runBcrypt(t, map[string]any{"password": "hunter2", "cost": 4})
	hash, _ := c["hash"].(string)
	if !strings.HasPrefix(hash, "$2") || c["cost"].(float64) != 4 {
		t.Fatalf("compute output: %+v", c)
	}
	v := runBcrypt(t, map[string]any{"password": "hunter2", "hash": hash})
	if v["matched"] != true {
		t.Errorf("round-trip verify failed: %+v", v)
	}
	// Distinct salts → distinct hashes for the same password.
	c2 := runBcrypt(t, map[string]any{"password": "hunter2", "cost": 4})
	if c2["hash"] == hash {
		t.Error("bcrypt should use a random salt (hashes should differ)")
	}
}

func TestBcryptHandler_Errors(t *testing.T) {
	// Cost out of range.
	if _, err := bcryptHandler(context.Background(), nil, map[string]any{"password": "x", "cost": 99}); err == nil {
		t.Error("out-of-range cost should error")
	}
	// Malformed hash in verify mode.
	if _, err := bcryptHandler(context.Background(), nil, map[string]any{"password": "x", "hash": "$2a$notvalid"}); err == nil {
		t.Error("malformed hash should error")
	}
	// Missing password.
	if _, err := bcryptHandler(context.Background(), nil, map[string]any{}); err == nil {
		t.Error("missing password should error")
	}
}
