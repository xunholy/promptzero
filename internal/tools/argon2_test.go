// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func runArgon2(t *testing.T, args map[string]any) map[string]any {
	t.Helper()
	out, err := argon2Handler(context.Background(), nil, args)
	if err != nil {
		t.Fatalf("argon2Handler: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	return m
}

// Reference hashes produced by the audited argon2-cffi library (password
// "password", salt "somesalt01234567", m=65536, t=2, p=1, 32-byte tag) — the
// independent oracle for the PHC parser + x/crypto/argon2 verify path.
const (
	refArgon2id = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQwMTIzNDU2Nw$JQsxRb/1mbOwOljowhJTfc/GbikYS7t/8Ku8D1WluS8"
	refArgon2i  = "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQwMTIzNDU2Nw$q2MxzdcvpHrAoU8yhNHBrt4Son+J/ktr4J0iYwogFkA"
)

func TestArgon2Handler_VerifyReference(t *testing.T) {
	for _, h := range []string{refArgon2id, refArgon2i} {
		m := runArgon2(t, map[string]any{"password": "password", "hash": h})
		if m["matched"] != true || m["mode"] != "verify" {
			t.Errorf("reference hash should verify: %s -> %+v", h, m)
		}
		if m["memory"].(float64) != 65536 || m["time"].(float64) != 2 || m["parallelism"].(float64) != 1 {
			t.Errorf("parsed params wrong for %s: %+v", h, m)
		}
		bad := runArgon2(t, map[string]any{"password": "wrong", "hash": h})
		if bad["matched"] != false {
			t.Errorf("wrong password must not verify: %s", h)
		}
	}
}

// TestArgon2Handler_RoundTrip computes (small params for speed) then verifies.
func TestArgon2Handler_RoundTrip(t *testing.T) {
	c := runArgon2(t, map[string]any{
		"password": "hunter2", "salt": "saltsalt", "memory": 256, "time": 1, "parallelism": 1,
	})
	hash, _ := c["hash"].(string)
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=256,t=1,p=1$") {
		t.Fatalf("compute output: %v", hash)
	}
	if v := runArgon2(t, map[string]any{"password": "hunter2", "hash": hash}); v["matched"] != true {
		t.Errorf("round-trip verify failed: %+v", v)
	}
	if v := runArgon2(t, map[string]any{"password": "nope", "hash": hash}); v["matched"] != false {
		t.Errorf("wrong password round-trip must not verify")
	}
	// Random salt: two computes of the same password differ.
	a := runArgon2(t, map[string]any{"password": "x", "memory": 256, "time": 1})
	b := runArgon2(t, map[string]any{"password": "x", "memory": 256, "time": 1})
	if a["hash"] == b["hash"] {
		t.Error("random salt should make hashes differ")
	}
}

func TestArgon2Handler_VariantI(t *testing.T) {
	c := runArgon2(t, map[string]any{
		"password": "pw", "variant": "argon2i", "salt": "saltsalt", "memory": 256, "time": 1,
	})
	if !strings.HasPrefix(c["hash"].(string), "$argon2i$") {
		t.Errorf("argon2i compute: %v", c["hash"])
	}
}

func TestArgon2Handler_Errors(t *testing.T) {
	// argon2d unsupported (verify path).
	if _, err := argon2Handler(context.Background(), nil, map[string]any{
		"password": "x", "hash": "$argon2d$v=19$m=256,t=1,p=1$c2FsdHNhbHQ$" + strings.Repeat("A", 43),
	}); err == nil {
		t.Error("argon2d should error")
	}
	// Malformed PHC.
	if _, err := argon2Handler(context.Background(), nil, map[string]any{"password": "x", "hash": "$argon2id$bogus"}); err == nil {
		t.Error("malformed PHC should error")
	}
	// memory < 8*parallelism.
	if _, err := argon2Handler(context.Background(), nil, map[string]any{
		"password": "x", "memory": 4, "parallelism": 2,
	}); err == nil {
		t.Error("memory < 8*parallelism should error")
	}
	// Missing password.
	if _, err := argon2Handler(context.Background(), nil, map[string]any{}); err == nil {
		t.Error("missing password should error")
	}
}
