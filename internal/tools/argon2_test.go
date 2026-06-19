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

// TestArgon2Handler_DoSGuards verifies the resource-exhaustion guards reject a
// hostile time/memory cost BEFORE the expensive derivation runs — so a crafted
// hash (verify) or crafted params (compute) cannot OOM or spin the host. Each
// case must return an error promptly; if a guard were missing the test would
// instead hang on a ~4-billion-pass Argon2 compute.
func TestArgon2Handler_DoSGuards(t *testing.T) {
	ctx := context.Background()

	// Verify: a well-formed PHC hash with an absurd time cost is rejected at
	// parse time, never derived.
	hugeTimeHash := "$argon2id$v=19$m=65536,t=4294967295,p=1$c29tZXNhbHQ$c29tZWRpZ2VzdA"
	if _, err := argon2Handler(ctx, nil, map[string]any{"password": "x", "hash": hugeTimeHash}); err == nil {
		t.Error("verify: expected rejection of t=4294967295 hash, got nil (would hang)")
	}
	hugeMemHash := "$argon2id$v=19$m=4294967295,t=3,p=1$c29tZXNhbHQ$c29tZWRpZ2VzdA"
	if _, err := argon2Handler(ctx, nil, map[string]any{"password": "x", "hash": hugeMemHash}); err == nil {
		t.Error("verify: expected rejection of m=4294967295 hash, got nil (would OOM)")
	}

	// Compute: hostile / negative params are rejected before derivation.
	cases := []map[string]any{
		{"password": "x", "time": 4294967295},
		{"password": "x", "time": -1},
		{"password": "x", "memory": 99999999999},
		{"password": "x", "memory": -1},
	}
	for i, args := range cases {
		if _, err := argon2Handler(ctx, nil, args); err == nil {
			t.Errorf("compute case %d (%v): expected rejection, got nil", i, args)
		}
	}

	// A legitimate small compute still succeeds (guards don't over-reject).
	if _, err := argon2Handler(ctx, nil, map[string]any{
		"password": "x", "memory": 256, "time": 2, "parallelism": 1,
	}); err != nil {
		t.Errorf("legitimate compute rejected: %v", err)
	}
}
