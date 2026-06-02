// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func runMD5Crypt(t *testing.T, args map[string]any) map[string]any {
	t.Helper()
	out, err := md5cryptHandler(context.Background(), nil, args)
	if err != nil {
		t.Fatalf("md5cryptHandler: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	return m
}

func TestMD5CryptHandler_Compute(t *testing.T) {
	m := runMD5Crypt(t, map[string]any{"password": "password", "salt": "abcdefgh"})
	if m["hash"] != "$1$abcdefgh$G//4keteveJp0qb8z2DxG/" {
		t.Errorf("hash = %v", m["hash"])
	}
	apr := runMD5Crypt(t, map[string]any{"password": "password", "salt": "abcdefgh", "scheme": "apr1"})
	if apr["hash"] != "$apr1$abcdefgh$FBwExRW4dCc8aL.OvjpIE1" {
		t.Errorf("apr1 hash = %v", apr["hash"])
	}
}

func TestMD5CryptHandler_Verify(t *testing.T) {
	ok := runMD5Crypt(t, map[string]any{"password": "password", "hash": "$1$abcdefgh$G//4keteveJp0qb8z2DxG/"})
	if ok["matched"] != true || ok["scheme"] != "md5crypt" {
		t.Errorf("verify good: %+v", ok)
	}
	bad := runMD5Crypt(t, map[string]any{"password": "nope", "hash": "$1$abcdefgh$G//4keteveJp0qb8z2DxG/"})
	if bad["matched"] != false {
		t.Errorf("verify bad should be false: %+v", bad)
	}
}

// TestMD5CryptHandler_RandomSalt confirms an omitted salt yields a valid,
// round-trip-verifiable hash with a fresh salt each call.
func TestMD5CryptHandler_RandomSalt(t *testing.T) {
	a := runMD5Crypt(t, map[string]any{"password": "secret"})
	b := runMD5Crypt(t, map[string]any{"password": "secret"})
	ha, _ := a["hash"].(string)
	if !strings.HasPrefix(ha, "$1$") {
		t.Fatalf("expected $1$ hash, got %v", ha)
	}
	if ha == b["hash"] {
		t.Error("random salt should differ between calls")
	}
	// The generated hash must verify the original password.
	v := runMD5Crypt(t, map[string]any{"password": "secret", "hash": ha})
	if v["matched"] != true {
		t.Errorf("random-salt hash should verify: %+v", v)
	}
}
