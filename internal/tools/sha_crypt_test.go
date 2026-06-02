// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func runSHACrypt(t *testing.T, args map[string]any) map[string]any {
	t.Helper()
	out, err := shaCryptHandler(context.Background(), nil, args)
	if err != nil {
		t.Fatalf("shaCryptHandler: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	return m
}

func TestSHACryptHandler_Compute(t *testing.T) {
	m := runSHACrypt(t, map[string]any{"password": "password", "salt": "abcdefgh"})
	want := "$6$abcdefgh$yVfUwsw5T.JApa8POvClA1pQ5peiq97DUNyXCZN5IrF.BMSkiaLQ5kvpuEm/VQ1Tvh/KV2TcaWh8qinoW5dhA1"
	if m["hash"] != want || m["scheme"] != "sha512crypt" {
		t.Errorf("sha512 compute: %+v", m)
	}
	m256 := runSHACrypt(t, map[string]any{"password": "password", "salt": "abcdefgh", "scheme": "sha256crypt"})
	if m256["hash"] != "$5$abcdefgh$ZLdkj8mkc2XVSrPVjskDAgZPGjtj1VGVaa1aUkrMTU/" {
		t.Errorf("sha256 compute: %v", m256["hash"])
	}
	// Explicit rounds form.
	mr := runSHACrypt(t, map[string]any{"password": "password", "salt": "abcdefgh", "rounds": 1000})
	if !strings.HasPrefix(mr["hash"].(string), "$6$rounds=1000$abcdefgh$") {
		t.Errorf("rounds form: %v", mr["hash"])
	}
}

func TestSHACryptHandler_Verify(t *testing.T) {
	h := "$6$abcdefgh$yVfUwsw5T.JApa8POvClA1pQ5peiq97DUNyXCZN5IrF.BMSkiaLQ5kvpuEm/VQ1Tvh/KV2TcaWh8qinoW5dhA1"
	if v := runSHACrypt(t, map[string]any{"password": "password", "hash": h}); v["matched"] != true || v["scheme"] != "sha512crypt" {
		t.Errorf("verify good: %+v", v)
	}
	if v := runSHACrypt(t, map[string]any{"password": "wrong", "hash": h}); v["matched"] != false {
		t.Errorf("verify bad should be false: %+v", v)
	}
}

// TestSHACryptHandler_RandomSalt confirms an omitted salt round-trips through
// verify with a fresh salt each call.
func TestSHACryptHandler_RandomSalt(t *testing.T) {
	a := runSHACrypt(t, map[string]any{"password": "secret"})
	b := runSHACrypt(t, map[string]any{"password": "secret"})
	ha, _ := a["hash"].(string)
	if !strings.HasPrefix(ha, "$6$") || ha == b["hash"] {
		t.Fatalf("expected distinct $6$ hashes, got %q and %v", ha, b["hash"])
	}
	if v := runSHACrypt(t, map[string]any{"password": "secret", "hash": ha}); v["matched"] != true {
		t.Errorf("random-salt hash should verify: %+v", v)
	}
}
