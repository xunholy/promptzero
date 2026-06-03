// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

const (
	djHash = "pbkdf2_sha256$1200000$saltsalt$ixcAVOgO1rOjuLHwUbM7+4k4ePLglGvBvsA2GWsip3Y="
	wzHash = "pbkdf2:sha256:600000$AIev4LSg$7a3fee5aaefe578e6195d2c3c82400f06e48e980e4eb613e3c695c639124cff0"
)

func runPBKDF2(t *testing.T, args map[string]any) map[string]any {
	t.Helper()
	out, err := pbkdf2PasswordHandler(context.Background(), nil, args)
	if err != nil {
		t.Fatalf("pbkdf2PasswordHandler: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	return m
}

func TestPBKDF2PasswordHandler_Verify(t *testing.T) {
	dj := runPBKDF2(t, map[string]any{"password": "password", "hash": djHash})
	if dj["matched"] != true || dj["scheme"] != "django" {
		t.Errorf("django verify: %+v", dj)
	}
	wz := runPBKDF2(t, map[string]any{"password": "password", "hash": wzHash})
	if wz["matched"] != true || wz["scheme"] != "werkzeug" {
		t.Errorf("werkzeug verify: %+v", wz)
	}
	bad := runPBKDF2(t, map[string]any{"password": "nope", "hash": djHash})
	if bad["matched"] != false {
		t.Errorf("wrong password should not match: %+v", bad)
	}
}

func TestPBKDF2PasswordHandler_Compute(t *testing.T) {
	m := runPBKDF2(t, map[string]any{
		"password": "hunter2", "scheme": "werkzeug", "iterations": 1000, "salt": "abcd",
	})
	h, _ := m["hash"].(string)
	if !strings.HasPrefix(h, "pbkdf2:sha256:1000$abcd$") {
		t.Fatalf("compute: %v", h)
	}
	if v := runPBKDF2(t, map[string]any{"password": "hunter2", "hash": h}); v["matched"] != true {
		t.Errorf("compute round-trip verify failed: %+v", v)
	}
}

// (Django/Werkzeug hash_crack tests live in security_test.go — package
// tools_test — alongside the invokeSpec/writeTempWordlist helpers and the other
// TestHashCrack_* cases.)

func TestPBKDF2PasswordHandler_Scrypt(t *testing.T) {
	const h = "scrypt:32768:8:1$pqUT1Bmj$f9f4c54fcdbf5dae6446bdfea07c11fb92f593472d94ec7571c18160d6774778d252252f06cadd70a365f14981a8e5901c58bb8822076f2cabf6c03812c02933"
	if m := runPBKDF2(t, map[string]any{"password": "password", "hash": h}); m["matched"] != true || m["scheme"] != "werkzeug" {
		t.Errorf("scrypt verify: %+v", m)
	}
	// Compute a werkzeug-scrypt hash (small N for speed) and round-trip.
	c := runPBKDF2(t, map[string]any{"password": "hunter2", "scheme": "werkzeug-scrypt", "n": 16384, "salt": "saltsalt"})
	hc, _ := c["hash"].(string)
	if hc[:7] != "scrypt:" {
		t.Fatalf("scrypt compute: %v", hc)
	}
	if v := runPBKDF2(t, map[string]any{"password": "hunter2", "hash": hc}); v["matched"] != true {
		t.Errorf("scrypt compute round-trip failed: %+v", v)
	}
}
