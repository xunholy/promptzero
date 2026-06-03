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
