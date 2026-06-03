// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/json"
	"testing"
)

const fsCookie = "eyJ1c2VyIjoiYWRtaW4iLCJhZG1pbiI6dHJ1ZX0.ah-2tQ.14vr_tyxftdfvskHue2B3IVihHc"

func runFlask(t *testing.T, args map[string]any) map[string]any {
	t.Helper()
	out, err := flaskSessionHandler(context.Background(), nil, args)
	if err != nil {
		t.Fatalf("flaskSessionHandler: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	return m
}

func TestFlaskSessionHandler_Decode(t *testing.T) {
	m := runFlask(t, map[string]any{"cookie": fsCookie})
	if m["mode"] != "decode" {
		t.Fatalf("mode: %v", m["mode"])
	}
	sess, _ := m["session"].(map[string]any)
	pl, _ := sess["payload"].(map[string]any)
	if pl["user"] != "admin" || pl["admin"] != true {
		t.Errorf("decoded payload: %v", sess["payload"])
	}
}

func TestFlaskSessionHandler_Verify(t *testing.T) {
	// Weak-SECRET_KEY test: a list with the real key among wrong ones.
	m := runFlask(t, map[string]any{
		"cookie":  fsCookie,
		"secrets": []any{"changeme", "secret", "my-secret", "admin"},
	})
	if m["valid"] != true || m["matched_secret"] != "my-secret" {
		t.Errorf("weak-secret test: %+v", m)
	}
	bad := runFlask(t, map[string]any{"cookie": fsCookie, "secret": "nope"})
	if bad["valid"] != false {
		t.Errorf("wrong secret should be invalid: %+v", bad)
	}
}

func TestFlaskSessionHandler_Forge(t *testing.T) {
	m := runFlask(t, map[string]any{
		"payload": `{"admin":true,"user":"root"}`, "secret": "leaked", "timestamp": 1700000000,
	})
	cookie, _ := m["cookie"].(string)
	if m["mode"] != "forge" || cookie == "" {
		t.Fatalf("forge: %+v", m)
	}
	// The forged cookie must verify under the same key.
	v := runFlask(t, map[string]any{"cookie": cookie, "secret": "leaked"})
	if v["valid"] != true {
		t.Errorf("forged cookie should verify: %+v", v)
	}
}

func TestFlaskSessionHandler_Errors(t *testing.T) {
	if _, err := flaskSessionHandler(context.Background(), nil, map[string]any{}); err == nil {
		t.Error("no cookie/payload should error")
	}
	if _, err := flaskSessionHandler(context.Background(), nil, map[string]any{"payload": `{"a":1}`}); err == nil {
		t.Error("forge without secret should error")
	}
}
