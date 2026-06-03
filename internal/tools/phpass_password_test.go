// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

const phpassRef = "$P$9abcdefghreUCnbbQX76dJT2aHvsT6." // passlib: "password"

func runPhpass(t *testing.T, args map[string]any) map[string]any {
	t.Helper()
	out, err := phpassPasswordHandler(context.Background(), nil, args)
	if err != nil {
		t.Fatalf("phpassPasswordHandler: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	return m
}

func TestPhpassPasswordHandler_Verify(t *testing.T) {
	if m := runPhpass(t, map[string]any{"password": "password", "hash": phpassRef}); m["matched"] != true {
		t.Errorf("ref hash should verify: %+v", m)
	}
	if m := runPhpass(t, map[string]any{"password": "nope", "hash": phpassRef}); m["matched"] != false {
		t.Errorf("wrong password should not match: %+v", m)
	}
}

func TestPhpassPasswordHandler_Compute(t *testing.T) {
	m := runPhpass(t, map[string]any{"password": "hunter2", "rounds_log": 8, "salt": "saltsalt"})
	h, _ := m["hash"].(string)
	if !strings.HasPrefix(h, "$P$") {
		t.Fatalf("compute: %v", h)
	}
	if v := runPhpass(t, map[string]any{"password": "hunter2", "hash": h}); v["matched"] != true {
		t.Errorf("compute round-trip verify failed: %+v", v)
	}
}

func TestPhpassPasswordHandler_Errors(t *testing.T) {
	if _, err := phpassPasswordHandler(context.Background(), nil, map[string]any{"password": "x", "hash": "$1$notphpass"}); err == nil {
		t.Error("non-phpass hash should error")
	}
}
