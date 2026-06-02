// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/json"
	"testing"
)

func TestNTHashHandler(t *testing.T) {
	out, err := ntHashHandler(context.Background(), nil, map[string]any{"password": "password"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	const want = "8846f7eaee8fb117ad06bdd830b7586c"
	if m["nt_hash"] != want {
		t.Errorf("nt_hash = %v, want %s", m["nt_hash"], want)
	}
	if m["pwdump_line"] != "aad3b435b51404eeaad3b435b51404ee:"+want {
		t.Errorf("pwdump_line = %v", m["pwdump_line"])
	}
}

func TestNTHashHandler_Empty(t *testing.T) {
	// Empty password is valid (NT hash of empty is the well-known 31d6…).
	out, err := ntHashHandler(context.Background(), nil, map[string]any{"password": ""})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(out), &m)
	if m["nt_hash"] != "31d6cfe0d16ae931b73c59d7e0c089c0" {
		t.Errorf("empty nt_hash = %v", m["nt_hash"])
	}
	// Missing password key errors.
	if _, err := ntHashHandler(context.Background(), nil, map[string]any{}); err == nil {
		t.Error("missing password should error")
	}
}
