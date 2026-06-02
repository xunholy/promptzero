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
	const wantNT = "8846f7eaee8fb117ad06bdd830b7586c"
	const wantLM = "e52cac67419a9a224a3b108f3fa6cb6d"
	if m["nt_hash"] != wantNT {
		t.Errorf("nt_hash = %v, want %s", m["nt_hash"], wantNT)
	}
	if m["lm_hash"] != wantLM {
		t.Errorf("lm_hash = %v, want %s", m["lm_hash"], wantLM)
	}
	if m["pwdump_line"] != wantLM+":"+wantNT {
		t.Errorf("pwdump_line = %v, want %s:%s", m["pwdump_line"], wantLM, wantNT)
	}
}

// TestNTHashHandler_LMOmitted checks the LM placeholder + note for the cases
// where Windows stores no LM hash.
func TestNTHashHandler_LMOmitted(t *testing.T) {
	for _, pw := range []string{"thispasswordistoolong", "пароль"} { // >14, and non-ASCII
		out, err := ntHashHandler(context.Background(), nil, map[string]any{"password": pw})
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal([]byte(out), &m)
		if m["lm_hash"] != "aad3b435b51404eeaad3b435b51404ee" {
			t.Errorf("%q: lm_hash = %v, want disabled-LM placeholder", pw, m["lm_hash"])
		}
		if m["notes"] == nil {
			t.Errorf("%q: expected a note explaining the omitted LM hash", pw)
		}
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
