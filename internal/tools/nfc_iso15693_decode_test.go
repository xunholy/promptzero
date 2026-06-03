// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/json"
	"testing"
)

func TestISO15693DecodeHandler(t *testing.T) {
	out, err := iso15693DecodeHandler(context.Background(), nil, map[string]any{
		"uid": "E004010050B2A123", "afi": "10",
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	if m["prefix_valid"] != true || m["manufacturer"] != "NXP Semiconductors" {
		t.Errorf("uid decode: %+v", m)
	}
	afi, _ := m["afi"].(map[string]any)
	if afi == nil || afi["family"] != "transport" {
		t.Errorf("afi: %v", m["afi"])
	}
}

func TestISO15693DecodeHandler_Errors(t *testing.T) {
	if _, err := iso15693DecodeHandler(context.Background(), nil, map[string]any{"uid": ""}); err == nil {
		t.Error("empty uid should error")
	}
	if _, err := iso15693DecodeHandler(context.Background(), nil, map[string]any{"uid": "E004", "afi": "zz"}); err == nil {
		t.Error("short uid should error")
	}
	if _, err := iso15693DecodeHandler(context.Background(), nil, map[string]any{"uid": "E004010050B2A123", "afi": "zz"}); err == nil {
		t.Error("bad afi should error")
	}
}
