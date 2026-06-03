// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/json"
	"testing"
)

func TestMagstripeDecodeHandler(t *testing.T) {
	out, err := magstripeDecodeHandler(context.Background(), nil, map[string]any{
		"track": "%B4111111111111111^DOE/JOHN^25121011200000?2;4111111111111111=25121011200000?",
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	t1, _ := m["track1"].(map[string]any)
	t2, _ := m["track2"].(map[string]any)
	if t1 == nil || t2 == nil {
		t.Fatalf("expected both tracks; got %s", out)
	}
	if t1["pan"] != "4111111111111111" || t1["luhn_valid"] != true {
		t.Errorf("track1 pan/luhn: %v %v", t1["pan"], t1["luhn_valid"])
	}
	if t1["name"] != "DOE/JOHN" || t1["service_code"] != "101" {
		t.Errorf("track1 name/service: %v %v", t1["name"], t1["service_code"])
	}
	if t2["expiry_mm_yy"] != "12/25" {
		t.Errorf("track2 expiry: %v", t2["expiry_mm_yy"])
	}
}

func TestMagstripeDecodeHandler_Errors(t *testing.T) {
	if _, err := magstripeDecodeHandler(context.Background(), nil, map[string]any{"track": ""}); err == nil {
		t.Error("empty track should error")
	}
	if _, err := magstripeDecodeHandler(context.Background(), nil, map[string]any{"track": "garbage"}); err == nil {
		t.Error("no-sentinel input should error")
	}
}
