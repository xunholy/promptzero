// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/json"
	"testing"
)

// TestWPAPMKDeriveHandler gates the tool against the IEEE 802.11i WPA-PSK vector.
func TestWPAPMKDeriveHandler(t *testing.T) {
	out, err := wpaPMKDeriveHandler(context.Background(), nil, map[string]any{
		"passphrase": "password", "ssid": "IEEE",
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	const want = "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
	if m["pmk"] != want {
		t.Errorf("pmk = %v, want %s", m["pmk"], want)
	}
	if m["pmk_bits"].(float64) != 256 {
		t.Errorf("pmk_bits = %v, want 256", m["pmk_bits"])
	}
}

func TestWPAPMKDeriveHandler_Errors(t *testing.T) {
	// Missing fields.
	if _, err := wpaPMKDeriveHandler(context.Background(), nil, map[string]any{"ssid": "x"}); err == nil {
		t.Error("missing passphrase should error")
	}
	// Too-short passphrase rejected by the validator.
	if _, err := wpaPMKDeriveHandler(context.Background(), nil, map[string]any{
		"passphrase": "short", "ssid": "net",
	}); err == nil {
		t.Error("short passphrase should error")
	}
}
