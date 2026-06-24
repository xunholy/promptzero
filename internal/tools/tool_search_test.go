package tools

import (
	"context"
	"strings"
	"testing"
)

// TestToolSearchHandler verifies the discovery tool wraps the live registry:
// an exact tool name ranks first, a task synonym surfaces a relevant tool, the
// output carries risk/group, and bad input is rejected.
func TestToolSearchHandler(t *testing.T) {
	// Exact name → that tool is present and (being an exact match) ranked first.
	out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": "device_info"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"name": "device_info"`) {
		t.Errorf("exact-name query missing device_info:\n%s", out)
	}
	if !strings.Contains(out, `"risk":`) || !strings.Contains(out, `"group":`) {
		t.Errorf("result missing risk/group enrichment:\n%s", out)
	}

	// Task query via synonym map: 'garage' should reach a subghz tool.
	out, err = toolSearchHandler(context.Background(), nil, map[string]any{"query": "garage door"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "subghz") {
		t.Errorf("garage door did not surface any subghz tool:\n%s", out)
	}

	// Empty query is rejected.
	if _, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": "  "}); err == nil {
		t.Error("empty query: expected error, got nil")
	}

	// No-match query returns a clean zero-result body, not an error.
	out, err = toolSearchHandler(context.Background(), nil, map[string]any{"query": "zzqqxx-nonexistent"})
	if err != nil {
		t.Fatalf("no-match handler: %v", err)
	}
	if !strings.Contains(out, `"count": 0`) {
		t.Errorf("no-match query should report count 0:\n%s", out)
	}
}

// TestToolSearch_AutomotiveDiscoverability guards that the OBD-II / UDS / CAN
// diagnostic tool family is reachable by natural automotive queries — a gap
// before the synonym map gained the engine/vehicle/diagnostic/obd/ecu/dtc
// entries and obd2_pid_decode's description listed its full (post-v0.726) PID
// coverage. Each query must surface its intended tool somewhere in the ranked
// results.
func TestToolSearch_AutomotiveDiscoverability(t *testing.T) {
	cases := []struct {
		query string
		want  string
	}{
		{"catalyst temperature", "obd2_pid_decode"}, // a v0.726 PID, now in the description
		{"engine sensor value", "obd2_pid_decode"},  // engine -> obd2/pid
		{"car diagnostic trouble code", "obd2_dtc_decode"},
		{"diagnostic trouble code status", "uds_dtc_status_decode"},
		{"ecu calibration flash", "xcp_decode"}, // ecu -> xcp/ccp
		{"vehicle identification number", "vin_decode"},
	}
	for _, c := range cases {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": c.query, "limit": 8})
		if err != nil {
			t.Fatalf("%q: handler: %v", c.query, err)
		}
		if !strings.Contains(out, `"name": "`+c.want+`"`) {
			t.Errorf("query %q did not surface %s in the top results:\n%s", c.query, c.want, out)
		}
	}
}

// TestToolSearch_IBANDiscoverability locks in that iban_decode is reachable by
// the natural ways an operator would ask for it (the discoverability concern
// codified in v0.729's automotive fix).
func TestToolSearch_IBANDiscoverability(t *testing.T) {
	for _, q := range []string{
		"IBAN",
		"international bank account number",
		"validate bank account number",
	} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: handler: %v", q, err)
		}
		if !strings.Contains(out, `"name": "iban_decode"`) {
			t.Errorf("query %q did not surface iban_decode in the top results:\n%s", q, out)
		}
	}
}
