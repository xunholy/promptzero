package tools

import (
	"strings"
	"testing"
)

// TestBruceHandlers_ValidateBeforeTransport pins the v0.177 contract.
// Six Bruce handlers (wifi_deauth, evil_twin, lora_scan, ir_send,
// badusb_run, raw_cli) previously checked RequireBruce before validating
// their args. A missing/invalid argument masqueraded as "bruce devboard
// not connected", sending the LLM to chase a wiring fix it can't perform.
//
// Same defect class as canbus v0.174/v0.175 and buspirate v0.176.
func TestBruceHandlers_ValidateBeforeTransport(t *testing.T) {
	cases := []struct {
		spec   string
		args   map[string]any
		expect string
	}{
		{
			spec:   "bruce_wifi_deauth",
			args:   map[string]any{"channel": float64(6)}, // missing bssid
			expect: "bssid is required",
		},
		{
			spec:   "bruce_wifi_deauth",
			args:   map[string]any{"bssid": "aa:bb:cc:dd:ee:ff"}, // missing channel
			expect: "channel is required",
		},
		{
			spec:   "bruce_evil_twin",
			args:   map[string]any{"bssid": "aa:bb:cc:dd:ee:ff"}, // missing ssid
			expect: "ssid is required",
		},
		{
			spec:   "bruce_evil_twin",
			args:   map[string]any{"ssid": "TargetAP"}, // missing bssid
			expect: "bssid is required",
		},
		{
			spec:   "bruce_lora_scan",
			args:   map[string]any{}, // missing frequency_mhz
			expect: "frequency_mhz is required",
		},
		{
			spec:   "bruce_ir_send",
			args:   map[string]any{"code": "DEADBEEF"}, // missing protocol
			expect: "protocol is required",
		},
		{
			spec:   "bruce_ir_send",
			args:   map[string]any{"protocol": "NEC"}, // missing code
			expect: "code is required",
		},
		{
			spec:   "bruce_badusb_run",
			args:   map[string]any{}, // missing filename
			expect: "filename is required",
		},
		{
			spec:   "bruce_raw_cli",
			args:   map[string]any{}, // missing command
			expect: "command is required",
		},
	}
	for _, c := range cases {
		t.Run(c.spec+"_"+c.expect, func(t *testing.T) {
			spec, ok := Get(c.spec)
			if !ok {
				t.Fatalf("%s not registered", c.spec)
			}
			_, err := spec.Handler(t.Context(), &Deps{}, c.args)
			if err == nil {
				t.Fatalf("expected error; got nil")
			}
			if strings.Contains(err.Error(), "not connected") {
				t.Errorf("err = %v; want validation error before transport check", err)
			}
			if !strings.Contains(err.Error(), c.expect) {
				t.Errorf("err = %v; want substring %q", err, c.expect)
			}
		})
	}
}
