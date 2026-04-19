//go:build linux

package workflows_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper/mock"
	"github.com/xunholy/promptzero/internal/workflows"
)

// TestGarageDoorTriageHappyPath drives the full scan → decode → aggregate
// pipeline on a narrow 2-frequency override. One frequency returns a
// fixed-code Princeton key (replayable); the other returns nothing. We
// assert the workflow surfaces exactly one decoded signal with an
// "attack_path" that mentions subghz_transmit.
func TestGarageDoorTriageHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("slow; full composite workflow — rerun without -short")
	}
	// The mock uses Momentum firmware so SubGHzRxRaw streams to stdout
	// (no file-path arg). Command: `subghz rx_raw <freq> 0`
	// args dispatched: ["rx_raw", "<freq>", "0"]
	f, _ := mockFlipper(t,
		mock.WithHandler("device_info", func(_ []string) string { return mock.MomentumDeviceInfo }),
		mock.WithHandler("subghz", func(args []string) string {
			if len(args) == 0 {
				return ""
			}
			switch args[0] {
			case "rx_raw":
				// args[1]=freq, args[2]=device-index (Momentum SubGHzNeedsDev)
				if len(args) >= 2 && args[1] == "433920000" {
					return "Capture started at 433.92 MHz\nCapture stopped — 128 samples written"
				}
				return "Capture started\nNo signal captured"
			case "decode_raw":
				// Only the 433.92 capture was non-empty; assume the mock is
				// asked to decode that file. Return a fixed-code Princeton
				// response so the workflow marks it replayable.
				return "Protocol: Princeton\nKey: 00 AA BB CC\nTe: 400\nBit: 24"
			}
			return ""
		}),
	)

	params := map[string]interface{}{
		"frequencies":      []interface{}{433_920_000, 868_350_000},
		"per_freq_seconds": 2,
	}
	out, err := workflows.GarageDoorTriage(context.Background(), workflows.Deps{Flipper: f}, params)
	if err != nil {
		t.Fatalf("GarageDoorTriage: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, out)
	}

	summary, _ := got["summary"].(string)
	if !strings.Contains(summary, "scanned 2 frequencies") {
		t.Errorf("summary missing scanned count: %q", summary)
	}
	if !strings.Contains(summary, "1 decoded signal") {
		t.Errorf("summary missing decoded count: %q", summary)
	}

	signals, _ := got["signals_found"].([]interface{})
	if len(signals) != 1 {
		t.Fatalf("expected 1 decoded signal, got %d: %v", len(signals), signals)
	}
	sig := signals[0].(map[string]interface{})
	if proto, _ := sig["protocol"].(string); proto != "Princeton" {
		t.Errorf("expected Princeton protocol, got %q", proto)
	}
	if rolling, _ := sig["rolling"].(bool); rolling {
		t.Errorf("Princeton is fixed-code, should not be marked rolling")
	}
	if path, _ := sig["attack_path"].(string); !strings.Contains(path, "subghz_transmit") {
		t.Errorf("expected replay suggestion, got %q", path)
	}

	next, _ := got["next_steps"].([]interface{})
	if len(next) == 0 {
		t.Errorf("expected replay suggestion in next_steps")
	}
}

// TestGarageDoorTriageNoSignal verifies the empty-scan path: every freq
// returns nothing, so we get zero signals and a "press the remote" hint.
func TestGarageDoorTriageNoSignal(t *testing.T) {
	f, _ := mockFlipper(t,
		mock.WithHandler("subghz", func(args []string) string {
			return "No signal"
		}),
	)

	params := map[string]interface{}{
		"frequencies":      []interface{}{433_920_000},
		"per_freq_seconds": 2,
	}
	out, err := workflows.GarageDoorTriage(context.Background(), workflows.Deps{Flipper: f}, params)
	if err != nil {
		t.Fatalf("GarageDoorTriage: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v", err)
	}
	signals, _ := got["signals_found"].([]interface{})
	if len(signals) != 0 {
		t.Errorf("expected 0 signals, got %v", signals)
	}
	next, _ := got["next_steps"].([]interface{})
	joined := ""
	for _, s := range next {
		if str, ok := s.(string); ok {
			joined += str + " "
		}
	}
	if !strings.Contains(joined, "press the remote") {
		t.Errorf("expected 'press the remote' hint in next_steps: %v", next)
	}
}
