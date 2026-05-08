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

// TestMousejackRefusesWithoutFlipper verifies the up-front nil-Flipper
// guard short-circuits cleanly with no phases recorded.
func TestMousejackRefusesWithoutFlipper(t *testing.T) {
	out, err := workflows.Mousejack(context.Background(),
		workflows.Deps{Flipper: nil},
		map[string]interface{}{"name": "x", "script": "STRING hi"})
	if err != nil {
		t.Fatalf("Mousejack: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, out)
	}
	summary, _ := got["summary"].(string)
	if !strings.Contains(strings.ToLower(summary), "flipper") {
		t.Errorf("expected Flipper-required refusal, got %q", summary)
	}
	phases, _ := got["phases"].([]interface{})
	if len(phases) != 0 {
		t.Errorf("expected zero phases on refusal, got %d", len(phases))
	}
}

// TestMousejackRequiresName guards the param-validation path: missing
// `name` yields a friendly summary and no phases (no IO performed).
func TestMousejackRequiresName(t *testing.T) {
	f, _ := mockFlipper(t)
	out, err := workflows.Mousejack(context.Background(),
		workflows.Deps{Flipper: f},
		map[string]interface{}{"script": "STRING hi"})
	if err != nil {
		t.Fatalf("Mousejack: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v", err)
	}
	summary, _ := got["summary"].(string)
	if !strings.Contains(summary, "name required") {
		t.Errorf("expected name-required summary, got %q", summary)
	}
	if phases, _ := got["phases"].([]interface{}); len(phases) != 0 {
		t.Errorf("expected zero phases, got %d", len(phases))
	}
}

// TestMousejackRequiresScript guards the second param-validation rung.
// `name` is set but `script` is empty — must short-circuit with no IO.
func TestMousejackRequiresScript(t *testing.T) {
	f, _ := mockFlipper(t)
	out, err := workflows.Mousejack(context.Background(),
		workflows.Deps{Flipper: f},
		map[string]interface{}{"name": "demo"})
	if err != nil {
		t.Fatalf("Mousejack: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v", err)
	}
	summary, _ := got["summary"].(string)
	if !strings.Contains(summary, "script required") {
		t.Errorf("expected script-required summary, got %q", summary)
	}
}

// TestMousejackLaunchFalseHappyPath drives the build-and-deploy path
// without launching the FAP. Asserts the payload is written to the
// /ext/mousejacker path and the launch phase is absent.
func TestMousejackLaunchFalseHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("slow; full composite workflow — rerun without -short")
	}
	f, _ := mockFlipper(t,
		mock.WithHandler("storage", func(args []string) string { return "" }),
	)

	params := map[string]interface{}{
		"name":      "demo",
		"script":    "STRING calc",
		"target_os": "windows",
		"launch":    false,
	}
	out, err := workflows.Mousejack(context.Background(),
		workflows.Deps{Flipper: f}, params)
	if err != nil {
		t.Fatalf("Mousejack: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, out)
	}

	summary, _ := got["summary"].(string)
	if !strings.Contains(summary, "launch skipped") {
		t.Errorf("summary should note launch was skipped: %q", summary)
	}

	// Extra fields are flattened to the top level by Result.MarshalJSON.
	if path, _ := got["payload_path"].(string); path != "/ext/mousejacker/demo.txt" {
		t.Errorf("payload_path = %q, want /ext/mousejacker/demo.txt", path)
	}
	if addr, _ := got["addresses_path"].(string); addr == "" {
		t.Errorf("addresses_path should be surfaced, got empty")
	}

	phases, _ := got["phases"].([]interface{})
	// list_targets + build_payload = 2 phases; no launch since launch=false.
	if len(phases) != 2 {
		t.Errorf("expected 2 phases (list_targets + build_payload), got %d", len(phases))
	}
	for _, p := range phases {
		pm, _ := p.(map[string]interface{})
		if name, _ := pm["phase"].(string); name == "launch" {
			t.Errorf("launch phase must not appear when launch=false")
		}
	}
}
