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

// TestRolljamLabDemoRefusesWithoutConsent ensures the consent guard
// short-circuits before any capture runs.
func TestRolljamLabDemoRefusesWithoutConsent(t *testing.T) {
	f, _ := mockFlipper(t)
	out, err := workflows.RolljamLabDemo(context.Background(),
		workflows.Deps{Flipper: f}, map[string]interface{}{
			"frequency": 433_920_000,
		})
	if err != nil {
		t.Fatalf("RolljamLabDemo: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v", err)
	}
	summary, _ := got["summary"].(string)
	if !strings.Contains(summary, "lab_consent") {
		t.Errorf("expected consent-required refusal, got %q", summary)
	}
	phases, _ := got["phases"].([]interface{})
	if len(phases) != 0 {
		t.Errorf("expected zero phases on refusal, got %d", len(phases))
	}
}

// TestRolljamLabDemoHappyPath drives the two-capture happy path with
// lab_consent=true. Asserts both files are recorded + the JSON surfaces
// both paths.
func TestRolljamLabDemoHappyPath(t *testing.T) {
	f, _ := mockFlipper(t,
		mock.WithHandler("subghz", func(args []string) string {
			// Any rx_raw call succeeds with a short non-empty capture banner.
			return "Capture started\n128 bytes written\nCapture stopped"
		}),
	)

	params := map[string]interface{}{
		"frequency":         433_920_000,
		"lab_consent":       true,
		"per_press_seconds": 2,
	}
	out, err := workflows.RolljamLabDemo(context.Background(),
		workflows.Deps{Flipper: f}, params)
	if err != nil {
		t.Fatalf("RolljamLabDemo: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, out)
	}

	summary, _ := got["summary"].(string)
	if !strings.Contains(summary, "433920000") {
		t.Errorf("summary missing frequency: %q", summary)
	}

	p1, _ := got["press1_capture"].(string)
	p2, _ := got["press2_capture"].(string)
	if !strings.HasPrefix(p1, "/ext/subghz/rolljam_") || !strings.HasSuffix(p1, "_press1.sub") {
		t.Errorf("press1_capture malformed: %q", p1)
	}
	if !strings.HasPrefix(p2, "/ext/subghz/rolljam_") || !strings.HasSuffix(p2, "_press2.sub") {
		t.Errorf("press2_capture malformed: %q", p2)
	}

	phases, _ := got["phases"].([]interface{})
	// prompt1 + rx1 + prompt2 + rx2 = 4 phases
	if len(phases) != 4 {
		t.Errorf("expected 4 phases, got %d", len(phases))
	}
}
