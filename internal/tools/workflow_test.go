package tools

import (
	"context"
	"testing"
)

// workflowSpecsCached holds workflow specs captured in init() — before any
// test function (including spec_test.go's resetForTest() calls) can clear the
// registry. Mirrors the pattern in wifi_marauder_test.go.
var (
	wfHWReconSpec    Spec
	wfGarageSpec     Spec
	wfBadgeWalkSpec  Spec
	wfNFCBadgeSpec   Spec
	wfWiFiHashSpec   Spec
	wfRolljamSpec    Spec
	wfBadUSBProfSpec Spec
	wfMousejackSpec  Spec
)

func init() {
	// init() runs after the package's own init() functions (which register
	// the specs) but before any test function.
	wfHWReconSpec, _ = Get("workflow_hw_recon_blackbox_device")
	wfGarageSpec, _ = Get("workflow_garage_door_triage")
	wfBadgeWalkSpec, _ = Get("workflow_phys_pentest_badge_walk")
	wfNFCBadgeSpec, _ = Get("workflow_nfc_badge_pipeline")
	wfWiFiHashSpec, _ = Get("workflow_wifi_target_to_hashcat")
	wfRolljamSpec, _ = Get("workflow_rolljam_lab_demo")
	wfBadUSBProfSpec, _ = Get("workflow_badusb_target_profile")
	wfMousejackSpec, _ = Get("workflow_mousejack")
}

// TestWorkflowMCPAccessible verifies that the three workflows that were
// previously in MCP's registerWorkflowTools() are now in the registry with
// AgentOnly:false so registerFromRegistry picks them up.
func TestWorkflowMCPAccessible(t *testing.T) {
	for _, spec := range []Spec{wfHWReconSpec, wfGarageSpec, wfBadgeWalkSpec} {
		if spec.Name == "" {
			t.Fatalf("workflow spec not captured at init time")
		}
		if spec.AgentOnly {
			t.Errorf("%s.AgentOnly = true, want false (should be MCP-accessible)", spec.Name)
		}
	}
}

// TestWorkflowAgentOnly verifies that the five agent-only workflows are
// properly excluded from MCP via AgentOnly:true.
func TestWorkflowAgentOnly(t *testing.T) {
	for _, spec := range []Spec{wfNFCBadgeSpec, wfWiFiHashSpec, wfRolljamSpec, wfBadUSBProfSpec, wfMousejackSpec} {
		if spec.Name == "" {
			t.Fatalf("workflow spec not captured at init time")
		}
		if !spec.AgentOnly {
			t.Errorf("%s.AgentOnly = false, want true", spec.Name)
		}
	}
}

// TestWorkflowDepsWiresConfirmSubtool verifies that buildWorkflowDeps
// correctly passes d.WorkflowConfirm into workflows.Deps.ConfirmSubtool.
func TestWorkflowDepsWiresConfirmSubtool(t *testing.T) {
	called := false
	d := &Deps{
		WorkflowConfirm: func(_ context.Context, _ string, _ any, _ string) bool {
			called = true
			return false
		},
	}

	wDeps := buildWorkflowDeps(d)
	if wDeps.ConfirmSubtool == nil {
		t.Error("buildWorkflowDeps: ConfirmSubtool is nil, want non-nil when WorkflowConfirm is set")
	}

	// Invoke the hook to verify it delegates correctly.
	wDeps.ConfirmSubtool(context.Background(), "test_tool", nil, "high")
	if !called {
		t.Error("buildWorkflowDeps: ConfirmSubtool did not call WorkflowConfirm")
	}
}
