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

// TestWorkflowMCPAccessible verifies the three device-only workflows carry no
// advisory flag (AgentOnly:false) — they need no LLM. Every workflow is exposed
// over MCP regardless of the flag; this pins which ones are flagged as needing
// agent-mode setup.
func TestWorkflowMCPAccessible(t *testing.T) {
	for _, spec := range []Spec{wfHWReconSpec, wfGarageSpec, wfBadgeWalkSpec} {
		if spec.Name == "" {
			t.Fatalf("workflow spec not captured at init time")
		}
		if spec.AgentOnly {
			t.Errorf("%s.AgentOnly = true, want false (these workflows need no LLM, should not carry the advisory flag)", spec.Name)
		}
	}
}

// TestWorkflowAgentOnly verifies the five LLM/multi-step workflows carry the
// advisory AgentOnly flag (they need agent-mode deps to function fully). The
// flag no longer affects exposure — every workflow is reachable over MCP and
// consent-gated by risk; it only marks which ones need extra setup.
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
