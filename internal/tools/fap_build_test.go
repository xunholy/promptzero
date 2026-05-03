package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfirmFAPDeploy_AutoApproveWhenHookNil locks the workflows.gateSubtool
// fallback semantics: if no WorkflowConfirm hook is wired (MCP mode, off-session
// tests), confirmFAPDeploy must return true so the deploy step still runs.
func TestConfirmFAPDeploy_AutoApproveWhenHookNil(t *testing.T) {
	d := &Deps{} // no WorkflowConfirm
	if !confirmFAPDeploy(context.Background(), d, []string{"/tmp/foo.fap"}) {
		t.Fatal("nil hook must auto-approve to preserve gateSubtool semantics")
	}
}

// TestConfirmFAPDeploy_PassesHighRiskAndDestinations asserts the gate is
// invoked with riskLevel "high" (mirrors generate_deploy_run / wifi_sniff_pmkid
// precedent — Medium parent must not silently authorise a native-code write to
// /ext/apps) and that the operator sees the destination paths so they can
// scope-check before approving.
func TestConfirmFAPDeploy_PassesHighRiskAndDestinations(t *testing.T) {
	var (
		gotTool  string
		gotRisk  string
		gotDsts  []string
		gotSrcs  []string
		hookCall int
	)
	d := &Deps{
		WorkflowConfirm: func(_ context.Context, tool string, input any, riskLevel string) bool {
			hookCall++
			gotTool = tool
			gotRisk = riskLevel
			if m, ok := input.(map[string]any); ok {
				if dsts, ok := m["destinations"].([]string); ok {
					gotDsts = dsts
				}
				if srcs, ok := m["sources"].([]string); ok {
					gotSrcs = srcs
				}
			}
			return true
		},
	}

	srcs := []string{"/tmp/build/foo.fap", "/tmp/build/bar.fap"}
	ok := confirmFAPDeploy(context.Background(), d, srcs)

	if !ok {
		t.Fatal("hook returned true but confirm reported denial")
	}
	if hookCall != 1 {
		t.Fatalf("WorkflowConfirm called %d times, want 1", hookCall)
	}
	if gotTool != "fap_deploy_to_flipper" {
		t.Errorf("tool name = %q, want fap_deploy_to_flipper", gotTool)
	}
	if gotRisk != "high" {
		t.Errorf("risk level = %q, want high (Medium parent must not silently authorise native-code write)", gotRisk)
	}
	if len(gotDsts) != 2 {
		t.Errorf("destinations passed to hook = %d, want 2 (operator needs to see what is being written)", len(gotDsts))
	}
	for _, p := range gotDsts {
		if !strings.HasPrefix(p, "/ext/apps/") {
			t.Errorf("destination %q must be under /ext/apps/", p)
		}
	}
	if len(gotSrcs) != len(srcs) {
		t.Errorf("source paths passed to hook = %d, want %d (operator needs to verify build provenance)", len(gotSrcs), len(srcs))
	}
}

// TestConfirmFAPDeploy_OperatorDenialPropagates locks that a "no" from the
// operator turns into the boolean the caller uses to switch to the
// "deploy declined" branch — without this, Medium auto-confirm would still
// land the .fap.
func TestConfirmFAPDeploy_OperatorDenialPropagates(t *testing.T) {
	d := &Deps{
		WorkflowConfirm: func(context.Context, string, any, string) bool { return false },
	}
	if confirmFAPDeploy(context.Background(), d, []string{"/tmp/x.fap"}) {
		t.Fatal("hook returned false but confirm reported approval — denial path is broken")
	}
}

// TestFindFAP_OnlyScansSingleDir locks the path-confinement contract that
// closes the security bypass: findFAP must scan only the directories it is
// passed, and must not be invoked with a caller-supplied (LLM-controlled)
// output_dir. We construct a layout with .fap files in (a) the canonical
// dist dir and (b) an unrelated sibling dir, then assert that scanning only
// the dist dir finds the dist file and ignores the sibling.
func TestFindFAP_OnlyScansSingleDir(t *testing.T) {
	root := t.TempDir()
	dist := filepath.Join(root, "src", ".ufbt", "dist")
	sibling := filepath.Join(root, "elsewhere")
	for _, d := range []string{dist, sibling} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	distFAP := filepath.Join(dist, "legit.fap")
	siblingFAP := filepath.Join(sibling, "rogue.fap")
	for _, p := range []string{distFAP, siblingFAP} {
		if err := os.WriteFile(p, []byte{}, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got := findFAP(dist)

	if len(got) != 1 || got[0] != distFAP {
		t.Errorf("findFAP(dist) = %v, want [%s] only — sibling .fap must NOT be discovered", got, distFAP)
	}
}
