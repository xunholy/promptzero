package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/targetmem"
	"github.com/xunholy/promptzero/internal/toolctx"
)

// toolctxHas is a local helper so the wiring test doesn't reach into
// unexported state — it defers to the package's own presence check.
func toolctxHas(name string) bool { return toolctx.Has(name) }

// wiring_test covers the post-review fixes that plug Batch B (target
// memory) and Batch E (confidence) into the live dispatch path. The
// review flagged both as orphan code; these tests lock that the live
// executeTool / dispatch route actually consumes them.

func TestDispatch_ConfidenceAbstainsOnMissingRequiredKey(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)

	// docs_search requires the "query" key. Calling it with an empty
	// params map must abstain via the confidence layer BEFORE dispatch
	// ever reaches docsSearch — proving the check is wired.
	out, isErr := a.executeTool(context.Background(), "docs_search", json.RawMessage(`{}`))
	if !isErr {
		t.Fatalf("expected abstain to surface as tool error; got success: %q", out)
	}
	if !strings.Contains(out, "low-confidence") {
		t.Errorf("tool error missing abstention marker: %q", out)
	}
	if !strings.Contains(out, "query") {
		t.Errorf("tool error should name the missing key: %q", out)
	}
}

func TestDispatch_ConfidenceAbstainsOnPlaceholderValue(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	out, isErr := a.executeTool(context.Background(), "docs_search",
		json.RawMessage(`{"query":"TODO: pick a search term"}`))
	if !isErr {
		t.Fatalf("placeholder input must abstain: %q", out)
	}
	if !strings.Contains(out, "low-confidence") {
		t.Errorf("abstain marker missing: %q", out)
	}
}

func TestDispatch_TargetRememberReachableThroughLivePath(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)

	store, err := targetmem.Open(t.TempDir() + "/tm.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	a.SetTargetMemory(store)

	// Remember a BSSID via the dispatch path — proves the case label
	// in agent.dispatch actually routes to targetRemember.
	out, isErr := a.executeTool(context.Background(), "target_remember",
		json.RawMessage(`{"identifier":"aa:bb:cc:dd:ee:ff","kind":"bssid","facts":{"ssid":"home"}}`))
	if isErr {
		t.Fatalf("target_remember returned error: %q", out)
	}
	if !strings.Contains(out, "remembered") {
		t.Errorf("unexpected success message: %q", out)
	}

	// Recall the same BSSID — proves the store is actually persisting
	// through the dispatch path, not just the unit test.
	out, isErr = a.executeTool(context.Background(), "target_recall",
		json.RawMessage(`{"identifier":"aa:bb:cc:dd:ee:ff","kind":"bssid"}`))
	if isErr {
		t.Fatalf("target_recall returned error: %q", out)
	}
	if !strings.Contains(out, "home") {
		t.Errorf("recall missing facts: %q", out)
	}
}

func TestDispatch_TargetMemoryInertWithoutStore(t *testing.T) {
	// When SetTargetMemory was never called, the target_* tools must
	// fail loudly rather than panic or silently no-op.
	a := agentForModelTest("claude-sonnet-4-6", nil)
	out, isErr := a.executeTool(context.Background(), "target_remember",
		json.RawMessage(`{"identifier":"x"}`))
	if !isErr {
		t.Fatalf("no-store state should error, got: %q", out)
	}
	if !strings.Contains(out, "target memory not initialised") {
		t.Errorf("error should explain why: %q", out)
	}
}

// NRF24 payload builder wiring: confidence gate must treat name+script
// as required. An empty params map must abstain through executeTool
// rather than panic or silently succeed.
func TestDispatch_NRF24PayloadBuildAbstainsOnEmptyParams(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	out, isErr := a.executeTool(context.Background(), "nrf24_payload_build", json.RawMessage(`{}`))
	if !isErr {
		t.Fatalf("empty params must abstain: %q", out)
	}
	if !strings.Contains(out, "low-confidence") {
		t.Errorf("abstention marker missing: %q", out)
	}
}

// Lock the surface area: every new NRF24 tool carries a toolctx sheet
// so the model sees guidance at registration time. A future refactor
// that drops a sheet should fail this test with a specific name.
func TestNRF24_ToolctxCoverage(t *testing.T) {
	required := []string{
		"nrf24_sniff_start",
		"nrf24_list_targets",
		"nrf24_payload_build",
		"nrf24_mousejack_start",
	}
	for _, name := range required {
		if !toolctxHas(name) {
			t.Errorf("tool %q missing cheat sheet", name)
		}
	}
}

// A build-verification call site regression check: Batch C's review
// flagged that block→skip-write ordering in subghzBuild/rfidBuild/
// irBuild/nfcBuild is only proved indirectly. This test installs a
// blocking verifier and invokes subghzBuild with a no-op flipper to
// confirm the write is SKIPPED — if a future refactor reorders the
// branches, the stub flipper's WriteFileCtx would be invoked and
// panic on nil, which this test catches as the expected failure.
func TestSubghzBuild_BlocksWriteOnHighSeverity(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.verifierFn = func(context.Context, string, string) (VerificationVerdict, error) {
		return VerificationVerdict{Severity: VerifySeverityHigh, Verified: true}, nil
	}
	// a.flipper is nil — if the code under test tries to write, it will
	// panic. The confidence abstention check requires "path" and
	// "frequency" for subghz_build, so pass both and a plausible body.
	// intOr expects JSON-shaped values (float64), mirroring what
	// Unmarshal would produce when the real dispatch path reaches here.
	out, err := a.subghzBuild(context.Background(), map[string]interface{}{
		"path":      "/ext/subghz/x.sub",
		"frequency": float64(433920000),
	})
	if err != nil {
		t.Fatalf("subghzBuild errored instead of blocking: %v", err)
	}
	if !strings.Contains(out, "blocked by verifier") {
		t.Errorf("expected block message, got: %q", out)
	}
}
