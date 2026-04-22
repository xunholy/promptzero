package agent

import (
	"context"
	"strings"
	"testing"
)

// Batch C — locks the verify-everywhere helper used by the parametric
// file builders. These tests install a deterministic verifier stub so
// the decision table is exercised without a live Anthropic client.

func TestRunBuildVerification_NoneSeverityProducesSummaryOnly(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.verifierFn = func(context.Context, string, string) (VerificationVerdict, error) {
		return VerificationVerdict{Severity: VerifySeverityNone, Verified: true}, nil
	}
	summary, blockMsg := a.runBuildVerification(context.Background(), "subghz", []byte("stub"), false)
	if blockMsg != "" {
		t.Errorf("none severity should not block: %q", blockMsg)
	}
	if !strings.Contains(summary, VerifySeverityNone) {
		t.Errorf("summary missing severity: %q", summary)
	}
}

func TestRunBuildVerification_HighSeverityBlocks(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.verifierFn = func(context.Context, string, string) (VerificationVerdict, error) {
		return VerificationVerdict{Severity: VerifySeverityHigh, Verified: true, FailureModes: []string{"uid length mismatch"}}, nil
	}
	summary, blockMsg := a.runBuildVerification(context.Background(), "nfc", []byte("stub"), false)
	if blockMsg == "" {
		t.Fatalf("high severity must block, got empty blockMsg (summary=%q)", summary)
	}
	if !strings.Contains(blockMsg, "verify_bypass=true") {
		t.Errorf("block message missing bypass hint: %q", blockMsg)
	}
	if !strings.Contains(blockMsg, "uid length mismatch") {
		t.Errorf("block message missing failure mode: %q", blockMsg)
	}
}

func TestRunBuildVerification_BypassOverridesBlock(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.verifierFn = func(context.Context, string, string) (VerificationVerdict, error) {
		return VerificationVerdict{Severity: VerifySeverityCritical, Verified: true}, nil
	}
	summary, blockMsg := a.runBuildVerification(context.Background(), "subghz", []byte("stub"), true)
	if blockMsg != "" {
		t.Errorf("bypass=true must suppress block: %q", blockMsg)
	}
	if !strings.Contains(summary, VerifySeverityCritical) {
		t.Errorf("summary must still surface severity on bypass: %q", summary)
	}
}

func TestRunBuildVerification_MediumSeverityNeverBlocks(t *testing.T) {
	// Medium is the mid-tier warning level — informative, not blocking.
	// Locking this separately from low/none so a future shouldBlockDeploy
	// refactor that accidentally escalates medium to high trips the test.
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.verifierFn = func(context.Context, string, string) (VerificationVerdict, error) {
		return VerificationVerdict{Severity: VerifySeverityMedium, Verified: true}, nil
	}
	_, blockMsg := a.runBuildVerification(context.Background(), "rfid", []byte("stub"), false)
	if blockMsg != "" {
		t.Errorf("medium severity must not block: %q", blockMsg)
	}
}

func TestRunBuildVerification_UnknownTypeSkipsVerification(t *testing.T) {
	// Unknown payloadType: verifyPayload returns uncertified/none, so
	// the helper should surface the "uncertified" summary and never
	// block. Production catches this case silently; tests lock that
	// an unknown type is a pass-through, not a crash.
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.verifierFn = func(context.Context, string, string) (VerificationVerdict, error) {
		return VerificationVerdict{Severity: VerifySeverityNone, Verified: false}, nil
	}
	summary, blockMsg := a.runBuildVerification(context.Background(), "totally_unknown", []byte("stub"), false)
	if blockMsg != "" {
		t.Errorf("unknown type should not block: %q", blockMsg)
	}
	if !strings.Contains(summary, "uncertified") {
		t.Errorf("unknown type summary should say uncertified: %q", summary)
	}
}

// The rfid prompt was added in Batch C — lock that the verifier map
// carries an entry for every parametric builder so a refactor that
// drops one trips this test.
func TestVerifyPayloadSystemPrompts_CoversParametricBuilders(t *testing.T) {
	required := []string{"subghz", "rfid", "ir", "nfc"}
	for _, k := range required {
		if _, ok := verifyPayloadSystemPrompts[k]; !ok {
			t.Errorf("verify prompt missing for parametric builder %q", k)
		}
	}
}
