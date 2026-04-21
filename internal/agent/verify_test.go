package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseVerificationVerdict_CleanJSON(t *testing.T) {
	raw := `{"severity":"high","failure_modes":["form action wrong","external CDN"],"recommendation":"fix the action path","verified":true}`
	v := parseVerificationVerdict(raw)
	if v.Severity != VerifySeverityHigh {
		t.Errorf("Severity = %q, want high", v.Severity)
	}
	if len(v.FailureModes) != 2 {
		t.Errorf("FailureModes len = %d, want 2", len(v.FailureModes))
	}
	if !v.Verified {
		t.Errorf("Verified = false, want true")
	}
}

func TestParseVerificationVerdict_StripsMarkdownFences(t *testing.T) {
	raw := "```json\n{\"severity\":\"low\",\"verified\":true}\n```"
	v := parseVerificationVerdict(raw)
	if v.Severity != VerifySeverityLow {
		t.Errorf("fences should be stripped; got severity %q", v.Severity)
	}
}

func TestParseVerificationVerdict_EmptyReturnsUncertified(t *testing.T) {
	v := parseVerificationVerdict("")
	if v.Severity != VerifySeverityNone {
		t.Errorf("empty input should default to severity none, got %q", v.Severity)
	}
	if v.Verified {
		t.Errorf("empty input should be Verified=false")
	}
}

func TestParseVerificationVerdict_ProseFallsBack(t *testing.T) {
	v := parseVerificationVerdict("Looks fine to me.")
	if v.Severity != VerifySeverityNone {
		t.Errorf("prose input should default to severity none, got %q", v.Severity)
	}
	if v.Verified {
		t.Errorf("prose input should be Verified=false")
	}
}

func TestParseVerificationVerdict_MissingSeverityDefaults(t *testing.T) {
	v := parseVerificationVerdict(`{"verified":true,"failure_modes":[]}`)
	if v.Severity != VerifySeverityNone {
		t.Errorf("missing severity should default to none, got %q", v.Severity)
	}
}

func TestParseVerificationVerdict_ProsePreambleStripped(t *testing.T) {
	// Haiku sometimes chats before the JSON. The brace-depth scanner
	// must pick out the object anyway.
	raw := "Sure — here's my verdict.\n{\"severity\":\"high\",\"verified\":true}\n\nLet me know if you need clarification."
	v := parseVerificationVerdict(raw)
	if v.Severity != VerifySeverityHigh {
		t.Errorf("prose preamble should be stripped; got %q", v.Severity)
	}
}

func TestParseVerificationVerdict_UppercaseJSONFence(t *testing.T) {
	// Earlier strip was case-sensitive — verify the extractor copes.
	raw := "```JSON\n{\"severity\":\"medium\",\"verified\":true}\n```"
	v := parseVerificationVerdict(raw)
	if v.Severity != VerifySeverityMedium {
		t.Errorf("uppercase fence should still parse; got %q", v.Severity)
	}
}

func TestParseVerificationVerdict_BraceInsideString(t *testing.T) {
	// The object contains a literal "{" character inside a string
	// value. The brace-depth scanner must honour string literals so
	// it doesn't bail out at the first inner '{'.
	raw := `{"severity":"low","recommendation":"output should not contain { or } stray","verified":true}`
	v := parseVerificationVerdict(raw)
	if v.Severity != VerifySeverityLow {
		t.Errorf("string-interior brace broke parsing; got %+v", v)
	}
	if !strings.Contains(v.Recommendation, "{") {
		t.Errorf("recommendation truncated: %q", v.Recommendation)
	}
}

func TestExtractJSONObject_NoBraces(t *testing.T) {
	if got := extractJSONObject("no json here"); got != "" {
		t.Errorf("expected empty on no-JSON input, got %q", got)
	}
}

func TestExtractJSONObject_UnbalancedBraces(t *testing.T) {
	// An unclosed object should return empty rather than the partial
	// tail — feeding an unbalanced string to json.Unmarshal would
	// error anyway, but extractJSONObject is defensive.
	if got := extractJSONObject("{\"severity\":\"high\""); got != "" {
		t.Errorf("expected empty on unbalanced input, got %q", got)
	}
}

func TestShouldBlockDeploy_BypassAlwaysFalse(t *testing.T) {
	for _, sev := range []string{VerifySeverityHigh, VerifySeverityCritical, VerifySeverityLow, ""} {
		if shouldBlockDeploy(VerificationVerdict{Severity: sev, Verified: true}, true) {
			t.Errorf("bypass=true should never block (severity=%q)", sev)
		}
	}
}

func TestShouldBlockDeploy_BlocksHighAndCritical(t *testing.T) {
	cases := map[string]bool{
		VerifySeverityNone:     false,
		VerifySeverityLow:      false,
		VerifySeverityMedium:   false,
		VerifySeverityHigh:     true,
		VerifySeverityCritical: true,
	}
	for sev, want := range cases {
		got := shouldBlockDeploy(VerificationVerdict{Severity: sev, Verified: true}, false)
		if got != want {
			t.Errorf("shouldBlockDeploy(sev=%q, bypass=false) = %v, want %v", sev, got, want)
		}
	}
}

func TestVerdictSummary_Certified(t *testing.T) {
	s := verdictSummary(VerificationVerdict{
		Severity:       VerifySeverityHigh,
		FailureModes:   []string{"wrong form action", "external CDN"},
		Recommendation: "set action to /get",
		Verified:       true,
	})
	for _, want := range []string{"verifier: high", "wrong form action", "external CDN", "set action to /get"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q: %s", want, s)
		}
	}
}

func TestVerdictSummary_Uncertified(t *testing.T) {
	s := verdictSummary(VerificationVerdict{Severity: VerifySeverityNone, Verified: false})
	if !strings.Contains(s, "uncertified") {
		t.Errorf("uncertified summary should say so: %s", s)
	}
}

// Ensure the verdict serialises back to JSON cleanly — consumers
// (detectors, reports, audit log) rely on the flat shape.
func TestVerificationVerdict_JSONRoundTrip(t *testing.T) {
	v := VerificationVerdict{
		Severity:       VerifySeverityMedium,
		FailureModes:   []string{"a", "b"},
		Recommendation: "r",
		Verified:       true,
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"severity":"medium"`, `"failure_modes"`, `"recommendation"`, `"verified":true`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("missing key %s in %s", key, b)
		}
	}
	var back VerificationVerdict
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Severity != v.Severity {
		t.Errorf("round-trip severity: %q vs %q", back.Severity, v.Severity)
	}
}

// Spot-check that each built-in system prompt mentions JSON output
// so the verifier stays parseable. Protects against a well-meaning
// prompt edit accidentally dropping the "Output ONLY ..." instruction.
func TestVerifyPayloadSystemPrompts_DemandJSONOutput(t *testing.T) {
	for typ, prompt := range verifyPayloadSystemPrompts {
		if !strings.Contains(prompt, "JSON") {
			t.Errorf("verifier prompt for %q doesn't demand JSON: %s", typ, prompt)
		}
		if !strings.Contains(prompt, "severity") {
			t.Errorf("verifier prompt for %q doesn't reference severity: %s", typ, prompt)
		}
	}
}
