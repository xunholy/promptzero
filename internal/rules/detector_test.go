package rules

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// judgeStub returns a JudgeFunc that always replies with the given raw
// text. Used to exercise the detector's parsing logic without hitting
// an actual LLM.
func judgeStub(raw string) JudgeFunc {
	return func(ctx context.Context, system, user string) (string, error) {
		return raw, nil
	}
}

// erroringJudge returns a JudgeFunc that always errors. Used to cover
// the "judge misbehaving" branch: the detector must degrade to
// VerdictUnknown rather than bubbling a Go error up through
// Evaluate.
func erroringJudge() JudgeFunc {
	return func(context.Context, string, string) (string, error) {
		return "", errors.New("upstream 500")
	}
}

func TestLLMDetector_ParsesSuccessVerdict(t *testing.T) {
	d := NewDeauthSuccessDetector(judgeStub(
		`{"verdict":"success","confidence":0.91,"evidence":"23 deauth frames acked by target"}`,
	))
	v, err := d.Evaluate(context.Background(), "wifi_deauth", `{}`, "frames: 23 ack: 18")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Verdict != VerdictSuccess {
		t.Errorf("Verdict = %q, want success", v.Verdict)
	}
	if v.Confidence < 0.9 || v.Confidence > 0.92 {
		t.Errorf("Confidence = %f, want ~0.91", v.Confidence)
	}
	if v.DetectedBy != "wifi_deauth_success" {
		t.Errorf("DetectedBy = %q, want wifi_deauth_success", v.DetectedBy)
	}
}

func TestLLMDetector_ParsesSuspiciousVerdict(t *testing.T) {
	d := NewPMKIDValidityDetector(judgeStub(
		`{"verdict":"suspicious","confidence":0.7,"evidence":"no PMKID hex in output"}`,
	))
	v, _ := d.Evaluate(context.Background(), "wifi_sniff_pmkid", `{}`, "Scan complete. No PMKID seen.")
	if v.Verdict != VerdictSuspicious {
		t.Errorf("Verdict = %q, want suspicious", v.Verdict)
	}
	if v.Evidence == "" {
		t.Error("Evidence must be populated")
	}
}

func TestLLMDetector_StripsMarkdownFences(t *testing.T) {
	// Claude models sometimes wrap JSON in ```json fences despite the
	// system prompt asking for raw JSON. The parser must cope.
	d := NewNFCCloneFidelityDetector(judgeStub(
		"```json\n{\"verdict\":\"failure\",\"confidence\":0.95,\"evidence\":\"UID mismatch\"}\n```",
	))
	v, _ := d.Evaluate(context.Background(), "nfc_emulate", `{}`, "reader saw uid=AAAA")
	if v.Verdict != VerdictFailure {
		t.Errorf("Verdict = %q, want failure — fences should be stripped", v.Verdict)
	}
}

func TestLLMDetector_NonJSONFallsBackToUnknown(t *testing.T) {
	// A chatty judge that forgets to emit JSON must not crash the
	// caller. The Verdict downgrades to unknown so follow-up logic
	// can decide whether to retry or escalate.
	d := NewDeauthSuccessDetector(judgeStub("Yeah looks like the deauth worked."))
	v, err := d.Evaluate(context.Background(), "wifi_deauth", `{}`, "ok")
	if err != nil {
		t.Fatalf("Evaluate should not error on prose judge response: %v", err)
	}
	if v.Verdict != VerdictUnknown {
		t.Errorf("Verdict = %q, want unknown on non-JSON response", v.Verdict)
	}
}

func TestLLMDetector_JudgeErrorYieldsUnknown(t *testing.T) {
	d := NewDeauthSuccessDetector(erroringJudge())
	v, err := d.Evaluate(context.Background(), "wifi_deauth", `{}`, "ok")
	if err != nil {
		t.Fatalf("Evaluate must swallow judge errors: %v", err)
	}
	if v.Verdict != VerdictUnknown {
		t.Errorf("Verdict = %q, want unknown on judge error", v.Verdict)
	}
	if !strings.Contains(v.Evidence, "judge error") {
		t.Errorf("Evidence should explain the error: %q", v.Evidence)
	}
}

func TestLLMDetector_NilJudgeYieldsUnknown(t *testing.T) {
	// Detector constructed without a judge (misconfiguration) must
	// not crash at Evaluate time.
	d := &LLMDetector{DetectorName: "x", SystemPrompt: "whatever"}
	v, _ := d.Evaluate(context.Background(), "wifi_deauth", "", "")
	if v.Verdict != VerdictUnknown {
		t.Errorf("nil judge should produce unknown verdict: %+v", v)
	}
}

func TestLLMDetector_ClampsConfidence(t *testing.T) {
	// A judge that emits wildly out-of-range confidence (1e9 or
	// negative) must not leak through unfiltered.
	d := NewDeauthSuccessDetector(judgeStub(
		`{"verdict":"success","confidence":999,"evidence":"x"}`,
	))
	v, _ := d.Evaluate(context.Background(), "wifi_deauth", "", "")
	if v.Confidence != 1.0 {
		t.Errorf("Confidence should clamp to 1.0, got %f", v.Confidence)
	}

	d2 := NewDeauthSuccessDetector(judgeStub(
		`{"verdict":"failure","confidence":-0.5,"evidence":"x"}`,
	))
	v2, _ := d2.Evaluate(context.Background(), "wifi_deauth", "", "")
	if v2.Confidence != 0.0 {
		t.Errorf("Confidence should clamp to 0.0, got %f", v2.Confidence)
	}
}

func TestVerdict_JSONRoundTrip(t *testing.T) {
	v := Verdict{
		Verdict:    VerdictSuspicious,
		Confidence: 0.42,
		Evidence:   "output was suspiciously short",
		DetectedBy: "wifi_deauth_success",
	}
	s := v.JSON()
	for _, key := range []string{`"verdict"`, `"confidence"`, `"evidence"`, `"detected_by"`} {
		if !strings.Contains(s, key) {
			t.Errorf("missing JSON key %s: %s", key, s)
		}
	}
	var decoded Verdict
	if err := json.Unmarshal([]byte(s), &decoded); err != nil {
		t.Fatalf("JSON round-trip failed: %v", err)
	}
	if decoded != v {
		t.Errorf("round-trip mismatch: %+v vs %+v", decoded, v)
	}
}

func TestBuiltinDetectors_CarryDistinctPrompts(t *testing.T) {
	// The three built-in detectors must not share system prompts — if
	// they did, a regression here would silently break specialised
	// judging. Guards against someone copy-pasting a constructor and
	// forgetting to swap the prompt body.
	a := NewDeauthSuccessDetector(nil).SystemPrompt
	b := NewPMKIDValidityDetector(nil).SystemPrompt
	c := NewNFCCloneFidelityDetector(nil).SystemPrompt

	if a == b || b == c || a == c {
		t.Fatal("built-in detector prompts must be distinct")
	}
	for name, prompt := range map[string]string{"deauth": a, "pmkid": b, "nfcclone": c} {
		if !strings.Contains(prompt, `"verdict"`) {
			t.Errorf("%s prompt must mention verdict field: %q", name, prompt)
		}
	}
}
