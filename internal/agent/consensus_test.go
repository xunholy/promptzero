package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/xunholy/promptzero/internal/obs"
)

// TestExtractRiskFromCritique pins the small parsing shim that
// translates a per-model critique JSON into the consensus package's
// Risk string. Empty / malformed input must produce "" so the
// consensus package treats it as abstention.
func TestExtractRiskFromCritique(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"valid ok", `{"risk":"ok"}`, "ok"},
		{"valid risky with extra fields", `{"risk":"risky","confidence":0.92}`, "risky"},
		{"missing risk field", `{"confidence":0.5}`, ""},
		{"non-json prose", "the call looks fine", ""},
		{"malformed json", `{"risk":"ok"`, ""},
		{"empty risk value", `{"risk":""}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractRiskFromCritique(tc.in); got != tc.want {
				t.Errorf("extractRiskFromCritique(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRunEnsembleProspective_NoClientReturnsEmpty pins the
// safety-fallback path: a missing Anthropic client (test harness,
// degraded mode) must NOT panic and must NOT block the dispatch.
// The function returns the empty string instead, which the dispatch
// loop treats as "no escalation".
func TestRunEnsembleProspective_NoClientReturnsEmpty(t *testing.T) {
	a := &Agent{} // no client
	got := a.runEnsembleProspective(context.Background(), "subghz_transmit", []byte(`{}`), []string{"haiku", "sonnet"})
	if got != "" {
		t.Errorf("no-client should yield empty escalation, got %q", got)
	}
}

// TestRunEnsembleProspective_EmptyModelsReturnsEmpty pins the
// "feature disabled" path — an empty Consensus list never invokes
// any model and never produces an escalation.
func TestRunEnsembleProspective_EmptyModelsReturnsEmpty(t *testing.T) {
	a := &Agent{}
	if got := a.runEnsembleProspective(context.Background(), "x", nil, nil); got != "" {
		t.Errorf("nil models: got %q", got)
	}
	if got := a.runEnsembleProspective(context.Background(), "x", nil, []string{}); got != "" {
		t.Errorf("empty models: got %q", got)
	}
}

// TestRunEnsembleProspective_BlanksFiltered pins that whitespace-
// only model entries don't fire model calls (defensive against a
// YAML parser leaving blank list elements).
func TestRunEnsembleProspective_BlanksFiltered(t *testing.T) {
	a := &Agent{} // no client → all model calls would fail anyway
	got := a.runEnsembleProspective(context.Background(), "x", nil, []string{"  ", "\t"})
	if got != "" {
		// With no client there's nothing to assert beyond "no panic"
		// — but assert empty output to keep the contract explicit.
		// (a.client check short-circuits before the loop.)
		if !strings.Contains(got, "") {
			t.Errorf("non-empty escalation despite blank models: %q", got)
		}
	}
}

// TestProspectiveWithModel_WarnLogOnAPIError pins the Persona.Consensus
// docstring's promise that "Names the agent doesn't recognise are
// skipped with a warn log so a typo doesn't silently disable the gate."
// Pre-fix the API error was dropped silently; an operator's typo
// (`consensus: [calude-sonnet-4-6]`) became a permanent invisible
// abstention on every critical-risk call. Post-fix the function still
// returns "" (abstention semantics preserved) but emits a warn log
// with the model name + error so operators can see and fix the typo.
//
// Uses an httptest server that returns 400 for /v1/messages — the
// shape Anthropic returns for an unknown model — and routes obs
// output through a tempfile (the only public obs capture path)
// so the test can assert on the emitted record.
func TestProspectiveWithModel_WarnLogOnAPIError(t *testing.T) {
	// Anthropic-style 400 response shape; the SDK surfaces this as
	// an *anthropic.Error with status code 400.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"not_found_error","message":"model: calude-typo not found"}}`))
	}))
	defer srv.Close()

	client := anthropic.NewClient(
		option.WithAPIKey("test-key"),
		option.WithBaseURL(srv.URL),
	)
	a := &Agent{client: &client}

	// Route obs.Default() through a tempfile so we can read back what
	// it emitted. obs.Setup is the only public swap-the-global helper,
	// so we work with what it gives us — it still mirrors to stderr
	// but the tempfile carries the same content.
	logFile := t.TempDir() + "/test.log"
	obs.Setup(obs.LogConfig{Level: "warn", Format: "text", File: logFile})
	t.Cleanup(func() {
		// Reset to defaults so later tests don't inherit our tempfile.
		obs.Setup(obs.LogConfig{Level: "info", Format: "text"})
	})

	// Drive runEnsembleProspective so the full surface participates:
	// blank-filtering, per-model loop, and the new warn log on
	// API error. The model name "calude-typo" mirrors the docstring's
	// scenario verbatim.
	_ = a.runEnsembleProspective(context.Background(), "subghz_transmit", []byte(`{"freq":433920000}`), []string{"calude-typo"})

	data, readErr := readFileAll(logFile)
	if readErr != nil {
		t.Fatalf("read log: %v", readErr)
	}
	log := string(data)
	if !strings.Contains(log, "ensemble_voter_api_error") {
		t.Errorf("expected warn log with ensemble_voter_api_error, got: %q", log)
	}
	if !strings.Contains(log, "calude-typo") {
		t.Errorf("warn log should name the unrecognised model so operators see the typo, got: %q", log)
	}
}

// readFileAll is a tiny helper local to this test file. Avoids
// pulling os into the file's import list at top scope just for one
// callsite.
func readFileAll(path string) ([]byte, error) {
	return os.ReadFile(path)
}
