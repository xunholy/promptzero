package obs

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRecorder_NilSafe(t *testing.T) {
	var r *Recorder
	// Every method should be a nil-safe no-op.
	r.RecordToolCall("x", "low", "ok", time.Second)
	r.RecordWorkflowRun("w", "ok", time.Second)
	r.RecordAudit("low", "info")
	r.RecordRiskPrompt("x", "approve")
	r.RecordMessage("user")
	r.RecordTokens("input", 5)
	r.SetFlipperConnected(true)
	r.SetMarauderConnected(true)
	r.RecordWebhookDelivery("x", "ok")
	r.SetAnthropicReachable(false)
	if got := r.LastTools(); got != nil {
		t.Fatalf("LastTools on nil Recorder: %v", got)
	}
	h := r.Handler()
	if h == nil {
		t.Fatal("nil Recorder.Handler returned nil")
	}
}

func TestRecorder_MetricsExport(t *testing.T) {
	r := NewRecorder()
	r.RecordToolCall("ir_transmit", "high", "ok", 250*time.Millisecond)
	r.RecordToolCall("ir_transmit", "high", "error", 100*time.Millisecond)
	r.RecordWorkflowRun("workflow_nfc_badge_pipeline", "ok", time.Second)
	r.RecordAudit("critical", "critical")
	r.RecordTokens("input", 1234)
	r.RecordTokens("output", 567)
	r.SetFlipperConnected(true)
	r.SetAnthropicReachable(true)

	srv := httptest.NewServer(r.Handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	text := string(body)

	wanted := []string{
		`promptzero_tool_calls_total{risk="high",status="ok",tool="ir_transmit"} 1`,
		`promptzero_tool_calls_total{risk="high",status="error",tool="ir_transmit"} 1`,
		`promptzero_workflow_runs_total{name="workflow_nfc_badge_pipeline",status="ok"} 1`,
		`promptzero_audit_entries_total{level="critical",risk="critical"} 1`,
		`promptzero_token_usage{kind="input"} 1234`,
		`promptzero_token_usage{kind="output"} 567`,
		`promptzero_flipper_connected 1`,
		`promptzero_anthropic_reachable 1`,
	}
	for _, want := range wanted {
		if !strings.Contains(text, want) {
			t.Errorf("metric surface missing %q", want)
		}
	}
}

func TestRecorder_LastToolsRing(t *testing.T) {
	r := NewRecorder()
	for i, tool := range []string{"a", "b", "c", "d", "e"} {
		r.RecordToolCall(tool, "low", "ok", time.Duration(i+1)*time.Millisecond)
	}
	got := r.LastTools()
	// Ring is size 3 → we should see the last three recordings, oldest first.
	if len(got) != 3 {
		t.Fatalf("LastTools len=%d want 3", len(got))
	}
	names := []string{got[0].Tool, got[1].Tool, got[2].Tool}
	want := []string{"c", "d", "e"}
	for i := range names {
		if names[i] != want[i] {
			t.Errorf("LastTools[%d]=%q want %q", i, names[i], want[i])
		}
	}
}
