package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/xunholy/promptzero/internal/obs"
)

// readLogFile reads back what obs.Default() wrote during a test.
// Mirrors the pattern in consensus_test.go's TestProspectiveWithModel_*.
func readLogFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	return string(b)
}

// stubAnthropicWithHTTPError returns a client pointed at an httptest
// server that responds 500 — used here as a quick stand-in for any
// error path (timeout, transient SDK failure). The SDK surfaces the
// 500 as a generic error which both error and timeout branches
// handle identically (return "" / nil) in prospective / reflect /
// routeGroups. The distinction is which warn log fires —
// pinned in the test by checking ctx.Err() classification.
func stubAnthropicWithHTTPError(t *testing.T) (*anthropic.Client, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"api_error","message":"upstream broke"}}`))
	}))
	c := anthropic.NewClient(option.WithAPIKey("test"), option.WithBaseURL(srv.URL))
	return &c, srv.Close
}

// stubAnthropicWithDelay returns a client pointed at an httptest
// server that sleeps for `delay` before responding. Combined with a
// short per-call timeout, this forces the SDK's request to fail with
// context.DeadlineExceeded, exercising the new "loud on timeout"
// warn-log path.
func stubAnthropicWithDelay(t *testing.T, delay time.Duration) (*anthropic.Client, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(delay):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"x","type":"message","role":"assistant","content":[],"usage":{"input_tokens":0,"output_tokens":0}}`))
		case <-r.Context().Done():
		}
	}))
	c := anthropic.NewClient(option.WithAPIKey("test"), option.WithBaseURL(srv.URL))
	return &c, srv.Close
}

// TestRouteGroups_TimeoutEmitsWarnLog pins the v0.200 observability
// contract: when the router's per-call deadline fires, a
// `router_timeout` warn record gets emitted so operators can see
// the gate is silently disabling. Other errors (5xx, transient) stay
// quiet to avoid noise on normal retries.
func TestRouteGroups_TimeoutEmitsWarnLog(t *testing.T) {
	// Server sleeps slightly longer than the router's 3 s budget so
	// the ctx fires first. Using 3.5 s keeps the test under 4 s wall
	// time; CI doesn't routinely tolerate fast clocks, so we err
	// generous.
	client, closeSrv := stubAnthropicWithDelay(t, routerTimeout+500*time.Millisecond)
	defer closeSrv()

	a := &Agent{client: client, model: "test-model"}
	logFile := t.TempDir() + "/test.log"
	obs.Setup(obs.LogConfig{Level: "warn", Format: "text", File: logFile})
	t.Cleanup(func() { obs.Setup(obs.LogConfig{Level: "info", Format: "text"}) })

	// routeGroups requires a.mu held by contract — we hold it here
	// since this isn't running inside Run().
	a.mu.Lock()
	_, err := a.routeGroups(context.Background(), "scan wifi", map[string]bool{"wifi": true})
	a.mu.Unlock()

	if err == nil {
		t.Fatal("expected routeGroups to return an error on timeout; got nil")
	}
	log := readLogFile(t, logFile)
	if !strings.Contains(log, "router_timeout") {
		t.Errorf("expected router_timeout warn log; got: %q", log)
	}
}

// TestVerifyPayload_TimeoutEmitsWarnLog pins the same loud-on-
// timeout contract for verify. A stalled verifier silently returns
// "uncertified" on every generate_* call — operators should see it.
func TestVerifyPayload_TimeoutEmitsWarnLog(t *testing.T) {
	client, closeSrv := stubAnthropicWithDelay(t, verifyTimeout+500*time.Millisecond)
	defer closeSrv()

	a := &Agent{client: client, model: "test-model"}
	logFile := t.TempDir() + "/test.log"
	obs.Setup(obs.LogConfig{Level: "warn", Format: "text", File: logFile})
	t.Cleanup(func() { obs.Setup(obs.LogConfig{Level: "info", Format: "text"}) })

	a.mu.Lock()
	verdict, err := a.verifyPayload(context.Background(), "badusb", "STRING hello\nENTER\n")
	a.mu.Unlock()

	// On timeout, verify returns benign verdict + nil error (fail-open).
	if err != nil {
		t.Fatalf("verifyPayload on timeout should not error; got %v", err)
	}
	if verdict.Verified {
		t.Error("verdict.Verified must be false on timeout (fail-open)")
	}
	log := readLogFile(t, logFile)
	if !strings.Contains(log, "verify_timeout") {
		t.Errorf("expected verify_timeout warn log; got: %q", log)
	}
	if !strings.Contains(log, "badusb") {
		t.Errorf("warn should include payload_type=badusb; got: %q", log)
	}
}

// TestVerifyPayload_NonTimeoutErrorStaysQuiet — same posture as the
// router non-timeout test: a 5xx response should NOT fire verify_timeout.
func TestVerifyPayload_NonTimeoutErrorStaysQuiet(t *testing.T) {
	client, closeSrv := stubAnthropicWithHTTPError(t)
	defer closeSrv()

	a := &Agent{client: client, model: "test-model"}
	logFile := t.TempDir() + "/test.log"
	obs.Setup(obs.LogConfig{Level: "warn", Format: "text", File: logFile})
	t.Cleanup(func() { obs.Setup(obs.LogConfig{Level: "info", Format: "text"}) })

	a.mu.Lock()
	_, _ = a.verifyPayload(context.Background(), "badusb", "STRING test\n")
	a.mu.Unlock()

	log := readLogFile(t, logFile)
	if strings.Contains(log, "verify_timeout") {
		t.Errorf("verify_timeout should NOT fire on non-timeout error; got: %q", log)
	}
}

// TestRouteGroups_NonTimeoutErrorStaysQuiet pins the other half of
// the contract: a 5xx from the SDK does NOT fire router_timeout. The
// distinction is meaningful because timeouts indicate a stalled gate
// (deserves operator attention) while transient 5xx errors recover.
func TestRouteGroups_NonTimeoutErrorStaysQuiet(t *testing.T) {
	client, closeSrv := stubAnthropicWithHTTPError(t)
	defer closeSrv()

	a := &Agent{client: client, model: "test-model"}
	logFile := t.TempDir() + "/test.log"
	obs.Setup(obs.LogConfig{Level: "warn", Format: "text", File: logFile})
	t.Cleanup(func() { obs.Setup(obs.LogConfig{Level: "info", Format: "text"}) })

	a.mu.Lock()
	_, err := a.routeGroups(context.Background(), "scan wifi", map[string]bool{"wifi": true})
	a.mu.Unlock()

	if err == nil {
		t.Fatal("expected error on 5xx; got nil")
	}
	log := readLogFile(t, logFile)
	if strings.Contains(log, "router_timeout") {
		t.Errorf("router_timeout should NOT fire on non-timeout error; got: %q", log)
	}
}
