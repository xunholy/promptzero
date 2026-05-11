// Tests for the REPL-parity HTTP endpoints. Each panel gets a focused
// test that exercises both the success and the not-configured paths so
// the frontend contract stays observable.

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/cost"
	"github.com/xunholy/promptzero/internal/persona"
	"github.com/xunholy/promptzero/internal/rules"
	"github.com/xunholy/promptzero/internal/watch"
)

// apiServer is startTestServer's equivalent for the HTTP JSON routes —
// skips the WebSocket dial and returns the raw httptest.Server so tests
// can GET/POST directly.
func apiServer(t *testing.T, fa *fakeAgent) (*Server, *httptest.Server) {
	t.Helper()
	s := &Server{
		agent:             fa,
		addr:              "127.0.0.1:0",
		conns:             make(map[*sessionConn]struct{}),
		confirms:          make(map[string]chan agent.ConfirmResponse),
		heartbeatInterval: 100 * time.Millisecond,
		heartbeatTimeout:  2 * time.Second,
		writeTimeout:      2 * time.Second,
		startedAt:         time.Now(),
	}
	s.attachAgentCallbacks()
	mux := http.NewServeMux()
	s.registerAPIRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return s, ts
}

func getJSON(t *testing.T, ts *httptest.Server, path string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+path, nil)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func postJSON(t *testing.T, ts *httptest.Server, path string, payload any) (int, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if payload != nil {
		_ = json.NewEncoder(&buf).Encode(payload)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	out := make([]byte, 0, 512)
	buf2 := make([]byte, 1024)
	for {
		n, rerr := resp.Body.Read(buf2)
		if n > 0 {
			out = append(out, buf2[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	return resp.StatusCode, out
}

// putJSON is the PUT analogue of postJSON. Used by the /api/budget
// PUT tests; the rest of the suite stayed on POST until v0.97
// introduced the first PUT endpoint.
func putJSON(t *testing.T, ts *httptest.Server, path string, payload any) (int, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if payload != nil {
		_ = json.NewEncoder(&buf).Encode(payload)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, ts.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", path, err)
	}
	defer resp.Body.Close()
	out := make([]byte, 0, 512)
	buf2 := make([]byte, 1024)
	for {
		n, rerr := resp.Body.Read(buf2)
		if n > 0 {
			out = append(out, buf2[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	return resp.StatusCode, out
}

// ---------------------------------------------------------------------------
// Personas
// ---------------------------------------------------------------------------

func TestPersonasListReturns503WithoutRegistry(t *testing.T) {
	_, ts := apiServer(t, &fakeAgent{})
	code, body := getJSON(t, ts, "/api/personas")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%v", code, body)
	}
	if body["error"] == "" {
		t.Errorf("expected error string, got %v", body)
	}
}

func TestPersonasListReturnsRegistry(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	reg := persona.NewRegistry()
	s.SetPersonaRegistry(reg)

	code, body := getJSON(t, ts, "/api/personas")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}
	avail, ok := body["available"].([]any)
	if !ok || len(avail) == 0 {
		t.Fatalf("expected non-empty available list, got %v", body["available"])
	}
	first, _ := avail[0].(map[string]any)
	if first["name"] == nil {
		t.Errorf("entry missing name: %v", first)
	}
	if _, ok := body["current"]; !ok {
		t.Errorf("expected 'current' key in response")
	}
	// Each entry must carry the unrestricted bool introduced in task #1.
	for _, entry := range avail {
		e, _ := entry.(map[string]any)
		if _, ok := e["unrestricted"].(bool); !ok {
			t.Errorf("entry %v missing unrestricted bool", e["name"])
		}
	}

	// Verify known contracts. v0.19.0+ all built-in personas are
	// unrestricted (the tool-allowlist job moved to --read-only as
	// the single safety rail). User personas loaded from
	// ~/.promptzero/personas/ may still set Tools for back-compat.
	byName := make(map[string]map[string]any, len(avail))
	for _, entry := range avail {
		e, _ := entry.(map[string]any)
		if n, ok := e["name"].(string); ok {
			byName[n] = e
		}
	}
	if def, ok := byName["default"]; ok {
		if def["unrestricted"] != true {
			t.Errorf("default persona unrestricted = %v, want true", def["unrestricted"])
		}
	} else {
		t.Errorf("'default' persona not found in available list")
	}
	if rf, ok := byName["rf-recon"]; ok {
		if rf["unrestricted"] != true {
			t.Errorf("rf-recon persona unrestricted = %v, want true (v0.19.0 dropped per-persona tool allowlists in favour of --read-only)", rf["unrestricted"])
		}
	} else {
		t.Errorf("'rf-recon' persona not found in available list")
	}
}

func TestPersonasSwitchApplies(t *testing.T) {
	fa := &fakeAgent{}
	s, ts := apiServer(t, fa)
	reg := persona.NewRegistry()
	s.SetPersonaRegistry(reg)

	names := reg.Names()
	if len(names) == 0 {
		t.Fatal("built-in registry empty; cannot test switch")
	}
	target := names[0]

	code, raw := postJSON(t, ts, "/api/personas/switch", map[string]string{"name": target})
	if code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", code, raw)
	}
	if fa.Persona() == nil || fa.Persona().Name != target {
		t.Errorf("agent persona = %v, want %s", fa.Persona(), target)
	}

	// Response must include switch_id (non-empty string) and unrestricted (bool).
	var respBody map[string]any
	if err := json.Unmarshal(raw, &respBody); err != nil {
		t.Fatalf("unmarshal switch response: %v", err)
	}
	switchID, ok := respBody["switch_id"].(string)
	if !ok || switchID == "" {
		t.Errorf("switch_id = %v, want non-empty string", respBody["switch_id"])
	}
	if _, ok := respBody["unrestricted"].(bool); !ok {
		t.Errorf("unrestricted = %v, want bool", respBody["unrestricted"])
	}
}

func TestPersonasSwitchUnknownReturns404(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	s.SetPersonaRegistry(persona.NewRegistry())

	code, _ := postJSON(t, ts, "/api/personas/switch", map[string]string{"name": "no-such-persona"})
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", code)
	}
}

// ---------------------------------------------------------------------------
// Device
// ---------------------------------------------------------------------------

func TestDeviceReturns503WithoutFlipper(t *testing.T) {
	_, ts := apiServer(t, &fakeAgent{})
	// No SetFlipper call — flipper is nil.
	code, body := getJSON(t, ts, "/api/device")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%v", code, body)
	}
	if body["error"] == "" {
		t.Errorf("expected error string in body, got %v", body)
	}
}

// ---------------------------------------------------------------------------
// Watch
// ---------------------------------------------------------------------------

func TestWatchReturnsState(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	tmp := t.TempDir()
	w := watch.New([]string{tmp}, []watch.Rule{
		{Pattern: "*.sub", Prompt: "decode {{path}}"},
	})
	s.SetWatcher(w)

	code, body := getJSON(t, ts, "/api/watch")
	if code != http.StatusOK {
		t.Fatalf("status = %d; body=%v", code, body)
	}
	rs, _ := body["rules"].([]any)
	if len(rs) != 1 {
		t.Errorf("rules = %v, want 1 entry", rs)
	}
	if body["paused"] != false {
		t.Errorf("paused = %v, want false", body["paused"])
	}
}

func TestWatchPauseResumeToggles(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	w := watch.New([]string{t.TempDir()}, nil)
	s.SetWatcher(w)

	code, _ := postJSON(t, ts, "/api/watch/pause", nil)
	if code != http.StatusOK || !w.Paused() {
		t.Fatalf("pause failed: code=%d paused=%v", code, w.Paused())
	}
	code, _ = postJSON(t, ts, "/api/watch/resume", nil)
	if code != http.StatusOK || w.Paused() {
		t.Fatalf("resume failed: code=%d paused=%v", code, w.Paused())
	}
}

// ---------------------------------------------------------------------------
// Cost
// ---------------------------------------------------------------------------

func TestCostSnapshot(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	tr := cost.NewTracker(cost.NewPricer(nil), "claude-opus-4-7", nil)
	tr.AddUsage(1_000_000, 500_000)
	s.SetCostTracker(tr)

	code, body := getJSON(t, ts, "/api/cost")
	if code != http.StatusOK {
		t.Fatalf("status = %d; body=%v", code, body)
	}
	total, _ := body["total"].(map[string]any)
	if total["input_tokens"].(float64) != 1_000_000 {
		t.Errorf("input_tokens = %v, want 1_000_000", total["input_tokens"])
	}
	if total["usd"].(float64) <= 0 {
		t.Errorf("usd = %v, want > 0", total["usd"])
	}
	byModel, _ := body["by_model"].([]any)
	if len(byModel) != 1 {
		t.Errorf("by_model len = %d, want 1", len(byModel))
	}
	// No budget configured → budget block is omitted (frontend
	// distinguishes "disabled" from "0/0" by absence).
	if _, ok := body["budget"]; ok {
		t.Errorf("budget block should be omitted when no cap is set")
	}
}

// TestBudgetGet_NoTracker returns 503 so the frontend can hide the
// budget tile when the host hasn't wired a cost tracker.
func TestBudgetGet_NoTracker(t *testing.T) {
	_, ts := apiServer(t, &fakeAgent{})
	code, _ := getJSON(t, ts, "/api/budget")
	if code != http.StatusServiceUnavailable {
		t.Errorf("code = %d, want 503", code)
	}
}

// TestBudgetGet_DisabledWhenNoCap returns {disabled: true} mirroring
// the CLI's "budget: disabled (spent $X)" line. Pre-v0.97 there was no
// such endpoint — web operators had no way to see the budget without
// reading the /api/cost rollup.
func TestBudgetGet_DisabledWhenNoCap(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	tr := cost.NewTracker(cost.NewPricer(nil), "claude-sonnet-4-6", nil)
	s.SetCostTracker(tr)
	code, body := getJSON(t, ts, "/api/budget")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	if disabled, _ := body["disabled"].(bool); !disabled {
		t.Errorf("disabled = %v, want true", body["disabled"])
	}
}

// TestBudgetGet_ShowsCapWhenSet pins the operator-visible block:
// cap_usd / spent_usd / remaining_usd / percent. Same shape as the
// budget block under /api/cost so the cockpit can use either.
func TestBudgetGet_ShowsCapWhenSet(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	tr := cost.NewTracker(cost.NewPricer(nil), "claude-sonnet-4-6", nil)
	tr.SetBudget(5.00, nil, nil)
	tr.AddUsageFull(0, 100000, 0, 0) // ~$1.50 spend → 30%
	s.SetCostTracker(tr)
	code, body := getJSON(t, ts, "/api/budget")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	if disabled, _ := body["disabled"].(bool); disabled {
		t.Errorf("disabled = true, want false (cap is set)")
	}
	if cap, _ := body["cap_usd"].(float64); cap != 5.0 {
		t.Errorf("cap_usd = %v, want 5.0", body["cap_usd"])
	}
}

// TestBudgetPut_SetsCap pins the runtime set path, mirroring the
// CLI's /budget set 10. Pre-v0.97 web operators had no way to raise
// or lower the cap mid-session — they had to restart with a new
// --budget flag.
func TestBudgetPut_SetsCap(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	tr := cost.NewTracker(cost.NewPricer(nil), "claude-sonnet-4-6", nil)
	s.SetCostTracker(tr)

	code, body := putJSON(t, ts, "/api/budget", map[string]any{"usd": 12.5})
	if code != http.StatusOK {
		t.Fatalf("code = %d, body=%s", code, body)
	}
	if got := tr.Snapshot().BudgetUSD; got != 12.5 {
		t.Errorf("BudgetUSD = %v, want 12.5", got)
	}
}

// TestBudgetPut_DisablesOnZero pins the disable path: usd=0 mirrors
// the CLI's /budget off and turns the cap off without removing the
// underlying callbacks.
func TestBudgetPut_DisablesOnZero(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	tr := cost.NewTracker(cost.NewPricer(nil), "claude-sonnet-4-6", nil)
	tr.SetBudget(5.00, nil, nil)
	s.SetCostTracker(tr)

	code, _ := putJSON(t, ts, "/api/budget", map[string]any{"usd": 0})
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	if got := tr.Snapshot().BudgetUSD; got != 0 {
		t.Errorf("BudgetUSD = %v, want 0", got)
	}
}

// TestBudgetPut_RejectsNegative pins the input-validation contract.
// The CLI's handleBudget also rejects negative values; the web
// endpoint must match so a fat-fingered -5 doesn't silently set 0.
func TestBudgetPut_RejectsNegative(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	tr := cost.NewTracker(cost.NewPricer(nil), "claude-sonnet-4-6", nil)
	tr.SetBudget(5.00, nil, nil)
	s.SetCostTracker(tr)

	code, _ := putJSON(t, ts, "/api/budget", map[string]any{"usd": -1.0})
	if code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", code)
	}
	if got := tr.Snapshot().BudgetUSD; got != 5.0 {
		t.Errorf("BudgetUSD = %v, want 5.0 (rejected PUT shouldn't mutate)", got)
	}
}

// TestCostSnapshot_BudgetBlock locks the budget rendering when a cap
// is configured. The web Cockpit reads cap_usd / spent_usd /
// remaining_usd / percent so it can paint a progress bar with the
// same shape as the /cost CLI rendering.
func TestCostSnapshot_BudgetBlock(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	tr := cost.NewTracker(cost.NewPricer(nil), "claude-sonnet-4-6", nil)
	tr.SetBudget(2.00, nil, nil)
	tr.AddUsageFull(0, 80000, 0, 0) // ~$1.20 spend → 60%
	s.SetCostTracker(tr)

	code, body := getJSON(t, ts, "/api/cost")
	if code != http.StatusOK {
		t.Fatalf("status = %d; body=%v", code, body)
	}
	budget, ok := body["budget"].(map[string]any)
	if !ok {
		t.Fatalf("budget block missing; body=%v", body)
	}
	if cap, _ := budget["cap_usd"].(float64); cap != 2.0 {
		t.Errorf("cap_usd = %v, want 2.0", budget["cap_usd"])
	}
	spent, _ := budget["spent_usd"].(float64)
	if spent <= 0 || spent > 2.0 {
		t.Errorf("spent_usd = %v, want 0 < spent <= cap", spent)
	}
	remaining, _ := budget["remaining_usd"].(float64)
	if remaining < 0 {
		t.Errorf("remaining_usd = %v, must be clamped >= 0", remaining)
	}
	pct, _ := budget["percent"].(float64)
	if pct <= 0 || pct > 100 {
		t.Errorf("percent = %v, want 0 < pct <= 100 for sub-cap spend", pct)
	}
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

func TestRulesList(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	eng := rules.New(rules.Deps{})
	eng.Register(rules.Rule{
		Name: "alpha", Description: "first", Enabled: true,
		Actions: []rules.Action{{Kind: rules.ActionLog, Params: map[string]interface{}{"message": "hi"}}},
	})
	s.SetRulesEngine(eng)

	code, body := getJSON(t, ts, "/api/rules")
	if code != http.StatusOK {
		t.Fatalf("status = %d; body=%v", code, body)
	}
	// Response is an array; decode as raw list.
	code, raw := postJSON(t, ts, "/api/rules/alpha/pause", nil)
	if code != http.StatusOK {
		t.Fatalf("pause status = %d; body=%s", code, raw)
	}
	code, _ = postJSON(t, ts, "/api/rules/alpha/resume", nil)
	if code != http.StatusOK {
		t.Fatalf("resume status = %d", code)
	}
}

func TestRuleTestRendersWithoutFiring(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	eng := rules.New(rules.Deps{})
	eng.Register(rules.Rule{
		Name: "preview-rule", Enabled: true,
		Actions: []rules.Action{{Kind: rules.ActionLog, Params: map[string]interface{}{"message": "tool={{tool}}"}}},
	})
	s.SetRulesEngine(eng)

	code, raw := postJSON(t, ts, "/api/rules/preview-rule/test", nil)
	if code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", code, raw)
	}
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	actions, _ := body["actions"].([]any)
	if len(actions) != 1 {
		t.Fatalf("actions = %v, want 1", actions)
	}
}

func TestRulePauseUnknownReturns404(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	s.SetRulesEngine(rules.New(rules.Deps{}))
	code, _ := postJSON(t, ts, "/api/rules/ghost/pause", nil)
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", code)
	}
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func TestValidateInlineContent(t *testing.T) {
	_, ts := apiServer(t, &fakeAgent{})

	code, raw := postJSON(t, ts, "/api/validate", map[string]string{
		"path":    "script.txt",
		"content": "STRING rm -rf /\n",
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", code, raw)
	}
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	if body["overall_risk"] != "critical" {
		t.Errorf("overall_risk = %v, want critical", body["overall_risk"])
	}
	if body["approved"] != false {
		t.Errorf("approved = %v, want false for critical", body["approved"])
	}
}

func TestValidateReadsFileFromPath(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	dir := t.TempDir()
	s.SetValidateBase(dir)
	p := filepath.Join(dir, "harmless.txt")
	if err := os.WriteFile(p, []byte("REM harmless\nSTRING hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, raw := postJSON(t, ts, "/api/validate", map[string]string{"path": p})
	if code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", code, raw)
	}
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	if body["approved"] != true {
		t.Errorf("approved = %v, want true for harmless script", body["approved"])
	}
}

// TestValidateRejectsEtcShadow proves that the /api/validate path reader
// refuses to open /etc/shadow (or anything else outside the configured safe
// base). Critical: without the base check, an unauthenticated caller with a
// bearer token could grep the server host's filesystem.
func TestValidateRejectsEtcShadow(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	dir := t.TempDir()
	s.SetValidateBase(dir)

	code, raw := postJSON(t, ts, "/api/validate", map[string]string{"path": "/etc/shadow"})
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for /etc/shadow; body=%s", code, raw)
	}
}

// TestValidateRejectsPathWhenNoBaseConfigured exercises the default: a
// server that never called SetValidateBase must 403 on every path read.
func TestValidateRejectsPathWhenNoBaseConfigured(t *testing.T) {
	_, ts := apiServer(t, &fakeAgent{})
	// NO SetValidateBase — base is "" (default).
	code, raw := postJSON(t, ts, "/api/validate", map[string]string{"path": "/tmp/whatever"})
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 with no base configured; body=%s", code, raw)
	}
}

// TestValidateRejectsSymlinkEscape proves the resolver follows symlinks
// (EvalSymlinks) so an attacker cannot drop a symlink inside the safe base
// pointing at a sensitive file outside it.
func TestValidateRejectsSymlinkEscape(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	base := t.TempDir()
	outside := t.TempDir()
	s.SetValidateBase(base)

	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("hush"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "sneaky")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}

	code, raw := postJSON(t, ts, "/api/validate", map[string]string{"path": link})
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for symlink escape; body=%s", code, raw)
	}
}

// ---------------------------------------------------------------------------
// Debug
// ---------------------------------------------------------------------------

func TestDebugSnapshotShape(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	s.SetFlipperConnected(true)
	s.SetMarauderConnected(false)

	code, body := getJSON(t, ts, "/api/debug")
	if code != http.StatusOK {
		t.Fatalf("status = %d; body=%v", code, body)
	}
	for _, key := range []string{"build", "runtime", "state"} {
		if _, ok := body[key]; !ok {
			t.Errorf("missing top-level %q in %v", key, body)
		}
	}
	state, _ := body["state"].(map[string]any)
	if state["flipper_connected"] != true {
		t.Errorf("flipper_connected = %v, want true", state["flipper_connected"])
	}
	rt, _ := body["runtime"].(map[string]any)
	if rt["goroutines"].(float64) <= 0 {
		t.Errorf("goroutines = %v, want > 0", rt["goroutines"])
	}
}
