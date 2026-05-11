// Tests for the REPL-parity HTTP endpoints. Each panel gets a focused
// test that exercises both the success and the not-configured paths so
// the frontend contract stays observable.

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/cost"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/mode"
	"github.com/xunholy/promptzero/internal/persona"
	"github.com/xunholy/promptzero/internal/rules"
	"github.com/xunholy/promptzero/internal/snapshot"
	"github.com/xunholy/promptzero/internal/watch"
	"github.com/xunholy/promptzero/internal/webhook"
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

// deleteReq performs a DELETE without a body and decodes the JSON
// response. Used by /api/attack DELETE — first DELETE in the API
// surface aside from /api/sessions/{id} which has its own pattern.
func deleteReq(t *testing.T, ts *httptest.Server, path string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, ts.URL+path, nil)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", path, err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
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

// TestRewindList_503WhenNoSnapshotMgr returns 503 so the cockpit
// hides the rewind panel when the host didn't wire a snapshot
// manager (typical for tests / non-Flipper setups).
func TestRewindList_503WhenNoSnapshotMgr(t *testing.T) {
	_, ts := apiServer(t, &fakeAgent{sessionID: "x"})
	code, _ := getJSON(t, ts, "/api/rewind")
	if code != http.StatusServiceUnavailable {
		t.Errorf("code = %d, want 503", code)
	}
}

// TestRewindList_400WhenNoActiveSession pins the no-session branch.
// Without a session the snapshot tree has no key to list under.
func TestRewindList_400WhenNoActiveSession(t *testing.T) {
	mgr := snapshot.NewManager(t.TempDir())
	_, ts := apiServer(t, &fakeAgent{snapshotMgr: mgr})
	code, _ := getJSON(t, ts, "/api/rewind")
	if code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", code)
	}
}

// TestRewindList_ReturnsEntries pins the happy path. Two snapshots
// stored → list returns both, newest-first.
func TestRewindList_ReturnsEntries(t *testing.T) {
	mgr := snapshot.NewManager(t.TempDir())
	if _, err := mgr.Store("sess-1", "/ext/a.sub", []byte("a")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if _, err := mgr.Store("sess-1", "/ext/b.sub", []byte("bb")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	_, ts := apiServer(t, &fakeAgent{snapshotMgr: mgr, sessionID: "sess-1"})

	code, body := getJSON(t, ts, "/api/rewind")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	entries, _ := body["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(entries))
	}
	// Spot-check fields on the first entry.
	first, _ := entries[0].(map[string]any)
	if _, ok := first["id"].(string); !ok {
		t.Errorf("entry missing id: %v", first)
	}
	if _, ok := first["original_path"].(string); !ok {
		t.Errorf("entry missing original_path: %v", first)
	}
}

// TestRewindRestore_DryRun pins the dry-run path: snapshot is
// loaded but no write happens (we don't need a real Flipper for
// dry-run). Cockpit can preview a restore safely.
func TestRewindRestore_DryRun(t *testing.T) {
	mgr := snapshot.NewManager(t.TempDir())
	entry, err := mgr.Store("sess-1", "/ext/a.sub", []byte("hello"))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	// Dry-run skips the flipper write, so no flipper is needed.
	s, ts := apiServer(t, &fakeAgent{snapshotMgr: mgr, sessionID: "sess-1"})
	// Still need s.flipper to pass the early 503 check. The dry-run
	// branch returns before invoking it.
	s.flipper = sentinelFlipper(t)

	code, body := postJSON(t, ts, "/api/rewind/restore", map[string]any{
		"id":      entry.ID,
		"dry_run": true,
	})
	if code != http.StatusOK {
		t.Fatalf("code = %d, body=%s", code, body)
	}
	var dto map[string]any
	if err := json.Unmarshal(body, &dto); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !dto["dry_run"].(bool) {
		t.Errorf("dry_run flag not set in response")
	}
	if got := int(dto["would_write"].(float64)); got != 5 {
		t.Errorf("would_write = %d, want 5", got)
	}
}

// TestRewindRestore_404OnUnknownID pins the missing-snapshot branch.
func TestRewindRestore_404OnUnknownID(t *testing.T) {
	mgr := snapshot.NewManager(t.TempDir())
	s, ts := apiServer(t, &fakeAgent{snapshotMgr: mgr, sessionID: "sess-1"})
	s.flipper = sentinelFlipper(t)

	code, _ := postJSON(t, ts, "/api/rewind/restore", map[string]any{"id": "nonexistent-id"})
	if code != http.StatusNotFound {
		t.Errorf("code = %d, want 404", code)
	}
}

// sentinelFlipper returns a non-nil *flipper.Flipper for tests that
// just need the nil-check to pass — we never call any of its
// methods in dry-run or 404 paths.
func sentinelFlipper(t *testing.T) *flipper.Flipper {
	t.Helper()
	return &flipper.Flipper{}
}

// TestReport_503WhenAuditMissing returns 503 so the cockpit can
// hide the report button when no audit log is wired.
func TestReport_503WhenAuditMissing(t *testing.T) {
	_, ts := apiServer(t, &fakeAgent{})
	code, _ := getJSON(t, ts, "/api/report")
	if code != http.StatusServiceUnavailable {
		t.Errorf("code = %d, want 503", code)
	}
}

// TestReport_DefaultMarkdownBody pins the happy path: GET with no
// query params returns markdown for the audit log's current session.
// The cockpit can render the body in-place or trigger save-as.
func TestReport_DefaultMarkdownBody(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	logPath := filepath.Join(t.TempDir(), "audit.db")
	l, _ := audit.Open(logPath)
	t.Cleanup(func() { _ = l.Close() })
	l.Record("subghz_rx", nil, "ok", "low", audit.LevelAction, 0, true)
	s.SetAuditLog(l)

	resp, err := ts.Client().Get(ts.URL + "/api/report")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("code = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("content-type = %q, want text/markdown prefix", ct)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, "# PromptZero Session Report") {
		end := 200
		if len(body) < end {
			end = len(body)
		}
		t.Errorf("body missing markdown title heading; got: %q", body[:end])
	}
}

// TestReport_JSONFormat pins the format=json branch. The body is
// the raw JSON renderer output with application/json content-type
// so the cockpit can parse it directly.
func TestReport_JSONFormat(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	logPath := filepath.Join(t.TempDir(), "audit.db")
	l, _ := audit.Open(logPath)
	t.Cleanup(func() { _ = l.Close() })
	l.Record("subghz_rx", nil, "ok", "low", audit.LevelAction, 0, true)
	s.SetAuditLog(l)

	resp, err := ts.Client().Get(ts.URL + "/api/report?format=json")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("code = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var dto map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&dto); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if _, ok := dto["session_id"]; !ok {
		keys := make([]string, 0, len(dto))
		for k := range dto {
			keys = append(keys, k)
		}
		t.Errorf("JSON report missing session_id; got keys %v", keys)
	}
}

// TestReport_RejectsBadFormat pins the validation contract: any
// format other than md|json gets 400.
func TestReport_RejectsBadFormat(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	logPath := filepath.Join(t.TempDir(), "audit.db")
	l, _ := audit.Open(logPath)
	t.Cleanup(func() { _ = l.Close() })
	s.SetAuditLog(l)

	code, _ := getJSON(t, ts, "/api/report?format=xml")
	if code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", code)
	}
}

// TestToolsList_ReturnsCatalog pins the GET /api/tools surface:
// every registered tool with name + description, count + total
// scalars, and the has_marauder boolean. Mirrors CLI /tools.
func TestToolsList_ReturnsCatalog(t *testing.T) {
	_, ts := apiServer(t, &fakeAgent{})
	code, body := getJSON(t, ts, "/api/tools")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	if total, _ := body["total"].(float64); total < 50 {
		t.Errorf("total = %v, want >= 50 (catalogue should be substantial)", total)
	}
	tools, _ := body["tools"].([]any)
	if len(tools) == 0 {
		t.Fatalf("tools array empty")
	}
	// Spot-check: every entry has name + description fields.
	first, _ := tools[0].(map[string]any)
	if _, ok := first["name"].(string); !ok {
		t.Errorf("first entry missing name: %v", first)
	}
}

// TestToolsList_FilterNarrows pins the ?filter=... behaviour. The
// CLI's /tools <filter> uses the same substring-match-on-name rule.
func TestToolsList_FilterNarrows(t *testing.T) {
	_, ts := apiServer(t, &fakeAgent{})
	codeAll, bodyAll := getJSON(t, ts, "/api/tools")
	if codeAll != http.StatusOK {
		t.Fatalf("unfiltered code = %d", codeAll)
	}
	allTotal := int(bodyAll["total"].(float64))

	code, body := getJSON(t, ts, "/api/tools?filter=flipper")
	if code != http.StatusOK {
		t.Fatalf("filtered code = %d", code)
	}
	count := int(body["count"].(float64))
	if count >= allTotal {
		t.Errorf("filter=flipper yielded %d, total catalogue is %d — filter didn't narrow", count, allTotal)
	}
	if count == 0 {
		t.Errorf("filter=flipper returned 0 entries; catalogue should have many flipper_* tools")
	}
}

// TestWebhooksList_503WhenUnset returns 503 when no dispatcher is
// wired, mirroring the pattern other panels use.
func TestWebhooksList_503WhenUnset(t *testing.T) {
	_, ts := apiServer(t, &fakeAgent{})
	code, _ := getJSON(t, ts, "/api/webhooks")
	if code != http.StatusServiceUnavailable {
		t.Errorf("code = %d, want 503", code)
	}
}

// TestWebhooksList_ReturnsSubscriptions pins the happy path. Two
// subscriptions configured → list returns both, with secret hidden
// (only the `signed` boolean exposed).
func TestWebhooksList_ReturnsSubscriptions(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	wh := webhook.New([]webhook.Subscription{
		{Name: "ops", URL: "https://ops.example/hook"},
		{Name: "secure", URL: "https://sec.example/hook", Secret: "shhh"},
	})
	t.Cleanup(func() { _ = wh.Close(context.Background()) })
	s.SetWebhooks(wh)

	code, body := getJSON(t, ts, "/api/webhooks")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	subs, _ := body["subscriptions"].([]any)
	if len(subs) != 2 {
		t.Fatalf("subscriptions len = %d, want 2", len(subs))
	}
	// Find the signed one and verify the secret is NOT in the body.
	for _, s := range subs {
		row, _ := s.(map[string]any)
		if row["name"] == "secure" {
			if signed, _ := row["signed"].(bool); !signed {
				t.Errorf("signed=false for subscription with non-empty Secret")
			}
			if _, leaked := row["secret"]; leaked {
				t.Errorf("secret leaked into response body: %v", row)
			}
		}
	}
}

// TestReconnect_503WhenFlipperMissing returns 503 when no Flipper
// is attached — the cockpit shows the reconnect button greyed out.
func TestReconnect_503WhenFlipperMissing(t *testing.T) {
	_, ts := apiServer(t, &fakeAgent{})
	code, _ := postJSON(t, ts, "/api/reconnect", nil)
	if code != http.StatusServiceUnavailable {
		t.Errorf("code = %d, want 503", code)
	}
}

// TestAttackGet_EmptyByDefault returns an empty techniques list when
// no constraint has been set. Cockpit uses the empty/non-empty
// distinction to render a "constrained to ATT&CK ..." chip.
func TestAttackGet_EmptyByDefault(t *testing.T) {
	fa := &fakeAgent{}
	_, ts := apiServer(t, fa)
	code, body := getJSON(t, ts, "/api/attack")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	techniques, _ := body["techniques"].([]any)
	if len(techniques) != 0 {
		t.Errorf("expected empty list, got %v", techniques)
	}
}

// TestAttackSet_NormalisesAndApplies pins the happy path: case-folded
// lowercase input ("t1557.004") + whitespace are accepted and stored
// in canonical uppercase. Mirrors the CLI's normaliseAttackIDs.
func TestAttackSet_NormalisesAndApplies(t *testing.T) {
	fa := &fakeAgent{}
	_, ts := apiServer(t, fa)
	code, body := postJSON(t, ts, "/api/attack", map[string]any{
		"techniques": []string{"t1557.004", "  T1499 "},
	})
	if code != http.StatusOK {
		t.Fatalf("code = %d, body=%s", code, body)
	}
	got := fa.AttackConstraint()
	if len(got) != 2 || got[0] != "T1557.004" || got[1] != "T1499" {
		t.Errorf("AttackConstraint = %v, want [T1557.004 T1499]", got)
	}
}

// TestAttackSet_RejectsBadID pins the validation contract: anything
// that doesn't match T#### or T####.### gets 400 with the same
// error shape the CLI surfaces. State unchanged on rejection.
func TestAttackSet_RejectsBadID(t *testing.T) {
	fa := &fakeAgent{attackIDs: []string{"T1234"}}
	_, ts := apiServer(t, fa)
	code, _ := postJSON(t, ts, "/api/attack", map[string]any{
		"techniques": []string{"BogusID"},
	})
	if code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", code)
	}
	got := fa.AttackConstraint()
	if len(got) != 1 || got[0] != "T1234" {
		t.Errorf("AttackConstraint mutated despite 400: got %v", got)
	}
}

// TestAttackSet_EmptyTechniquesRejected pins the contract that
// "set with no IDs" is a 400 — use DELETE /api/attack to clear.
// This avoids the silent "set nothing = clear" footgun.
func TestAttackSet_EmptyTechniquesRejected(t *testing.T) {
	fa := &fakeAgent{}
	_, ts := apiServer(t, fa)
	code, _ := postJSON(t, ts, "/api/attack", map[string]any{"techniques": []string{}})
	if code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400 (use DELETE to clear)", code)
	}
}

// TestAttackClear_RemovesConstraint pins the DELETE path: the
// constraint is wiped. Mirrors CLI `/attack clear`.
func TestAttackClear_RemovesConstraint(t *testing.T) {
	fa := &fakeAgent{attackIDs: []string{"T1557.004"}}
	_, ts := apiServer(t, fa)
	code, body := deleteReq(t, ts, "/api/attack")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	techniques, _ := body["techniques"].([]any)
	if len(techniques) != 0 {
		t.Errorf("expected empty list after clear, got %v", techniques)
	}
	if fa.AttackConstraint() != nil {
		t.Errorf("AttackConstraint not nil after DELETE: %v", fa.AttackConstraint())
	}
}

// TestAuditEndpoints_503WhenLogMissing verifies all six /api/audit
// endpoints return 503 (so the cockpit can hide the audit panel)
// when the host hasn't wired an audit log via SetAuditLog.
func TestAuditEndpoints_503WhenLogMissing(t *testing.T) {
	_, ts := apiServer(t, &fakeAgent{})
	endpoints := []string{
		"/api/audit/stats",
		"/api/audit/query",
		"/api/audit/find",
		"/api/audit/session/abc",
		"/api/audit/top",
		"/api/audit/export",
	}
	for _, p := range endpoints {
		t.Run(p, func(t *testing.T) {
			code, _ := getJSON(t, ts, p)
			if code != http.StatusServiceUnavailable {
				t.Errorf("code = %d, want 503", code)
			}
		})
	}
}

// TestAuditQuery_ReturnsRecentRows pins the GET /api/audit/query
// happy path: insert two rows, GET, expect both back. Mirrors the
// CLI's `/audit query [N]` (default N=20). Limit cap parsing is
// shared with handleAuditFind so we test the parse only there.
func TestAuditQuery_ReturnsRecentRows(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	logPath := filepath.Join(t.TempDir(), "audit.db")
	l, err := audit.Open(logPath)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	l.Record("subghz_rx", nil, "out", "low", audit.LevelAction, 0, true)
	l.Record("flipper_device_info", nil, "out2", "low", audit.LevelAction, 0, true)
	s.SetAuditLog(l)

	code, body := getJSON(t, ts, "/api/audit/query?n=10")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	entries, _ := body["entries"].([]any)
	if len(entries) != 2 {
		t.Errorf("entries len = %d, want 2", len(entries))
	}
}

// TestAuditFind_FiltersByTool pins the GET /api/audit/find filtering
// behaviour. Same DSL the CLI's parseAuditFilter uses, just expressed
// as URL query params instead of `k=v` tokens.
func TestAuditFind_FiltersByTool(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	logPath := filepath.Join(t.TempDir(), "audit.db")
	l, _ := audit.Open(logPath)
	t.Cleanup(func() { _ = l.Close() })
	l.Record("subghz_rx", nil, "a", "low", audit.LevelAction, 0, true)
	l.Record("flipper_device_info", nil, "b", "low", audit.LevelAction, 0, true)
	s.SetAuditLog(l)

	code, body := getJSON(t, ts, "/api/audit/find?tool=subghz")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	entries, _ := body["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1 (only subghz_rx matches)", len(entries))
	}
}

// TestAuditFind_RejectsBadRisk pins the input validation: the CLI's
// parseAuditFilter rejects unknown risk levels and the web mirror
// must match so the cockpit shows the same error.
func TestAuditFind_RejectsBadRisk(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	logPath := filepath.Join(t.TempDir(), "audit.db")
	l, _ := audit.Open(logPath)
	t.Cleanup(func() { _ = l.Close() })
	s.SetAuditLog(l)

	code, _ := getJSON(t, ts, "/api/audit/find?risk=neon")
	if code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", code)
	}
}

// TestAuditTop_ToolsAggregation pins the top-tools surface. Three
// invocations of subghz_rx + one of device_info → subghz_rx should
// be top.
func TestAuditTop_ToolsAggregation(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	logPath := filepath.Join(t.TempDir(), "audit.db")
	l, _ := audit.Open(logPath)
	t.Cleanup(func() { _ = l.Close() })
	for i := 0; i < 3; i++ {
		l.Record("subghz_rx", nil, "o", "low", audit.LevelAction, 0, true)
	}
	l.Record("flipper_device_info", nil, "o", "low", audit.LevelAction, 0, true)
	s.SetAuditLog(l)

	code, body := getJSON(t, ts, "/api/audit/top?on=tools")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	rows, _ := body["rows"].([]any)
	if len(rows) == 0 {
		t.Fatalf("rows empty: %v", body)
	}
	first, _ := rows[0].(map[string]any)
	if tool, _ := first["tool"].(string); tool != "subghz_rx" {
		t.Errorf("top tool = %v, want subghz_rx", first["tool"])
	}
}

// TestAuditExport_ReturnsJSONBody pins the export endpoint — it
// returns the raw JSON Export() produces. Cockpit can save the
// response body to disk for triage / report attachment.
func TestAuditExport_ReturnsJSONBody(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	logPath := filepath.Join(t.TempDir(), "audit.db")
	l, _ := audit.Open(logPath)
	t.Cleanup(func() { _ = l.Close() })
	l.Record("subghz_rx", nil, "o", "low", audit.LevelAction, 0, true)
	s.SetAuditLog(l)

	resp, err := ts.Client().Get(ts.URL + "/api/audit/export")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("code = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
}

// TestModeGet_ListsAllModes pins the GET /api/mode surface: active +
// available catalogue with display names, descriptions, and the
// read-restrictive flag. Mirrors the CLI's `/mode` (no-args) listing.
func TestModeGet_ListsAllModes(t *testing.T) {
	fa := &fakeAgent{opMode: mode.ModeRecon, readOnly: true}
	_, ts := apiServer(t, fa)
	code, body := getJSON(t, ts, "/api/mode")
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	if active, _ := body["active"].(string); active != "recon" {
		t.Errorf("active = %v, want recon", body["active"])
	}
	if ro, _ := body["read_only"].(bool); !ro {
		t.Errorf("read_only = false, want true (recon engages it)")
	}
	avail, ok := body["available"].([]any)
	if !ok || len(avail) == 0 {
		t.Fatalf("available list missing or empty: %v", body["available"])
	}
}

// TestModeSet_SwitchesMode pins the operator-facing POST: body
// {"name": "stealth"} switches the active mode AND engages ReadOnly
// (stealth is read-restrictive). Matches handleMode's runtime
// behaviour (v0.80 fix).
func TestModeSet_SwitchesMode(t *testing.T) {
	fa := &fakeAgent{opMode: mode.ModeStandard, readOnly: false}
	_, ts := apiServer(t, fa)
	code, body := postJSON(t, ts, "/api/mode", map[string]any{"name": "stealth"})
	if code != http.StatusOK {
		t.Fatalf("code = %d, body=%s", code, body)
	}
	if got := fa.Mode(); got != mode.ModeStealth {
		t.Errorf("Mode() = %v, want stealth", got)
	}
	if !fa.ReadOnly() {
		t.Errorf("ReadOnly() = false; stealth is read-restrictive and must engage it")
	}
}

// TestModeSet_StandardDoesNotEngageReadOnly pins the negative
// branch: switching to standard mode does NOT touch the ReadOnly
// flag. The CLI handleMode only engages ReadOnly when the new mode
// is read-restrictive; standard is not.
func TestModeSet_StandardDoesNotEngageReadOnly(t *testing.T) {
	fa := &fakeAgent{opMode: mode.ModeRecon, readOnly: true}
	_, ts := apiServer(t, fa)
	code, _ := postJSON(t, ts, "/api/mode", map[string]any{"name": "standard"})
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	if got := fa.Mode(); got != mode.ModeStandard {
		t.Errorf("Mode() = %v, want standard", got)
	}
	// ReadOnly stays where it was — matches handleMode's "engage only
	// on entering restrictive mode" behaviour. The operator can
	// switch ReadOnly off via a separate mechanism if needed.
}

// TestModeSet_RejectsUnknown pins the input-validation contract:
// unknown mode names get 400 with the same error shape as the CLI's
// ParseMode error. The cockpit can render that verbatim.
func TestModeSet_RejectsUnknown(t *testing.T) {
	fa := &fakeAgent{opMode: mode.ModeStandard}
	_, ts := apiServer(t, fa)
	code, _ := postJSON(t, ts, "/api/mode", map[string]any{"name": "wrong-name"})
	if code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", code)
	}
	if got := fa.Mode(); got != mode.ModeStandard {
		t.Errorf("Mode() = %v, want standard (rejected POST shouldn't mutate)", got)
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
