package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/session"
)

// fakeSessionDriver wraps a real *session.Store so tests can verify the
// HTTP layer end-to-end against the actual on-disk wire format. ResumeSession
// just records the id; we don't need a live agent for transport testing.
type fakeSessionDriver struct {
	mu        sync.Mutex
	store     *session.Store
	active    string
	resumed   string
	deleted   string
	renamedTo map[string]string
	resumeErr error
}

func newFakeSessionDriver(t *testing.T) *fakeSessionDriver {
	t.Helper()
	dir := t.TempDir()
	st, err := session.NewStore(dir)
	if err != nil {
		t.Fatalf("session.NewStore: %v", err)
	}
	return &fakeSessionDriver{store: st, renamedTo: make(map[string]string)}
}

func (f *fakeSessionDriver) SessionID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active
}

func (f *fakeSessionDriver) NewSession() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active = "new-session"
	return f.active
}

func (f *fakeSessionDriver) ListSessions() ([]session.State, error) {
	return f.store.List()
}

func (f *fakeSessionDriver) ResumeSession(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resumeErr != nil {
		return f.resumeErr
	}
	if _, err := f.store.Load(id); err != nil {
		return err
	}
	f.resumed = id
	f.active = id
	return nil
}

func (f *fakeSessionDriver) RenameSession(id, title string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, err := f.store.Load(id)
	if err != nil {
		return err
	}
	state.Title = title
	f.renamedTo[id] = title
	return f.store.Save(state)
}

func (f *fakeSessionDriver) DeleteSession(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = id
	return f.store.Delete(id)
}

// seed plants two saved sessions on disk: an older "alpha" and a newer
// "beta" with one user + one assistant message and a tool roundtrip on
// beta so the transcript-render test has real Raw content to walk.
func (f *fakeSessionDriver) seed(t *testing.T) (alphaID, betaID string) {
	t.Helper()
	alpha := &session.State{
		ID:        "alpha",
		Title:     "Alpha session",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		Model:     "claude-sonnet-test",
	}
	if err := f.store.Save(alpha); err != nil {
		t.Fatalf("save alpha: %v", err)
	}
	// Make sure UpdatedAt for beta is strictly later than alpha so the
	// list ordering test is deterministic regardless of FS clock granularity.
	time.Sleep(2 * time.Millisecond)

	user := anthropic.NewUserMessage(anthropic.NewTextBlock("hello there"))
	assistant := anthropic.NewAssistantMessage(
		anthropic.NewTextBlock("checking files"),
		anthropic.NewToolUseBlock("tool-1", map[string]any{"path": "/ext"}, "list_files"),
	)
	toolResult := anthropic.NewUserMessage(anthropic.NewToolResultBlock("tool-1", "ok\nfile1\nfile2", false))

	betaMsgs := []anthropic.MessageParam{user, assistant, toolResult}
	out := make([]session.Message, 0, len(betaMsgs))
	for _, m := range betaMsgs {
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		out = append(out, session.Message{Role: string(m.Role), Raw: raw})
	}
	beta := &session.State{
		ID:        "beta",
		Title:     "Beta session",
		CreatedAt: time.Now().Add(-1 * time.Hour),
		Messages:  out,
		Model:     "claude-sonnet-test",
	}
	if err := f.store.Save(beta); err != nil {
		t.Fatalf("save beta: %v", err)
	}
	f.mu.Lock()
	f.active = "beta"
	f.mu.Unlock()
	return "alpha", "beta"
}

func TestSessionList_OrdersNewestFirstAndMarksActive(t *testing.T) {
	fa := &fakeAgent{}
	srv, ts := apiServer(t, fa)
	driver := newFakeSessionDriver(t)
	driver.seed(t)
	srv.SetSessionDriver(driver)

	status, body := getJSON(t, ts, "/api/sessions")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if body["active"] != "beta" {
		t.Errorf("active = %v, want beta", body["active"])
	}
	list, _ := body["sessions"].([]any)
	if len(list) != 2 {
		t.Fatalf("got %d sessions, want 2", len(list))
	}
	first := list[0].(map[string]any)
	second := list[1].(map[string]any)
	if first["id"] != "beta" {
		t.Errorf("first.id = %v, want beta (newer)", first["id"])
	}
	if first["active"] != true {
		t.Errorf("active flag missing on beta")
	}
	if second["id"] != "alpha" {
		t.Errorf("second.id = %v, want alpha", second["id"])
	}
}

// Pre-existing on-disk session files (saved before the Title field
// existed) must surface a derived sidebar label rather than the raw
// "Untitled session" placeholder. This guards the API-side fallback in
// listEntryFromState that decodes Raw on the fly.
func TestSessionList_DerivesTitleForLegacyState(t *testing.T) {
	fa := &fakeAgent{}
	srv, ts := apiServer(t, fa)
	driver := newFakeSessionDriver(t)
	srv.SetSessionDriver(driver)

	// Save a state with no Title, only a real user message in Raw.
	user := anthropic.NewUserMessage(anthropic.NewTextBlock("scan wifi networks"))
	raw, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	state := &session.State{
		ID: "legacy",
		Messages: []session.Message{
			{Role: string(user.Role), Raw: raw},
		},
	}
	if err := driver.store.Save(state); err != nil {
		t.Fatalf("save: %v", err)
	}

	status, body := getJSON(t, ts, "/api/sessions")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	list := body["sessions"].([]any)
	if len(list) != 1 {
		t.Fatalf("got %d sessions", len(list))
	}
	entry := list[0].(map[string]any)
	if entry["title"] != "scan wifi networks" {
		t.Errorf("title = %v, want derived from first user message", entry["title"])
	}
}

func TestSessionList_503WhenDriverMissing(t *testing.T) {
	_, ts := apiServer(t, &fakeAgent{})
	status, _ := getJSON(t, ts, "/api/sessions")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", status)
	}
}

func TestSessionGet_RendersTranscriptEvents(t *testing.T) {
	fa := &fakeAgent{}
	srv, ts := apiServer(t, fa)
	driver := newFakeSessionDriver(t)
	driver.seed(t)
	srv.SetSessionDriver(driver)

	status, body := getJSON(t, ts, "/api/sessions/beta")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	events, ok := body["events"].([]any)
	if !ok || len(events) == 0 {
		t.Fatalf("events missing or empty: %v", body["events"])
	}

	kinds := make([]string, 0, len(events))
	for _, ev := range events {
		m := ev.(map[string]any)
		kinds = append(kinds, m["kind"].(string))
	}
	want := []string{"user_text", "assistant_text", "tool_use", "tool_result"}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("event kinds = %v, want %v", kinds, want)
	}

	tu := events[2].(map[string]any)
	if tu["name"] != "list_files" {
		t.Errorf("tool_use.name = %v, want list_files", tu["name"])
	}
	if tu["tool_use_id"] != "tool-1" {
		t.Errorf("tool_use.tool_use_id = %v, want tool-1", tu["tool_use_id"])
	}
	tr := events[3].(map[string]any)
	if tr["tool_use_id"] != "tool-1" {
		t.Errorf("tool_result.tool_use_id = %v, want tool-1", tr["tool_use_id"])
	}
	if !strings.Contains(tr["output"].(string), "file1") {
		t.Errorf("tool_result.output missing seeded text: %v", tr["output"])
	}
}

func TestSessionGet_NotFound(t *testing.T) {
	fa := &fakeAgent{}
	srv, ts := apiServer(t, fa)
	driver := newFakeSessionDriver(t)
	driver.seed(t)
	srv.SetSessionDriver(driver)

	status, _ := getJSON(t, ts, "/api/sessions/missing")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
}

func TestSessionResume_BroadcastsAndRecordsID(t *testing.T) {
	fa := &fakeAgent{}
	srv, ts := apiServer(t, fa)
	driver := newFakeSessionDriver(t)
	driver.seed(t)
	srv.SetSessionDriver(driver)

	status, _ := postJSON(t, ts, "/api/sessions/alpha/resume", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if driver.resumed != "alpha" {
		t.Errorf("resumed = %q, want alpha", driver.resumed)
	}
	if driver.SessionID() != "alpha" {
		t.Errorf("SessionID = %q, want alpha", driver.SessionID())
	}
}

func TestSessionResume_PropagatesAgentError(t *testing.T) {
	fa := &fakeAgent{}
	srv, ts := apiServer(t, fa)
	driver := newFakeSessionDriver(t)
	driver.seed(t)
	driver.resumeErr = errors.New("nope")
	srv.SetSessionDriver(driver)

	status, _ := postJSON(t, ts, "/api/sessions/alpha/resume", nil)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
}

func TestSessionRename_PersistsTitle(t *testing.T) {
	fa := &fakeAgent{}
	srv, ts := apiServer(t, fa)
	driver := newFakeSessionDriver(t)
	driver.seed(t)
	srv.SetSessionDriver(driver)

	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodPatch,
		ts.URL+"/api/sessions/alpha",
		strings.NewReader(`{"title":"Renamed"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("PATCH: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if driver.renamedTo["alpha"] != "Renamed" {
		t.Errorf("title = %q, want Renamed", driver.renamedTo["alpha"])
	}
	state, err := driver.store.Load("alpha")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if state.Title != "Renamed" {
		t.Errorf("persisted title = %q, want Renamed", state.Title)
	}
}

func TestSessionDelete_RotatesActive(t *testing.T) {
	fa := &fakeAgent{}
	srv, ts := apiServer(t, fa)
	driver := newFakeSessionDriver(t)
	driver.seed(t)
	srv.SetSessionDriver(driver)

	// Deleting the active session should swap to a fresh one.
	req, _ := http.NewRequestWithContext(
		context.Background(), http.MethodDelete, ts.URL+"/api/sessions/beta", nil,
	)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if driver.deleted != "beta" {
		t.Errorf("deleted = %q, want beta", driver.deleted)
	}
	if driver.SessionID() != "new-session" {
		t.Errorf("active after delete = %q, want new-session", driver.SessionID())
	}
}

func TestSessionNew_CallsDriver(t *testing.T) {
	fa := &fakeAgent{}
	srv, ts := apiServer(t, fa)
	driver := newFakeSessionDriver(t)
	srv.SetSessionDriver(driver)

	status, body := postJSON(t, ts, "/api/sessions", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != "new-session" {
		t.Errorf("id = %q, want new-session", got.ID)
	}
}

// Compile-time guard: *agent.Agent must satisfy sessionDriver so the
// production wiring in cmd/promptzero/setup.go (`srv.SetSessionDriver(deps.Ai)`)
// stays type-safe even if the Server interface is renamed.
var _ sessionDriver = (*agent.Agent)(nil)
