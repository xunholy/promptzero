package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/mode"
	"github.com/xunholy/promptzero/internal/persona"
)

// fakeAgent satisfies agentDriver without touching any real LLM client. The
// runFn is invoked from Run inside a goroutine so tests can drive the three
// registered callbacks (textDelta, toolStatus, confirm) mid-turn.
type fakeAgent struct {
	mu           sync.Mutex
	textDeltaCb  func(agent.TextDelta)
	toolStatusCb func(agent.ToolEvent)
	confirmCb    agent.ConfirmFunc
	runFn        func(ctx context.Context, input string, f *fakeAgent) (string, error)
	resetCalls   int
	lastRunInput string
	persona      *persona.Persona
	opMode       mode.Mode
	readOnly     bool
}

func (f *fakeAgent) Run(ctx context.Context, input string) (string, error) {
	f.mu.Lock()
	f.lastRunInput = input
	fn := f.runFn
	f.mu.Unlock()
	if fn == nil {
		return "ok", nil
	}
	return fn(ctx, input, f)
}

func (f *fakeAgent) Reset() {
	f.mu.Lock()
	f.resetCalls++
	f.mu.Unlock()
}

func (f *fakeAgent) SetTextDeltaCallback(cb func(agent.TextDelta)) {
	f.mu.Lock()
	f.textDeltaCb = cb
	f.mu.Unlock()
}
func (f *fakeAgent) SetToolStatusCallback(cb func(agent.ToolEvent)) {
	f.mu.Lock()
	f.toolStatusCb = cb
	f.mu.Unlock()
}
func (f *fakeAgent) SetConfirmCallback(cb agent.ConfirmFunc) {
	f.mu.Lock()
	f.confirmCb = cb
	f.mu.Unlock()
}

func (f *fakeAgent) SetPersona(p *persona.Persona) {
	f.mu.Lock()
	f.persona = p
	f.mu.Unlock()
}

func (f *fakeAgent) Persona() *persona.Persona {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.persona
}

func (f *fakeAgent) PersonaSnapshot() *persona.Persona {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.persona
}

func (f *fakeAgent) Mode() mode.Mode {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.opMode == "" {
		return mode.ModeStandard
	}
	return f.opMode
}

func (f *fakeAgent) SetMode(m mode.Mode) {
	f.mu.Lock()
	f.opMode = m
	f.mu.Unlock()
}

func (f *fakeAgent) ReadOnly() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.readOnly
}

func (f *fakeAgent) SetReadOnly(v bool) {
	f.mu.Lock()
	f.readOnly = v
	f.mu.Unlock()
}

func (f *fakeAgent) emitDelta(t agent.TextDelta) {
	f.mu.Lock()
	cb := f.textDeltaCb
	f.mu.Unlock()
	if cb != nil {
		cb(t)
	}
}

func (f *fakeAgent) emitTool(e agent.ToolEvent) {
	f.mu.Lock()
	cb := f.toolStatusCb
	f.mu.Unlock()
	if cb != nil {
		cb(e)
	}
}

func (f *fakeAgent) confirm(ctx context.Context, req agent.ConfirmRequest) agent.ConfirmResponse {
	f.mu.Lock()
	cb := f.confirmCb
	f.mu.Unlock()
	if cb == nil {
		return agent.ConfirmResponse{Decision: agent.DecisionDeny}
	}
	return cb(ctx, req)
}

// startTestServer wires a Server onto an httptest.Server and returns a
// dialed client connection plus a cleanup function.
func startTestServer(t *testing.T, fa *fakeAgent) (*websocket.Conn, func()) {
	t.Helper()

	s := NewServer("127.0.0.1:0", fa, nil)
	// Tighten the production defaults so test failures surface in seconds,
	// not minutes. Going through NewServer keeps every other field — like
	// requestQueue — initialised in lockstep with prod.
	s.heartbeatInterval = 100 * time.Millisecond
	s.heartbeatTimeout = 2 * time.Second
	s.writeTimeout = 2 * time.Second

	ts := httptest.NewServer(http.HandlerFunc(s.handleWebSocket))
	url := "ws" + strings.TrimPrefix(ts.URL, "http")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		ts.Close()
		t.Fatalf("dial: %v", err)
	}

	cleanup := func() {
		c.Close(websocket.StatusNormalClosure, "")
		ts.Close()
	}

	// Drain the initial status frame so tests only see event-under-test traffic.
	if _, err := readFrame(ctx, c); err != nil {
		cleanup()
		t.Fatalf("read initial status: %v", err)
	}

	return c, cleanup
}

func readFrame(ctx context.Context, c *websocket.Conn) (map[string]any, error) {
	_, data, err := c.Read(ctx)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// readUntil keeps pulling frames and returns the first one whose type matches
// one of the wanted strings. Ping/phase/status frames are skipped by default.
func readUntil(t *testing.T, ctx context.Context, c *websocket.Conn, wanted ...string) map[string]any {
	t.Helper()
	for {
		frame, err := readFrame(ctx, c)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		typ, _ := frame["type"].(string)
		for _, w := range wanted {
			if typ == w {
				return frame
			}
		}
	}
}

// Compile-time check that *agent.Agent satisfies agentDriver.
var _ agentDriver = (*agent.Agent)(nil)

func TestTextDeltaFlowsToClient(t *testing.T) {
	fa := &fakeAgent{}
	fa.runFn = func(ctx context.Context, input string, f *fakeAgent) (string, error) {
		f.emitDelta(agent.TextDelta{Text: "hello "})
		f.emitDelta(agent.TextDelta{Text: "world"})
		return "hello world", nil
	}

	c, cleanup := startTestServer(t, fa)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := writeJSON(ctx, c, map[string]any{"type": "text", "content": "hi"}); err != nil {
		t.Fatalf("write: %v", err)
	}

	first := readUntil(t, ctx, c, "text_delta")
	if got, want := first["content"], "hello "; got != want {
		t.Errorf("first delta content = %q, want %q", got, want)
	}
	if first["turn_id"] == "" || first["turn_id"] == nil {
		t.Errorf("first delta missing turn_id: %v", first)
	}

	second := readUntil(t, ctx, c, "text_delta")
	if got, want := second["content"], "world"; got != want {
		t.Errorf("second delta content = %q, want %q", got, want)
	}

	resp := readUntil(t, ctx, c, "response")
	if got, want := resp["content"], "hello world"; got != want {
		t.Errorf("response content = %q, want %q", got, want)
	}
	if resp["turn_id"] != first["turn_id"] {
		t.Errorf("response turn_id %v != delta turn_id %v", resp["turn_id"], first["turn_id"])
	}
}

func TestToolStatusShape(t *testing.T) {
	fa := &fakeAgent{}
	fa.runFn = func(ctx context.Context, input string, f *fakeAgent) (string, error) {
		f.emitTool(agent.ToolEvent{
			Phase: "start",
			Name:  "rfid_read",
			Input: json.RawMessage(`{"mode":"lf"}`),
		})
		f.emitTool(agent.ToolEvent{
			Phase:    "finish",
			Name:     "rfid_read",
			Input:    json.RawMessage(`{"mode":"lf"}`),
			Duration: 123 * time.Millisecond,
			Output:   "UID=ABCD",
			Err:      false,
		})
		return "done", nil
	}

	c, cleanup := startTestServer(t, fa)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := writeJSON(ctx, c, map[string]any{"type": "text", "content": "read a card"}); err != nil {
		t.Fatalf("write: %v", err)
	}

	start := readUntil(t, ctx, c, "tool_status")
	if start["phase"] != "start" || start["name"] != "rfid_read" {
		t.Errorf("start frame = %v", start)
	}
	if start["input"] != `{"mode":"lf"}` {
		t.Errorf("start input = %v, want raw JSON passthrough", start["input"])
	}

	finish := readUntil(t, ctx, c, "tool_status")
	if finish["phase"] != "finish" {
		t.Errorf("finish phase = %v", finish["phase"])
	}
	if finish["output"] != "UID=ABCD" {
		t.Errorf("finish output = %v", finish["output"])
	}
	if dur, ok := finish["duration_ms"].(float64); !ok || dur != 123 {
		t.Errorf("finish duration_ms = %v (%T), want 123", finish["duration_ms"], finish["duration_ms"])
	}
	if finish["err"] != false {
		t.Errorf("finish err = %v, want false", finish["err"])
	}
}

func TestConfirmRoundTrip(t *testing.T) {
	fa := &fakeAgent{}
	decisionCh := make(chan agent.ConfirmResponse, 1)

	fa.runFn = func(ctx context.Context, input string, f *fakeAgent) (string, error) {
		r := f.confirm(ctx, agent.ConfirmRequest{
			Tool:  "subghz_transmit",
			Input: json.RawMessage(`{"file":"/x.sub"}`),
			Risk:  3, // Critical
		})
		decisionCh <- r
		return "decided", nil
	}

	c, cleanup := startTestServer(t, fa)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := writeJSON(ctx, c, map[string]any{"type": "text", "content": "transmit"}); err != nil {
		t.Fatalf("write: %v", err)
	}

	req := readUntil(t, ctx, c, "confirm_request")
	if req["tool"] != "subghz_transmit" {
		t.Errorf("tool = %v", req["tool"])
	}
	cid, _ := req["confirm_id"].(string)
	if cid == "" {
		t.Fatalf("confirm_id missing: %v", req)
	}

	if err := writeJSON(ctx, c, map[string]any{
		"type":       "confirm_response",
		"confirm_id": cid,
		"decision":   "approve",
	}); err != nil {
		t.Fatalf("write confirm_response: %v", err)
	}

	select {
	case r := <-decisionCh:
		if r.Decision != agent.DecisionApprove {
			t.Errorf("decision = %v, want DecisionApprove", r.Decision)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent never received decision")
	}

	// Drain remainder so writer goroutine flushes before cleanup.
	_ = readUntil(t, ctx, c, "response")
}

func TestResetCallsAgent(t *testing.T) {
	fa := &fakeAgent{}
	c, cleanup := startTestServer(t, fa)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := writeJSON(ctx, c, map[string]any{"type": "reset"}); err != nil {
		t.Fatalf("write: %v", err)
	}

	frame := readUntil(t, ctx, c, "status")
	if frame["content"] != "conversation reset" {
		t.Errorf("status content = %v", frame["content"])
	}

	fa.mu.Lock()
	calls := fa.resetCalls
	fa.mu.Unlock()
	if calls != 1 {
		t.Errorf("agent.Reset calls = %d, want 1", calls)
	}
}

func writeJSON(ctx context.Context, c *websocket.Conn, m map[string]any) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, data)
}

// TestIndexScriptOrder verifies the v0.9 redesign: the index serves a
// vanilla-JS app.js (no framework) as a deferred script with the correct
// link tags. The test replaces the old Alpine-ordering guard because the
// redesign removed Alpine entirely.
func TestIndexScriptOrder(t *testing.T) {
	html, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	body := string(html)

	if !strings.Contains(body, `src="app.js"`) {
		t.Fatal("index.html is missing a <script src=\"app.js\"> tag")
	}
	if !strings.Contains(body, "defer") {
		t.Fatal("app.js script tag must carry the defer attribute")
	}
	// Sanity: no Alpine CDN script in the redesigned UI.
	if strings.Contains(body, "alpinejs") {
		t.Fatal("index.html must not include Alpine CDN in the v0.9 redesign")
	}
}

// TestNoLiteralUndefinedInTemplates ensures the redesigned index.html (which
// uses DOM APIs rather than Alpine templates) contains no literal "undefined"
// strings that could appear as visible text in the UI. The old allow-list of
// 1 (for Alpine tool-output guards) no longer applies.
func TestNoLiteralUndefinedInTemplates(t *testing.T) {
	html, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	body := string(html)
	if count := strings.Count(body, "undefined"); count != 0 {
		t.Fatalf("index.html contains %d occurrences of \"undefined\" — "+
			"the redesigned markup uses static text only; no JS literals should leak into HTML.",
			count)
	}
}

// TestPanicInHandlerDoesNotCrashConnection verifies that obs.SafeGo wrapping
// prevents a panic inside a WS-dispatched goroutine from crashing the process
// or the connection. The first turn panics; the second turn succeeds, proving
// the WS connection is still alive.
func TestPanicInHandlerDoesNotCrashConnection(t *testing.T) {
	fa := &fakeAgent{}
	var panicOnce sync.Once
	fa.runFn = func(ctx context.Context, input string, f *fakeAgent) (string, error) {
		panicOnce.Do(func() { panic("intentional test panic in handleText") })
		return "still alive", nil
	}

	c, cleanup := startTestServer(t, fa)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First message triggers the panic; SafeGo recovers it.
	if err := writeJSON(ctx, c, map[string]any{"type": "text", "content": "panic now"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Allow the goroutine time to panic and recover before the next send.
	time.Sleep(150 * time.Millisecond)

	// Second message must succeed — connection must still be open.
	if err := writeJSON(ctx, c, map[string]any{"type": "text", "content": "still here?"}); err != nil {
		t.Fatalf("write after panic: %v", err)
	}
	resp := readUntil(t, ctx, c, "response")
	if resp["content"] != "still alive" {
		t.Errorf("response content = %v, want 'still alive'", resp["content"])
	}
}
