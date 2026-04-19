package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/persona"
)

// newAuthTestServer is the shared fixture for auth tests. It wires up the
// same route table Start() uses (minus the static FS + metrics), with a
// caller-supplied token. Returns the Server, the httptest.Server, and the
// base URL for the test client.
func newAuthTestServer(t *testing.T, token string, origins []string) (*Server, *httptest.Server) {
	t.Helper()
	s := &Server{
		agent:             &fakeAgent{},
		addr:              "127.0.0.1:0",
		conns:             make(map[*sessionConn]struct{}),
		confirms:          make(map[string]chan agent.Decision),
		heartbeatInterval: 100 * time.Millisecond,
		heartbeatTimeout:  2 * time.Second,
		writeTimeout:      2 * time.Second,
		startedAt:         time.Now(),
	}
	s.attachAgentCallbacks()
	s.SetAuthToken(token)
	s.SetCORSOrigins(origins)
	s.SetPersonaRegistry(persona.NewRegistry())
	mux := http.NewServeMux()
	s.registerAPIRoutes(mux)
	mux.HandleFunc("/ws", s.handleWebSocket)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return s, ts
}

func TestBearerFromHeader(t *testing.T) {
	cases := map[string]string{
		"":                 "",
		"Bearer":           "",
		"Bearer ":          "",
		"Bearer abc":       "abc",
		"Bearer  abc  ":    "abc",
		"bearer abc":       "",   // scheme is case-sensitive to force a real Bearer
		"Basic Zm9vOmJhcg": "",
	}
	for in, want := range cases {
		if got := bearerFromHeader(in); got != want {
			t.Errorf("bearerFromHeader(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckAuth_EmptyTokenIsPassthrough(t *testing.T) {
	s := &Server{token: ""}
	if !s.checkAuth(nil, "") {
		t.Fatal("empty server token should allow empty supplied token")
	}
	if !s.checkAuth(nil, "anything") {
		t.Fatal("empty server token should allow any supplied token")
	}
}

func TestCheckAuth_ConstantTimeMatch(t *testing.T) {
	s := &Server{token: "s3cret"}
	if !s.checkAuth(nil, "s3cret") {
		t.Fatal("matching token should pass")
	}
	if s.checkAuth(nil, "wrong") {
		t.Fatal("non-matching token should fail")
	}
	if s.checkAuth(nil, "") {
		t.Fatal("empty supplied should fail when token required")
	}
}

func TestAuthInfoEndpoint_OpenAndReportsRequired(t *testing.T) {
	_, ts := newAuthTestServer(t, "supersecret", nil)

	resp, err := ts.Client().Get(ts.URL + "/api/auth")
	if err != nil {
		t.Fatalf("GET /api/auth: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body map[string]bool
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body["required"] {
		t.Fatal("required should be true when token configured")
	}
}

func TestAuthInfoEndpoint_ReportsFalseWhenNoToken(t *testing.T) {
	_, ts := newAuthTestServer(t, "", nil)
	resp, err := ts.Client().Get(ts.URL + "/api/auth")
	if err != nil {
		t.Fatalf("GET /api/auth: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]bool
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["required"] {
		t.Fatal("required should be false when token empty")
	}
}

func TestAPIEndpoint_401WithoutBearer(t *testing.T) {
	_, ts := newAuthTestServer(t, "supersecret", nil)
	resp, err := ts.Client().Get(ts.URL + "/api/personas")
	if err != nil {
		t.Fatalf("GET /api/personas: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAPIEndpoint_401WithWrongBearer(t *testing.T) {
	_, ts := newAuthTestServer(t, "supersecret", nil)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/personas", nil)
	req.Header.Set("Authorization", "Bearer nope")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAPIEndpoint_200WithCorrectBearer(t *testing.T) {
	_, ts := newAuthTestServer(t, "supersecret", nil)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/personas", nil)
	req.Header.Set("Authorization", "Bearer supersecret")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestAPIEndpoint_OpenWhenTokenUnset(t *testing.T) {
	_, ts := newAuthTestServer(t, "", nil)
	resp, err := ts.Client().Get(ts.URL + "/api/personas")
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (open when token empty)", resp.StatusCode)
	}
}

func TestWebSocket_401WithoutToken(t *testing.T) {
	_, ts := newAuthTestServer(t, "supersecret", nil)
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// coder/websocket.Dial returns (nil, *http.Response, err) when the
	// server rejects the upgrade — we deliberately want both the error
	// and the HTTP response so we can assert the status code.
	_, resp, err := websocket.Dial(ctx, wsURL, nil)
	if err == nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		t.Fatal("dial should fail without token")
	}
	if resp == nil {
		t.Fatal("expected non-nil HTTP response alongside upgrade error")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("handshake status = %d, want 401", resp.StatusCode)
	}
}

func TestWebSocket_OKWithTokenQueryParam(t *testing.T) {
	_, ts := newAuthTestServer(t, "supersecret", nil)
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws?token=supersecret"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial with correct token: %v", err)
	}
	c.Close(websocket.StatusNormalClosure, "")
}

func TestEffectiveOriginPatterns_EmptyIsSameOriginOnly(t *testing.T) {
	s := &Server{corsOrigins: nil}
	if got := s.effectiveOriginPatterns(); got != nil {
		t.Fatalf("nil corsOrigins should map to nil patterns, got %v", got)
	}
}

func TestEffectiveOriginPatterns_TrimsBlanks(t *testing.T) {
	s := &Server{corsOrigins: []string{"https://a.lan", "", "  https://b.lan  "}}
	got := s.effectiveOriginPatterns()
	want := []string{"https://a.lan", "https://b.lan"}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("patterns[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:8080": "127.0.0.1",
		"0.0.0.0:8080":   "0.0.0.0",
		":8080":          "",
		"localhost:80":   "localhost",
		"not-a-host":     "",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
