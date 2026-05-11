package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestCORS_AllowedOrigin_GET_EchoesACAO pins the load-bearing piece of
// the WebConfig.CORSOrigins docstring's "call /api cross-origin"
// promise: a GET from an allow-listed origin must come back with
// Access-Control-Allow-Origin echoing that origin so the browser
// exposes the response body to the JS caller. Pre-fix the server
// emitted no CORS headers at all and the browser blocked the response.
func TestCORS_AllowedOrigin_GET_EchoesACAO(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	s.corsOrigins = []string{"https://cockpit.lan"}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/auth", nil)
	req.Header.Set("Origin", "https://cockpit.lan")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://cockpit.lan" {
		t.Errorf("ACAO = %q, want %q", got, "https://cockpit.lan")
	}
	if !strings.Contains(resp.Header.Get("Vary"), "Origin") {
		t.Errorf("Vary header missing Origin: %q", resp.Header.Get("Vary"))
	}
	if resp.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("Allow-Credentials = %q, want true", resp.Header.Get("Access-Control-Allow-Credentials"))
	}
}

// TestCORS_Preflight_AllowedOrigin asserts the OPTIONS preflight that
// browsers send before a credentialed cross-origin call returns the
// full set of headers browsers require. Pre-fix the mux returned 405
// for OPTIONS on method-routed paths (e.g. `PUT /api/budget`) and the
// preflight failed silently.
func TestCORS_Preflight_AllowedOrigin(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	s.corsOrigins = []string{"https://cockpit.lan"}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodOptions, ts.URL+"/api/budget", nil)
	req.Header.Set("Origin", "https://cockpit.lan")
	req.Header.Set("Access-Control-Request-Method", "PUT")
	req.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("OPTIONS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://cockpit.lan" {
		t.Errorf("ACAO = %q, want %q", got, "https://cockpit.lan")
	}
	for _, want := range []string{"GET", "POST", "PUT", "DELETE"} {
		if !strings.Contains(resp.Header.Get("Access-Control-Allow-Methods"), want) {
			t.Errorf("Allow-Methods %q missing %q", resp.Header.Get("Access-Control-Allow-Methods"), want)
		}
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Access-Control-Allow-Headers")), "authorization") {
		t.Errorf("Allow-Headers missing authorization: %q", resp.Header.Get("Access-Control-Allow-Headers"))
	}
	if resp.Header.Get("Access-Control-Max-Age") == "" {
		t.Errorf("Max-Age missing")
	}
}

// TestCORS_DisallowedOrigin_NoACAO covers the negative case: a request
// from an origin NOT on the allow-list passes through the handler
// (curl-style integrations always work server-side) but receives no
// Access-Control-Allow-Origin, so a browser would block the response
// from being read by JS. This is the "same-origin only" default.
func TestCORS_DisallowedOrigin_NoACAO(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	s.corsOrigins = []string{"https://cockpit.lan"}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/auth", nil)
	req.Header.Set("Origin", "https://evil.example")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO = %q, want empty (disallowed origin)", got)
	}
	// The handler still runs server-side — only the browser blocks
	// the response read. Server-side responses are governed by the
	// bearer-token check, not CORS.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (server-side dispatch unchanged)", resp.StatusCode)
	}
}

// TestCORS_AllowAnyOrigin_EchoesOriginNotStar asserts that with
// allowAnyOrigin=true the middleware echoes the SPECIFIC Origin
// header back, never the literal "*". The CORS spec forbids
// ACAO: * with Allow-Credentials: true; browsers reject that combo.
func TestCORS_AllowAnyOrigin_EchoesOriginNotStar(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	s.allowAnyOrigin = true

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/auth", nil)
	req.Header.Set("Origin", "https://anywhere.example")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	got := resp.Header.Get("Access-Control-Allow-Origin")
	if got == "*" {
		t.Errorf(`ACAO = "*"; CORS spec forbids "*" with Allow-Credentials:true`)
	}
	if got != "https://anywhere.example" {
		t.Errorf("ACAO = %q, want %q", got, "https://anywhere.example")
	}
}

// TestCORS_NoOriginHeader_NoACAO covers same-origin / curl-style
// callers: no Origin header at all means no CORS headers in the
// response. Existing same-origin tests rely on this — adding the
// middleware must not perturb them.
func TestCORS_NoOriginHeader_NoACAO(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	s.corsOrigins = []string{"https://cockpit.lan"}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/auth", nil)
	// No Origin header.
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO = %q, want empty (no Origin header)", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestCORS_NonAPI_PathUnaffected ensures the middleware only touches
// /api/* — the static UI and / itself must be free of CORS shaping
// so the served HTML/JS bundle keeps its current cache headers
// intact for same-origin loads.
func TestCORS_NonAPI_PathUnaffected(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	s.corsOrigins = []string{"https://cockpit.lan"}

	// apiServer's test mux doesn't register a static handler, so
	// hitting "/" returns 404 from the mux. The point is the
	// middleware doesn't add CORS headers to non-/api paths.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/", nil)
	req.Header.Set("Origin", "https://cockpit.lan")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO = %q on non-/api path; middleware should only touch /api/*", got)
	}
}
