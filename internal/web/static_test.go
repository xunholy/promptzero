package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
)

// newStaticServer spins up a full httptest.Server with the embedded static FS
// wired in — identical to what Start() does minus the real listener.
func newStaticServer(t *testing.T, token string) *httptest.Server {
	t.Helper()
	s := &Server{
		agent:             &fakeAgent{},
		addr:              "127.0.0.1:0",
		conns:             make(map[*sessionConn]struct{}),
		confirms:          make(map[string]chan agent.ConfirmResponse),
		heartbeatInterval: 100 * time.Millisecond,
		heartbeatTimeout:  2 * time.Second,
		writeTimeout:      2 * time.Second,
		startedAt:         time.Now(),
		token:             token,
	}
	s.attachAgentCallbacks()

	mux := http.NewServeMux()
	s.registerAPIRoutes(mux)

	// Replicate the sub-FS logic from Start() so we can test without a real listener.
	subFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		t.Fatalf("fs.Sub static: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(subFS)))

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// TestStaticFilesContentTypes verifies that the three redesigned static assets
// are served with the expected MIME types and are non-empty.
func TestStaticFilesContentTypes(t *testing.T) {
	ts := newStaticServer(t, "") // open mode — no token required

	cases := []struct {
		path   string
		wantCT string
	}{
		{"/", "text/html"},
		{"/app.css", "text/css"},
		{"/app.js", "text/javascript"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.path, func(t *testing.T) {
			resp, err := ts.Client().Get(ts.URL + c.path)
			if err != nil {
				t.Fatalf("GET %s: %v", c.path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}

			ct := resp.Header.Get("Content-Type")
			if ct == "" {
				t.Errorf("Content-Type header missing for %s", c.path)
			}
			// Content-Type may include charset suffix; check prefix only.
			want := c.wantCT
			if len(ct) < len(want) || ct[:len(want)] != want {
				t.Errorf("Content-Type = %q, want prefix %q", ct, want)
			}

			if resp.ContentLength == 0 {
				t.Errorf("%s body is empty", c.path)
			}
		})
	}
}

// TestStaticFilesOpenWithoutToken confirms static assets are NOT gated behind
// the bearer token — only /api/* and /ws require auth.
func TestStaticFilesOpenWithoutToken(t *testing.T) {
	ts := newStaticServer(t, "hunter2") // token set, but static should still serve

	for _, path := range []string{"/", "/app.css", "/app.js"} {
		resp, err := ts.Client().Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d with token configured, want 200 (static files are public)", path, resp.StatusCode)
		}
	}
}
