//go:build linux

package web

import (
	"net/http"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// ---------------------------------------------------------------------------
// POST /api/input/send — no flipper
// ---------------------------------------------------------------------------

func TestInputSendNoFlipper(t *testing.T) {
	s, ts := apiServer(t, &fakeAgent{})
	_ = s
	code, raw := postJSON(t, ts, "/api/input/send", map[string]string{
		"button":     "ok",
		"event_type": "short",
	})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", code, raw)
	}
}

// ---------------------------------------------------------------------------
// POST /api/input/send — invalid button / event_type
// ---------------------------------------------------------------------------

func TestInputSendInvalidButton(t *testing.T) {
	_, ts, _ := fsServer(t)
	code, _ := postJSON(t, ts, "/api/input/send", map[string]string{
		"button":     "diagonal",
		"event_type": "short",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for invalid button", code)
	}
}

func TestInputSendInvalidEventType(t *testing.T) {
	_, ts, _ := fsServer(t)
	code, _ := postJSON(t, ts, "/api/input/send", map[string]string{
		"button":     "ok",
		"event_type": "double_tap",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for invalid event_type", code)
	}
}

// ---------------------------------------------------------------------------
// POST /api/input/send — happy path: all valid button × event_type combos
// ---------------------------------------------------------------------------

func TestInputSendHappyPath(t *testing.T) {
	cases := []struct {
		button    string
		eventType string
	}{
		{"up", "press"},
		{"down", "release"},
		{"left", "short"},
		{"right", "long"},
		{"ok", "short"},
		{"back", "short"},
	}
	for _, tc := range cases {
		t.Run(tc.button+"/"+tc.eventType, func(t *testing.T) {
			_, ts, _ := fsServer(t,
				mock.WithHandler("input", func(args []string) string {
					return ""
				}),
			)
			code, raw := postJSON(t, ts, "/api/input/send", map[string]string{
				"button":     tc.button,
				"event_type": tc.eventType,
			})
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", code, raw)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// POST /api/input/send — empty body
// ---------------------------------------------------------------------------

func TestInputSendEmptyBody(t *testing.T) {
	_, ts, _ := fsServer(t)
	code, _ := postJSON(t, ts, "/api/input/send", nil)
	// Empty body decodes to zero values — button "" is invalid.
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for empty body", code)
	}
}
