// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"strings"
	"testing"
)

// TestApplyLoopbackDefault pins the local-first bind default: an empty
// host is rewritten to loopback, while an explicit non-loopback host is
// respected (the operator opted into network exposure). A regression
// here would silently bind a fresh install to all interfaces.
func TestApplyLoopbackDefault(t *testing.T) {
	cases := []struct{ in, want string }{
		{":8080", "127.0.0.1:8080"},          // empty host -> loopback
		{"127.0.0.1:8080", "127.0.0.1:8080"}, // explicit loopback unchanged
		{"localhost:8080", "localhost:8080"}, // localhost respected as-is
		{"0.0.0.0:8080", "0.0.0.0:8080"},     // explicit public respected
		{"192.168.1.5:9000", "192.168.1.5:9000"},
		{"[::1]:8080", "[::1]:8080"},           // IPv6 loopback unchanged
		{"garbage-no-port", "garbage-no-port"}, // unparseable -> returned as-is
	}
	for _, c := range cases {
		if got := applyLoopbackDefault(c.in); got != c.want {
			t.Errorf("applyLoopbackDefault(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestIsLoopback pins the loopback classification used by both the bind
// default and the no-token bind refusal.
func TestIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"localhost":   true,
		"127.0.0.1":   true,
		"127.0.0.2":   true, // entire 127/8 is loopback
		"::1":         true,
		"0.0.0.0":     false,
		"192.168.1.1": false,
		"example.com": false,
		"":            false,
	}
	for host, want := range cases {
		if got := isLoopback(host); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestStart_RefusesNonLoopbackWithoutToken is the safety-critical
// fail-closed guard: a non-loopback bind with no auth token and the
// default allow_unauthed_public=false must be refused before any socket
// is opened. This is the gate that stops a misconfigured public bind
// from exposing every /api and /ws unauthenticated; the test exists so a
// future change that flips the default or drops the check fails CI.
func TestStart_RefusesNonLoopbackWithoutToken(t *testing.T) {
	s := NewServer("0.0.0.0:0", &fakeAgent{}, nil)
	// Defaults: token == "" and allowUnauthedPublic == false.
	err := s.Start(context.Background())
	if err == nil {
		t.Fatal("Start on 0.0.0.0 with no token returned nil; expected a fail-closed refusal")
	}
	if !strings.Contains(err.Error(), "refusing to bind") {
		t.Errorf("Start error = %q; want it to mention refusing to bind", err)
	}
}
