package mcp

import (
	"testing"

	"github.com/xunholy/promptzero/internal/bruce"
	"github.com/xunholy/promptzero/internal/buspirate"
	"github.com/xunholy/promptzero/internal/faultier"
	"github.com/xunholy/promptzero/internal/testmocks"
)

// SetBruce / SetFaultier / SetBusPirate / PromptNames / ResourceNames
// were all at 0% statement coverage — quiet drift in any of them would
// silently strip devboard wiring from the MCP server or hide registered
// prompt / resource lookups from clients introspecting the server.

func TestServer_SetBruce_StoresClient(t *testing.T) {
	flip := testmocks.NewMockFlipper(t)
	s := NewServer(flip, nil)
	if s.bruce != nil {
		t.Fatal("fresh server: s.bruce should start nil")
	}

	port := bruce.NewMockPort()
	c := bruce.NewWithPort(port)
	s.SetBruce(c)
	if s.bruce != c {
		t.Errorf("after SetBruce: s.bruce = %p; want %p", s.bruce, c)
	}

	// Passing nil clears the wiring (e.g. after a session-end teardown).
	s.SetBruce(nil)
	if s.bruce != nil {
		t.Error("after SetBruce(nil): s.bruce should be nil again")
	}
}

func TestServer_SetFaultier_StoresClient(t *testing.T) {
	flip := testmocks.NewMockFlipper(t)
	s := NewServer(flip, nil)
	if s.faultier != nil {
		t.Fatal("fresh server: s.faultier should start nil")
	}

	c, _ := faultier.NewMockClient()
	s.SetFaultier(c)
	if s.faultier != c {
		t.Errorf("after SetFaultier: s.faultier = %p; want %p", s.faultier, c)
	}
}

func TestServer_SetBusPirate_StoresClient(t *testing.T) {
	flip := testmocks.NewMockFlipper(t)
	s := NewServer(flip, nil)
	if s.busPirate != nil {
		t.Fatal("fresh server: s.busPirate should start nil")
	}

	port := buspirate.NewMockPort()
	c := buspirate.NewWithPort(port)
	s.SetBusPirate(c)
	if s.busPirate != c {
		t.Errorf("after SetBusPirate: s.busPirate = %p; want %p", s.busPirate, c)
	}
}

func TestServer_PromptNames_ReturnsRegisteredPrompts(t *testing.T) {
	flip := testmocks.NewMockFlipper(t)
	s := NewServer(flip, nil)

	got := s.PromptNames()
	if len(got) == 0 {
		t.Fatal("PromptNames returned empty; persona prompts should auto-register")
	}

	// PromptNames must return a copy — callers mutating the slice should
	// not corrupt the server's internal list.
	if len(got) > 0 {
		original := got[0]
		got[0] = "__sentinel__"
		if s.PromptNames()[0] == "__sentinel__" {
			t.Error("PromptNames returns the internal slice (mutation leaked back to server)")
		}
		got[0] = original
	}
}

func TestServer_ResourceNames_ReturnsRegisteredResources(t *testing.T) {
	flip := testmocks.NewMockFlipper(t)
	s := NewServer(flip, nil)

	got := s.ResourceNames()
	if len(got) == 0 {
		t.Fatal("ResourceNames returned empty; wordlist resources should auto-register")
	}

	// Wordlist resources are documented in the package comment: at
	// least the two common.txt and passwords.txt URIs should be present.
	found := map[string]bool{}
	for _, r := range got {
		found[r] = true
	}
	for _, want := range []string{
		"promptzero://wordlists/common.txt",
		"promptzero://wordlists/passwords.txt",
	} {
		if !found[want] {
			t.Errorf("ResourceNames missing %q; got %v", want, got)
		}
	}

	// ResourceNames must return a copy.
	got[0] = "__sentinel__"
	if s.ResourceNames()[0] == "__sentinel__" {
		t.Error("ResourceNames returns the internal slice (mutation leaked)")
	}
}
