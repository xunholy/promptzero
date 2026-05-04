package generate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/provider"
)

// TestLooksLikeRefusal_Positive locks the canonical refusal openers we
// detect. Adding a new refusal pattern should add a case here.
func TestLooksLikeRefusal_Positive(t *testing.T) {
	cases := []string{
		"I can't help with that request.",
		"I cannot assist with creating malware.",
		"I won't help with this kind of attack.",
		"I'm not able to help with that.",
		"I am unable to provide that.",
		"I cannot provide instructions for credential theft.",
		"I can't create that payload.",
		"I won't generate that content.",
		"I'm unable to write code that does that.",
		"I'd recommend reaching out to a security professional.",
		// Lowercase + leading whitespace must still match.
		"   i cannot help with that.",
	}
	for _, c := range cases {
		if !looksLikeRefusal(c) {
			t.Errorf("expected refusal: %q", c)
		}
	}
}

// TestLooksLikeRefusal_Negative locks responses we MUST NOT
// false-positive on — caveated answers, normal completions, even
// medium-length explanations that begin with "I cannot guarantee".
func TestLooksLikeRefusal_Negative(t *testing.T) {
	cases := []string{
		"",
		"<!DOCTYPE html><html><body>...",
		"DELAY 500\nGUI r\nSTRING cmd",
		"Here's the payload you requested:",
		"I cannot guarantee compatibility across all firmware versions, but here's a portal...", // > 300 chars when extended; skipped on length too
		strings.Repeat("I can't help. ", 50),                                                    // long enough to be a caveated explanation, not a pure refusal
	}
	for _, c := range cases {
		if looksLikeRefusal(c) {
			t.Errorf("did NOT expect refusal: %q (len=%d)", c, len(c))
		}
	}
}

// TestLooksLikeRefusal_LongResponseNotRefusal verifies the length
// floor: a response that opens with a refusal phrase but goes on for
// more than refusalMaxLen is treated as a genuine answer with a
// caveat, not a refusal.
func TestLooksLikeRefusal_LongResponseNotRefusal(t *testing.T) {
	long := "I cannot guarantee that this works on every Flipper firmware variant, " +
		"but here's a starting point. The default subghz preset is FuriHalSubGhzPresetOok650Async " +
		"and a Princeton-protocol key file has Filetype, Version, Frequency, Preset, Protocol, Bit, " +
		"Key, TE, and Repeat fields. Below is a complete .sub file for a 433.92 MHz Princeton key..."
	if looksLikeRefusal(long) {
		t.Fatalf("long response with caveat opener was treated as refusal")
	}
}

// stub provider for completeWithFallback testing.
type fakeProvider struct {
	name    string
	resp    string
	err     error
	calls   int
	gotSys  string
	gotMsgs []provider.Message
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) Complete(_ context.Context, sys string, msgs []provider.Message) (*provider.Response, error) {
	f.calls++
	f.gotSys = sys
	f.gotMsgs = msgs
	if f.err != nil {
		return nil, f.err
	}
	return &provider.Response{Content: f.resp}, nil
}

// TestCompleteWithFallback_NoRefusal_PrimaryServes verifies that when
// the primary returns a normal response, the fallback is NOT consulted
// and the metadata reports no fallback was used.
func TestCompleteWithFallback_NoRefusal_PrimaryServes(t *testing.T) {
	primary := &fakeProvider{name: "claude", resp: "DELAY 500\nGUI r"}
	fb := &fakeProvider{name: "ollama", resp: "should-not-be-called"}
	g := New(primary, nil)
	g.SetFallback(fb)

	resp, fbName, err := g.completeWithFallback(context.Background(), "sys", []provider.Message{{Role: "user", Content: "p"}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if fbName != "" {
		t.Errorf("fallback name should be empty when primary served; got %q", fbName)
	}
	if resp.Content != "DELAY 500\nGUI r" {
		t.Errorf("response content = %q", resp.Content)
	}
	if primary.calls != 1 {
		t.Errorf("primary called %d times, want 1", primary.calls)
	}
	if fb.calls != 0 {
		t.Errorf("fallback called %d times, want 0", fb.calls)
	}
}

// TestCompleteWithFallback_RefusalRoutesToFallback locks the v0.20.0
// fallback contract: primary refuses → fallback is consulted → its
// response is returned and metadata names the fallback so the
// operator sees what served the request.
func TestCompleteWithFallback_RefusalRoutesToFallback(t *testing.T) {
	primary := &fakeProvider{name: "claude", resp: "I can't help with that request."}
	fb := &fakeProvider{name: "ollama/llama3.1", resp: "DELAY 500\nGUI r\nSTRING cmd"}
	g := New(primary, nil)
	g.SetFallback(fb)

	resp, fbName, err := g.completeWithFallback(context.Background(), "sys", []provider.Message{{Role: "user", Content: "p"}}, "badusb")
	if err != nil {
		t.Fatal(err)
	}
	if fbName != "ollama/llama3.1" {
		t.Errorf("fallback name = %q, want %q", fbName, "ollama/llama3.1")
	}
	if resp.Content != "DELAY 500\nGUI r\nSTRING cmd" {
		t.Errorf("response content = %q (expected fallback's content)", resp.Content)
	}
	if primary.calls != 1 || fb.calls != 1 {
		t.Errorf("call counts: primary=%d fb=%d, want 1/1", primary.calls, fb.calls)
	}
}

// TestCompleteWithFallback_NoFallbackWired_RefusalPropagates ensures
// that without a fallback, behaviour is identical to a direct
// Complete call — the refusal text passes through to the caller.
// Pre-v0.20.0 behaviour preserved for callers that haven't opted in.
func TestCompleteWithFallback_NoFallbackWired_RefusalPropagates(t *testing.T) {
	primary := &fakeProvider{name: "claude", resp: "I cannot help with that."}
	g := New(primary, nil)
	// no SetFallback

	resp, fbName, err := g.completeWithFallback(context.Background(), "sys", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if fbName != "" {
		t.Errorf("no fallback wired; fbName should be empty")
	}
	if resp.Content != "I cannot help with that." {
		t.Errorf("refusal text should propagate; got %q", resp.Content)
	}
}

// TestCompleteWithFallback_FallbackErrorReturnsRefusal locks the
// graceful-degradation rule: when the fallback errors, return the
// original refusal rather than the fallback error. The operator sees
// the refusal (something useful) instead of "your fallback Ollama
// instance is offline" (something they can't act on mid-turn).
func TestCompleteWithFallback_FallbackErrorReturnsRefusal(t *testing.T) {
	primary := &fakeProvider{name: "claude", resp: "I can't help with that."}
	fb := &fakeProvider{name: "ollama", err: errors.New("connection refused")}
	g := New(primary, nil)
	g.SetFallback(fb)

	resp, fbName, err := g.completeWithFallback(context.Background(), "sys", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if fbName != "" {
		t.Errorf("fallback failed; fbName should be empty (no successful fallback)")
	}
	if resp.Content != "I can't help with that." {
		t.Errorf("expected original refusal to propagate when fallback errors; got %q", resp.Content)
	}
}

// TestCompleteWithFallback_PrimaryError_NotRefusalDetection ensures
// that genuine API errors (network, timeout, 5xx) propagate as errors
// rather than triggering the refusal-detection retry path. Retrying a
// 503 through the fallback would mask the real issue.
func TestCompleteWithFallback_PrimaryError_NotRefusalDetection(t *testing.T) {
	primary := &fakeProvider{name: "claude", err: errors.New("anthropic 503 unavailable")}
	fb := &fakeProvider{name: "ollama", resp: "fallback-content"}
	g := New(primary, nil)
	g.SetFallback(fb)

	_, _, err := g.completeWithFallback(context.Background(), "sys", nil, "test")
	if err == nil {
		t.Fatal("API errors must propagate, not trigger fallback")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should be the original API error; got %v", err)
	}
	if fb.calls != 0 {
		t.Errorf("fallback should NOT be called on API errors; got %d calls", fb.calls)
	}
}
