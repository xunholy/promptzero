package generate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/provider"
)

// TestCleanOutput_StripsLanguageFence locks the most common LLM
// wrapping: "```html\n<...>\n```". cleanOutput is the gate that keeps
// markdown contamination out of every deployed payload, so this is the
// shape it must handle correctly.
func TestCleanOutput_StripsLanguageFence(t *testing.T) {
	in := "```html\n<!DOCTYPE html><body>x</body>\n```"
	got := cleanOutput(in, "html")
	want := "<!DOCTYPE html><body>x</body>"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestCleanOutput_StripsBareFence covers ```...``` without a language
// hint.
func TestCleanOutput_StripsBareFence(t *testing.T) {
	in := "```\nDELAY 100\nGUI r\n```"
	got := cleanOutput(in, "")
	want := "DELAY 100\nGUI r"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestCleanOutput_NoFencePassesThrough confirms that already-clean
// input is returned unchanged (modulo trim).
func TestCleanOutput_NoFencePassesThrough(t *testing.T) {
	in := "  GUI r\nDELAY 50  "
	got := cleanOutput(in, "")
	want := "GUI r\nDELAY 50"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestCleanOutput_MismatchedFencesKeepText guards the "only opening
// fence found" case: cleanOutput should still return the body content
// after the opening fence, not corrupt it.
func TestCleanOutput_MismatchedFencesKeepText(t *testing.T) {
	in := "```html\nDELAY 100"
	got := cleanOutput(in, "html")
	want := "DELAY 100"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestCleanOutput_CaseInsensitiveFenceLanguage exercises the lowercase
// normalisation path — operators paste outputs from various LLMs that
// emit "```HTML" or "```Html".
func TestCleanOutput_CaseInsensitiveFenceLanguage(t *testing.T) {
	in := "```HTML\n<body>x</body>\n```"
	got := cleanOutput(in, "html")
	want := "<body>x</body>"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestCapSize_TruncatesAboveMax ensures the bytes-cap is enforced — a
// runaway LLM should not be able to write a multi-MB BadUSB script.
func TestCapSize_TruncatesAboveMax(t *testing.T) {
	got := capSize(strings.Repeat("a", 100), 10)
	if len(got) != 10 {
		t.Errorf("len(got) = %d, want 10", len(got))
	}
}

func TestCapSize_LeavesShortAlone(t *testing.T) {
	got := capSize("short", 100)
	if got != "short" {
		t.Errorf("got %q, want unchanged", got)
	}
}

func TestTruncate_AppendsEllipsisOverThreshold(t *testing.T) {
	got := truncate("abcdefghij", 5)
	want := "abcde..."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTruncate_LeavesShortAlone(t *testing.T) {
	got := truncate("xyz", 10)
	if got != "xyz" {
		t.Errorf("got %q, want unchanged", got)
	}
}

// TestDefaultPath_KnownTypes locks every type the deploy step knows
// about. If anyone changes one of these paths, downstream tooling
// (wrappers, docs, MCP advertisements) must be updated together.
func TestDefaultPath_KnownTypes(t *testing.T) {
	cases := map[string]string{
		"evil_portal": "/ext/apps_data/evil_portal/index.html",
		"badusb":      "/ext/badusb/generated_payload.txt",
		"subghz":      "/ext/subghz/generated_signal.sub",
		"ir":          "/ext/infrared/generated_remote.ir",
		"nfc":         "/ext/nfc/generated_tag.nfc",
	}
	for typ, want := range cases {
		if got := defaultPath(typ); got != want {
			t.Errorf("defaultPath(%q) = %q, want %q", typ, got, want)
		}
	}
}

// TestDefaultPath_UnknownTypeFallback verifies the fallback never
// returns an empty path — that would let a Deploy call hit the
// Flipper's storage root.
func TestDefaultPath_UnknownTypeFallback(t *testing.T) {
	got := defaultPath("ZZ")
	if got == "" || !strings.HasPrefix(got, "/ext/") {
		t.Errorf("defaultPath fallback %q must start with /ext/ to scope writes", got)
	}
}

// stubProvider returns a fixed Response and records the args it was
// called with.
type stubProvider struct {
	resp      *provider.Response
	err       error
	gotSys    string
	gotMsgs   []provider.Message
	callCount int
}

func (s *stubProvider) Name() string { return "stub" }
func (s *stubProvider) Complete(_ context.Context, sys string, msgs []provider.Message) (*provider.Response, error) {
	s.callCount++
	s.gotSys = sys
	s.gotMsgs = msgs
	return s.resp, s.err
}

// TestEvilPortal_StripsFencesFromLLMOutput verifies the cleanOutput
// pipe is wired into EvilPortal: a fenced response from the LLM is
// unwrapped before being returned to the caller. Skips the deploy
// path (Flipper is nil — Deploy is a separate call).
func TestEvilPortal_StripsFencesFromLLMOutput(t *testing.T) {
	llm := &stubProvider{
		resp: &provider.Response{Content: "```html\n<!DOCTYPE html><body>portal</body>\n```"},
	}
	g := New(llm, nil)

	got, err := g.EvilPortal(context.Background(), "starbucks")
	if err != nil {
		t.Fatalf("EvilPortal: %v", err)
	}

	if got.Type != "evil_portal" {
		t.Errorf("Type = %q, want evil_portal", got.Type)
	}
	if strings.Contains(got.Content, "```") {
		t.Errorf("Content still has markdown fence: %q", got.Content)
	}
	if !strings.Contains(got.Content, "<body>portal</body>") {
		t.Errorf("Content lost semantic body: %q", got.Content)
	}
	if got.Deployed {
		t.Errorf("Deployed should be false until Deploy is called")
	}
	if llm.callCount != 1 {
		t.Errorf("LLM called %d times, want 1", llm.callCount)
	}
}

// TestEvilPortal_CapsAt20kBytes guards against a runaway LLM producing
// a multi-MB HTML payload that would overflow the captive-portal
// memory budget.
func TestEvilPortal_CapsAt20kBytes(t *testing.T) {
	huge := strings.Repeat("x", 50_000)
	llm := &stubProvider{resp: &provider.Response{Content: huge}}
	g := New(llm, nil)

	got, err := g.EvilPortal(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Content) > 20_000 {
		t.Errorf("len = %d, want <= 20000", len(got.Content))
	}
}

// TestEvilPortal_LLMErrorBubblesUp ensures the error path doesn't
// silently produce a zero-content Result. The caller must learn the
// generation failed.
func TestEvilPortal_LLMErrorBubblesUp(t *testing.T) {
	llm := &stubProvider{err: errors.New("upstream gone")}
	g := New(llm, nil)

	_, err := g.EvilPortal(context.Background(), "test")
	if err == nil {
		t.Fatal("LLM error must propagate from EvilPortal")
	}
	if !strings.Contains(err.Error(), "upstream gone") {
		t.Errorf("err = %v, want wrapped 'upstream gone'", err)
	}
}

// TestBadUSB_DefaultsToWindowsTarget locks the default-OS contract.
func TestBadUSB_DefaultsToWindowsTarget(t *testing.T) {
	llm := &stubProvider{resp: &provider.Response{Content: "DELAY 100\nSTRING hi"}}
	g := New(llm, nil)

	if _, err := g.BadUSB(context.Background(), "open run dialog", ""); err != nil {
		t.Fatal(err)
	}

	// Inspect the prompt sent to the LLM — it should have asked for
	// windows when no target was supplied.
	if len(llm.gotMsgs) != 1 {
		t.Fatalf("LLM should be called with one user message, got %d", len(llm.gotMsgs))
	}
	if !strings.Contains(strings.ToLower(llm.gotMsgs[0].Content), "windows") {
		t.Errorf("prompt should mention windows when targetOS is empty; got: %s", llm.gotMsgs[0].Content)
	}
}

// TestBadUSB_CapsAt64KBytes — runaway script protection.
func TestBadUSB_CapsAt64KBytes(t *testing.T) {
	huge := strings.Repeat("a", 100_000)
	llm := &stubProvider{resp: &provider.Response{Content: huge}}
	g := New(llm, nil)

	got, err := g.BadUSB(context.Background(), "test", "linux")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Content) > 65_536 {
		t.Errorf("len = %d, want <= 65536", len(got.Content))
	}
}

// TestPreviewIsBoundedAcrossGenerators confirms the Preview field
// stays small regardless of Content length — agents/UIs use Preview
// for short summaries and shouldn't have to re-truncate.
func TestPreviewIsBoundedAcrossGenerators(t *testing.T) {
	huge := strings.Repeat("x", 10_000)
	llm := &stubProvider{resp: &provider.Response{Content: huge}}
	g := New(llm, nil)

	r, err := g.EvilPortal(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Preview) > 510 { // 500 chars + ellipsis
		t.Errorf("EvilPortal Preview len = %d, want <= 510", len(r.Preview))
	}
}
