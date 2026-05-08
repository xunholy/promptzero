package generate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

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

// TestCapSize_UTF8Boundary pins the rune-aware truncation. The
// previous implementation sliced at byte index max which could
// split a multi-byte UTF-8 rune in half — the resulting file
// would have invalid UTF-8 at the tail (rendered as U+FFFD by
// most parsers, or rejected outright by strict validators).
// Now capSize walks back to the previous rune start.
func TestCapSize_UTF8Boundary(t *testing.T) {
	// Build a string that places "é" (2 bytes 0xc3 0xa9) so the
	// natural cut at len-1 lands on the continuation byte. Filler
	// "x" is ASCII (1 byte each).
	in := strings.Repeat("x", 8) + "é" + strings.Repeat("x", 8)
	got := capSize(in, 9) // cut would land on byte 9 = 0xa9
	if !utf8.ValidString(got) {
		t.Fatalf("capSize produced invalid UTF-8: % x", got)
	}
	if len(got) != 8 {
		t.Errorf("expected walk-back to byte 8 (before é), got len=%d", len(got))
	}
	if got != strings.Repeat("x", 8) {
		t.Errorf("got %q, want 8 'x' filler", got)
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

	if _, err := g.BadUSB(context.Background(), "open run dialog", "", ""); err != nil {
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

	got, err := g.BadUSB(context.Background(), "test", "linux", "")
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

// --- v0.23-keyboard-layout ---------------------------------------------

// TestKeyboardLayoutGuidance_KnownLayoutsHaveNotes locks the
// curated table — every layout we claim to support in the Spec
// schema must produce a non-empty guidance string. Empty guidance
// means the LLM gets no extra context, which silently degrades to
// US-default behaviour.
func TestKeyboardLayoutGuidance_KnownLayoutsHaveNotes(t *testing.T) {
	cases := []string{"gb", "uk", "de", "fr", "es", "it", "dk", "no", "sv", "se", "pt", "br"}
	for _, layout := range cases {
		got := keyboardLayoutGuidance(layout)
		if got == "" {
			t.Errorf("layout %q: expected non-empty guidance, got empty", layout)
		}
	}
}

// TestKeyboardLayoutGuidance_USIsEmpty is the contract for the
// happy-path / pre-this-fix shape: empty string and "us" both
// produce no extra prompt content, so existing payloads that don't
// pass a layout argument behave identically.
func TestKeyboardLayoutGuidance_USIsEmpty(t *testing.T) {
	for _, layout := range []string{"", "us", "US", "  us  "} {
		if got := keyboardLayoutGuidance(layout); got != "" {
			t.Errorf("layout %q: expected empty (US default), got %q", layout, got)
		}
	}
}

// TestKeyboardLayoutGuidance_UnknownFallsBackToGeneric verifies the
// catch-all path — an unknown layout still produces guidance (just
// generic) so the model gets the signal that non-US encoding is
// required.
func TestKeyboardLayoutGuidance_UnknownFallsBackToGeneric(t *testing.T) {
	got := keyboardLayoutGuidance("xx-yz-not-a-real-layout")
	if got == "" {
		t.Fatal("unknown layout should still produce generic guidance")
	}
	if !strings.Contains(got, "ALTCHAR") {
		t.Errorf("generic guidance should mention ALTCHAR; got: %s", got)
	}
}

// TestBadUSB_LayoutThreadsIntoPrompt exercises the full path:
// when a layout is supplied, the LLM call should receive a prompt
// containing the layout-specific note. We capture the prompt via a
// fake provider and verify its content.
func TestBadUSB_LayoutThreadsIntoPrompt(t *testing.T) {
	llm := &stubProvider{resp: &provider.Response{Content: "DELAY 100\nSTRING test"}}
	g := New(llm, nil)

	if _, err := g.BadUSB(context.Background(), "type a German phrase", "windows", "de"); err != nil {
		t.Fatal(err)
	}

	if len(llm.gotMsgs) == 0 {
		t.Fatal("LLM should have been called")
	}
	prompt := llm.gotMsgs[0].Content
	if !strings.Contains(prompt, "KEYBOARD LAYOUT") {
		t.Errorf("prompt should include layout heading; got prompt:\n%s", prompt)
	}
	if !strings.Contains(prompt, "German") {
		t.Errorf("prompt should mention German layout; got prompt:\n%s", prompt)
	}
	if !strings.Contains(prompt, "Y/Z") {
		t.Errorf("prompt should mention Y/Z swap (German layout fact); got prompt:\n%s", prompt)
	}
}

// TestBadUSB_USLayoutKeepsPromptUnchanged is the regression guard:
// when the operator doesn't ask for a non-US layout, the prompt
// should NOT contain layout boilerplate that would waste tokens on
// the common case.
func TestBadUSB_USLayoutKeepsPromptUnchanged(t *testing.T) {
	llm := &stubProvider{resp: &provider.Response{Content: "DELAY 100\nSTRING test"}}
	g := New(llm, nil)

	if _, err := g.BadUSB(context.Background(), "say hi", "windows", ""); err != nil {
		t.Fatal(err)
	}
	if len(llm.gotMsgs) == 0 {
		t.Fatal("LLM should have been called")
	}
	prompt := llm.gotMsgs[0].Content
	if strings.Contains(prompt, "KEYBOARD LAYOUT") {
		t.Errorf("US layout should not add KEYBOARD LAYOUT note to prompt; got:\n%s", prompt)
	}
}
