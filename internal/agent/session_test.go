package agent

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/session"
)

// TestSessionRoundTrip verifies that tool_use + tool_result blocks survive
// a save/load cycle byte-identical to the original MessageParam values, so
// resuming a session doesn't strand the model with a dangling tool_use.
func TestSessionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := session.NewStore(filepath.Join(dir, "sessions"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	history := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock("please turn on the vibration")),
		anthropic.NewAssistantMessage(
			anthropic.NewTextBlock("On it."),
			anthropic.ContentBlockParamUnion{
				OfToolUse: &anthropic.ToolUseBlockParam{
					ID:    "toolu_123",
					Name:  "vibro",
					Input: json.RawMessage(`{"on":true}`),
				},
			},
		),
		anthropic.NewUserMessage(
			anthropic.NewToolResultBlock("toolu_123", "vibration on", false),
		),
		anthropic.NewAssistantMessage(anthropic.NewTextBlock("Done.")),
	}

	msgs, err := toSessionMessages(history)
	if err != nil {
		t.Fatalf("toSessionMessages: %v", err)
	}
	state := &session.State{ID: "smoke", Messages: msgs, Model: "claude-opus-4-7"}
	if err := store.Save(state); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Load("smoke")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rebuilt, err := fromSessionMessages(loaded.Messages)
	if err != nil {
		t.Fatalf("fromSessionMessages: %v", err)
	}

	origJSON, _ := json.Marshal(history)
	rebuiltJSON, _ := json.Marshal(rebuilt)
	if !reflect.DeepEqual(origJSON, rebuiltJSON) {
		t.Fatalf("mismatch:\norig:  %s\nback:  %s", origJSON, rebuiltJSON)
	}
}

// TestAgentResumeRestoresHistory exercises the Agent-level API: after
// attaching a store, resuming a previously saved session rebuilds the
// in-memory history the same as the source.
func TestAgentResumeRestoresHistory(t *testing.T) {
	dir := t.TempDir()
	store, err := session.NewStore(filepath.Join(dir, "sessions"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	history := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock("hi")),
		anthropic.NewAssistantMessage(anthropic.NewTextBlock("hello")),
	}
	msgs, err := toSessionMessages(history)
	if err != nil {
		t.Fatalf("toSessionMessages: %v", err)
	}
	if err := store.Save(&session.State{ID: "greetings", Messages: msgs}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	a := &Agent{}
	a.SetSessionStore(store)
	if err := a.ResumeSession("greetings"); err != nil {
		t.Fatalf("ResumeSession: %v", err)
	}
	if len(a.history) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(a.history))
	}

	if err := a.SaveSessionAs("greetings-copy"); err != nil {
		t.Fatalf("SaveSessionAs: %v", err)
	}
	list, err := a.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(list))
	}
}

func TestSessionTranscript_FlattensBlocks(t *testing.T) {
	history := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock("hi there")),
		anthropic.NewAssistantMessage(
			anthropic.NewTextBlock("checking"),
			anthropic.NewToolUseBlock("tu1", map[string]any{"k": "v"}, "list_files"),
		),
		anthropic.NewUserMessage(anthropic.NewToolResultBlock("tu1", "ok", false)),
	}
	msgs, err := toSessionMessages(history)
	if err != nil {
		t.Fatalf("toSessionMessages: %v", err)
	}

	events := SessionTranscript(&session.State{Messages: msgs})
	got := make([]string, 0, len(events))
	for _, e := range events {
		got = append(got, e.Kind)
	}
	want := []string{"user_text", "assistant_text", "tool_use", "tool_result"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("kinds = %v, want %v", got, want)
	}
	if events[2].Name != "list_files" || events[2].ToolUseID != "tu1" {
		t.Errorf("tool_use = %+v", events[2])
	}
	if events[3].Output != "ok" || events[3].IsError {
		t.Errorf("tool_result = %+v", events[3])
	}
}

func TestSessionTranscript_DropsHandoffSentinel(t *testing.T) {
	msgs := []session.Message{
		{Role: "user", Content: "real user"},
		{Role: "user", Content: HandoffResumeSentinel + "\n{...}\n</handoff-resume>"},
	}
	events := SessionTranscript(&session.State{Messages: msgs})
	if len(events) != 1 || events[0].Text != "real user" {
		t.Fatalf("expected 1 event 'real user', got %+v", events)
	}
}

func TestDeriveTitle_TruncatesAndSkipsHandoff(t *testing.T) {
	long := "this is a very very very long opening message that should get clipped after sixty characters or so"
	cases := []struct {
		name string
		hist []anthropic.MessageParam
		want string
	}{
		{"empty", nil, ""},
		{
			"first user text",
			[]anthropic.MessageParam{
				anthropic.NewUserMessage(anthropic.NewTextBlock("scan WiFi networks")),
			},
			"scan WiFi networks",
		},
		{
			"skips handoff prefix",
			[]anthropic.MessageParam{
				anthropic.NewUserMessage(anthropic.NewTextBlock(HandoffResumeSentinel + "\n{...}")),
				anthropic.NewUserMessage(anthropic.NewTextBlock("real prompt")),
			},
			"real prompt",
		},
		{
			"truncates long",
			[]anthropic.MessageParam{
				anthropic.NewUserMessage(anthropic.NewTextBlock(long)),
			},
			long[:titleMaxLen-1] + "…",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveTitle(tc.hist)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClipTitle_UTF8Boundary pins the rune-aware truncation. The
// previous implementation sliced at byte index titleMaxLen-1 which
// could split a multi-byte UTF-8 rune in half, producing invalid
// UTF-8 in the sidebar (renderers display U+FFFD or drop the
// fragment). Now clipTitle walks back to the previous rune start.
func TestClipTitle_UTF8Boundary(t *testing.T) {
	// Build a string that places a multi-byte rune (é = 2 bytes
	// 0xc3 0xa9) so the byte at the natural cut is a continuation
	// byte. Filler "x" is ASCII (1 byte each); place the é so that
	// the cut at titleMaxLen-1 lands on the second byte of the rune.
	filler := strings.Repeat("x", titleMaxLen-2)
	in := filler + "é-tail-content-that-pushes-past-the-cap"
	got := clipTitle(in)
	// Must be valid UTF-8 — no continuation byte at the boundary.
	if !utf8.ValidString(got) {
		t.Fatalf("clipTitle produced invalid UTF-8: %q", got)
	}
	// Must end with the ellipsis.
	if !strings.HasSuffix(got, "…") {
		t.Errorf("clipTitle should end with ellipsis: %q", got)
	}
	// The é rune (2 bytes) at the boundary must be excluded entirely
	// — we walk back from the cut to a rune start.
	if strings.HasSuffix(strings.TrimSuffix(got, "…"), "\xc3") {
		t.Errorf("clipTitle left a dangling lead byte: % x", got)
	}
}

func TestNewSession_ClearsHistoryAndRotatesID(t *testing.T) {
	a := &Agent{}
	a.history = []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock("old")),
	}
	a.sessionID = "session-old"
	id := a.NewSession()
	if id == "" || id == "session-old" {
		t.Errorf("expected fresh id, got %q", id)
	}
	if len(a.history) != 0 {
		t.Errorf("history not cleared: %d", len(a.history))
	}
}

// TestNewSession_DoesNotCollideOnRapidCalls covers the
// same-second-collision regression: when sessionID was generated
// from time.Now().Unix() (seconds), two consecutive NewSession()
// calls in the same wall-clock second produced the same id and
// would overwrite each other's saved state on disk. UnixNano
// brings collision risk to effectively zero.
func TestNewSession_DoesNotCollideOnRapidCalls(t *testing.T) {
	a := &Agent{}
	const n = 50
	seen := map[string]struct{}{}
	for i := 0; i < n; i++ {
		id := a.NewSession()
		if _, dup := seen[id]; dup {
			t.Fatalf("collision on iteration %d: id=%q", i, id)
		}
		seen[id] = struct{}{}
	}
}

// The agent prepends <ui-context .../> and <device-state>...</device-state>
// blocks to user input as turn grounding. Title derivation must skip
// these so the sidebar shows the operator's prompt, not the JSON dump.
func TestDeriveTitle_StripsAgentInjectedPrefixes(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{
			"device-state then prompt",
			"<device-state>\n{\"connected\":true,\"fork\":\"Momentum\"}\n</device-state>\n\nlist every installed app (FAP) on the flipper SD card",
			"list every installed app (FAP) on the flipper SD card",
		},
		{
			"ui-context self-closing then prompt",
			"<ui-context view=\"agent\" path=\"\"/>\nscan wifi",
			"scan wifi",
		},
		{
			"chained ui-context + device-state",
			"<ui-context view=\"agent\" path=\"\"/>\n<device-state>\n{}\n</device-state>\n\nreal prompt",
			"real prompt",
		},
		{
			"prefixes only",
			"<device-state>{}</device-state>",
			"",
		},
		{
			"user starts with non-allowlisted tag — preserved",
			"<example>look at this</example>",
			"<example>look at this</example>",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hist := []anthropic.MessageParam{
				anthropic.NewUserMessage(anthropic.NewTextBlock(tc.text)),
			}
			got := deriveTitle(hist)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDeriveTitleFromMessages_FallbackForLegacyState(t *testing.T) {
	// Pre-existing session files saved before the Title field existed:
	// no Title, but Raw round-trips a real user message. The API layer
	// must surface the user's first prompt instead of "Untitled session".
	history := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock("scan the wifi networks")),
		anthropic.NewAssistantMessage(anthropic.NewTextBlock("on it")),
	}
	msgs, err := toSessionMessages(history)
	if err != nil {
		t.Fatalf("toSessionMessages: %v", err)
	}
	got := DeriveTitleFromMessages(msgs)
	if got != "scan the wifi networks" {
		t.Errorf("got %q, want 'scan the wifi networks'", got)
	}

	// Plain-text fallback path: legacy entries with Content but no Raw.
	got = DeriveTitleFromMessages([]session.Message{
		{Role: "user", Content: "  hello there\nworld  "},
	})
	if got != "hello there world" {
		t.Errorf("plaintext fallback got %q", got)
	}

	// Empty / handoff-only sessions return empty so the frontend renders
	// the "Untitled session" placeholder rather than internal context.
	got = DeriveTitleFromMessages([]session.Message{
		{Role: "user", Content: HandoffResumeSentinel + "\n{...}"},
	})
	if got != "" {
		t.Errorf("handoff-only got %q, want empty", got)
	}
}

func TestMaybeGenerateTitle_GatedOnFirstAssistantTurn(t *testing.T) {
	dir := t.TempDir()
	store, err := session.NewStore(filepath.Join(dir, "sessions"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	a := &Agent{}
	a.SetSessionStore(store)
	// No anthropic client → maybeGenerateTitleLocked must return without
	// touching state (and certainly without panicking on a.client.Messages).
	a.history = []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock("hi")),
		anthropic.NewAssistantMessage(anthropic.NewTextBlock("hello")),
	}
	state := &session.State{ID: a.sessionID}
	a.maybeGenerateTitleLocked(state) // must be a no-op without a client
}

func TestHasFirstAssistantTurn(t *testing.T) {
	cases := []struct {
		name string
		hist []anthropic.MessageParam
		want bool
	}{
		{"empty", nil, false},
		{
			"user-only",
			[]anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock("hi"))},
			false,
		},
		{
			"assistant-then-user",
			[]anthropic.MessageParam{
				anthropic.NewAssistantMessage(anthropic.NewTextBlock("ready")),
				anthropic.NewUserMessage(anthropic.NewTextBlock("hi")),
			},
			false,
		},
		{
			"user-then-assistant",
			[]anthropic.MessageParam{
				anthropic.NewUserMessage(anthropic.NewTextBlock("hi")),
				anthropic.NewAssistantMessage(anthropic.NewTextBlock("hello")),
			},
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasFirstAssistantTurn(tc.hist); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildTitlePrompt_DropsHandoffAndCaps(t *testing.T) {
	hist := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock(HandoffResumeSentinel + "\n{...}")),
		anthropic.NewUserMessage(anthropic.NewTextBlock("real prompt")),
		anthropic.NewAssistantMessage(anthropic.NewTextBlock("real reply")),
	}
	got := buildTitlePrompt(hist)
	if !strings.Contains(got, "user: real prompt") || !strings.Contains(got, "assistant: real reply") {
		t.Errorf("missing real lines: %q", got)
	}
	if strings.Contains(got, HandoffResumeSentinel) {
		t.Errorf("handoff leaked into prompt: %q", got)
	}
}

func TestRenameSession_PersistsTitle(t *testing.T) {
	dir := t.TempDir()
	store, err := session.NewStore(filepath.Join(dir, "sessions"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Save(&session.State{ID: "x", Title: "before"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	a := &Agent{}
	a.SetSessionStore(store)
	if err := a.RenameSession("x", "after"); err != nil {
		t.Fatalf("RenameSession: %v", err)
	}
	state, err := store.Load("x")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if state.Title != "after" {
		t.Errorf("title = %q, want after", state.Title)
	}
}
