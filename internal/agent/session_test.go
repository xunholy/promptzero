package agent

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

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
