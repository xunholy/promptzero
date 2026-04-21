package agent

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/session"
)

// DefaultSessionStore creates a Store rooted at ~/.promptzero/sessions.
func DefaultSessionStore() (*session.Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolving home dir: %w", err)
	}
	return session.NewStore(filepath.Join(home, ".promptzero", "sessions"))
}

// SetSessionStore wires a session store so Run auto-saves after every turn
// and ResumeSession / SaveSessionAs / ListSessions become usable. Safe to
// leave nil — persistence is opt-in.
func (a *Agent) SetSessionStore(s *session.Store) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessionStore = s
	if a.sessionID == "" {
		a.sessionID = fmt.Sprintf("session-%d", time.Now().Unix())
	}
}

// SessionID returns the current session's identifier (empty until a store
// is attached).
func (a *Agent) SessionID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessionID
}

// ResumeSession loads a saved session and replaces the in-memory history
// with its messages. The tool_use / tool_result blocks round-trip via the
// Raw field on session.Message, so the model sees an identical prior
// conversation.
func (a *Agent) ResumeSession(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sessionStore == nil {
		return fmt.Errorf("session store not configured")
	}
	state, err := a.sessionStore.Load(id)
	if err != nil {
		return err
	}
	history, err := fromSessionMessages(state.Messages)
	if err != nil {
		return fmt.Errorf("decoding session history: %w", err)
	}
	a.history = history
	a.sessionID = state.ID
	if state.Model != "" {
		a.model = state.Model
	}
	return nil
}

// SaveSessionAs persists the current history under a caller-supplied id
// (typically a human-friendly name). The auto-save session continues to
// write under its original id.
func (a *Agent) SaveSessionAs(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sessionStore == nil {
		return fmt.Errorf("session store not configured")
	}
	if name == "" {
		return fmt.Errorf("session name is empty")
	}
	msgs, err := toSessionMessages(a.history)
	if err != nil {
		return err
	}
	state := &session.State{
		ID:        name,
		CreatedAt: time.Now(),
		Messages:  msgs,
		Model:     a.model,
	}
	if existing, err := a.sessionStore.Load(name); err == nil {
		state.CreatedAt = existing.CreatedAt
	}
	return a.sessionStore.Save(state)
}

// ListSessions returns every saved session known to the attached store.
func (a *Agent) ListSessions() ([]session.State, error) {
	a.mu.Lock()
	store := a.sessionStore
	a.mu.Unlock()
	if store == nil {
		return nil, fmt.Errorf("session store not configured")
	}
	return store.List()
}

// autoSaveLocked persists the current history under the active session id.
// Callers must already hold a.mu.
func (a *Agent) autoSaveLocked() {
	if a.sessionStore == nil || a.sessionID == "" {
		return
	}
	msgs, err := toSessionMessages(a.history)
	if err != nil {
		log.Printf("agent: autoSave marshal failed for session %s: %v", a.sessionID, err)
		return
	}
	// Structured handoff artifact: heuristic summary of tool usage,
	// unresolved user threads, and blocked tools. Embedded in the
	// persisted session so /session resume and future /report can
	// consume the structure without replaying the full history.
	handoff := BuildHandoff(a.history)
	state := &session.State{
		ID:        a.sessionID,
		CreatedAt: time.Now(),
		Messages:  msgs,
		Model:     a.model,
		Handoff:   json.RawMessage(handoff.JSON()),
	}
	if existing, err := a.sessionStore.Load(a.sessionID); err == nil {
		state.CreatedAt = existing.CreatedAt
	}
	if err := a.sessionStore.Save(state); err != nil {
		log.Printf("agent: autoSave for session %s failed: %v", a.sessionID, err)
	}
}

// toSessionMessages marshals the live history into the session wire format.
// Each MessageParam is JSON-marshaled into the Message.Raw field so tool_use
// / tool_result blocks round-trip losslessly; Content holds a best-effort
// text preview for anyone browsing the file by hand.
func toSessionMessages(history []anthropic.MessageParam) ([]session.Message, error) {
	out := make([]session.Message, 0, len(history))
	for _, m := range history {
		raw, err := json.Marshal(m)
		if err != nil {
			return nil, fmt.Errorf("marshaling message: %w", err)
		}
		out = append(out, session.Message{
			Role:    string(m.Role),
			Content: previewText(m),
			Raw:     raw,
		})
	}
	return out, nil
}

// fromSessionMessages rebuilds the history from a saved session. When Raw is
// present it is the source of truth; otherwise we fall back to synthesising
// a plain text message from Role + Content (best-effort for hand-edited
// files or sessions saved by older versions).
func fromSessionMessages(msgs []session.Message) ([]anthropic.MessageParam, error) {
	out := make([]anthropic.MessageParam, 0, len(msgs))
	for i, m := range msgs {
		if len(m.Raw) > 0 {
			var param anthropic.MessageParam
			if err := json.Unmarshal(m.Raw, &param); err != nil {
				return nil, fmt.Errorf("message %d: %w", i, err)
			}
			out = append(out, param)
			continue
		}
		switch m.Role {
		case string(anthropic.MessageParamRoleAssistant):
			out = append(out, anthropic.NewAssistantMessage(anthropic.NewTextBlock(m.Content)))
		default:
			out = append(out, anthropic.NewUserMessage(anthropic.NewTextBlock(m.Content)))
		}
	}
	return out, nil
}

// previewText returns a short human-readable preview of a MessageParam,
// concatenating its text blocks. Tool blocks are summarised so the
// session JSON stays skimmable.
func previewText(m anthropic.MessageParam) string {
	var preview string
	for _, block := range m.Content {
		switch {
		case block.OfText != nil:
			preview += block.OfText.Text
		case block.OfToolUse != nil:
			preview += fmt.Sprintf("[tool_use:%s]", block.OfToolUse.Name)
		case block.OfToolResult != nil:
			preview += fmt.Sprintf("[tool_result:%s]", block.OfToolResult.ToolUseID)
		}
	}
	return preview
}
