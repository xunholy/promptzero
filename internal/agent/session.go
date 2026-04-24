package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/obs"
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
	// Inject the persisted handoff artifact so the model sees the
	// structured {findings, open_threads, blocked, device_state}
	// block on its first post-resume turn (P1-08). Without this, the
	// handoff JSON would stay dormant on disk and the LLM would lose
	// the compact resumability signal the artifact is built for.
	if len(state.Handoff) > 0 {
		a.history = append(a.history,
			anthropic.NewUserMessage(anthropic.NewTextBlock(handoffResumeContext(state.Handoff))),
		)
	}
	return nil
}

// handoffResumeContext wraps the persisted HandoffArtifact JSON in a
// <handoff-resume> sentinel so the model can recognise it as a
// structured snapshot of the prior session rather than a fresh user
// question. Kept terse — the artifact itself carries the findings /
// threads / blocked detail.
func handoffResumeContext(raw json.RawMessage) string {
	return "<handoff-resume>\n" + string(raw) + "\n</handoff-resume>\n\n" +
		"This session was resumed. The block above summarises what happened before the break. Prioritise the open_threads; avoid retrying tools listed in blocked."
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

// DeleteSession removes a session from the attached store and auto-
// purges any per-session snapshots (P1-09). Callers that only want
// the session file removed can use sessionStore.Delete directly;
// DeleteSession is the sanctioned path for the CLI because it keeps
// the snapshot tree in lockstep with the session's lifecycle. Errors
// from the snapshot purge are best-effort — a failed snapshot purge
// leaves orphaned backup files but doesn't block the session
// deletion itself.
func (a *Agent) DeleteSession(id string) error {
	a.mu.Lock()
	store := a.sessionStore
	mgr := a.snapshotMgr
	a.mu.Unlock()
	if store == nil {
		return fmt.Errorf("session store not configured")
	}
	if id == "" {
		return fmt.Errorf("session id is empty")
	}
	if err := store.Delete(id); err != nil {
		return fmt.Errorf("delete session %s: %w", id, err)
	}
	if mgr != nil {
		if err := mgr.Purge(id); err != nil {
			obs.Default().Warn("session_snapshot_purge_failed", "session_id", id, "err", err)
		}
	}
	return nil
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
		obs.Default().Warn("session_autosave_marshal_failed", "session_id", a.sessionID, "err", err)
		return
	}
	// Structured handoff artifact: heuristic summary of tool usage,
	// unresolved user threads, and blocked tools. Embedded in the
	// persisted session so /session resume and future /report can
	// consume the structure without replaying the full history. The
	// device_state_at_compact field is populated lazily — autosave
	// runs under a.mu and a State probe would block it, so we ship a
	// cached capability snapshot instead (the full State oracle with
	// battery + SD runs on every user turn elsewhere).
	handoff := BuildHandoff(a.history)
	if a.flipper != nil {
		caps := a.flipper.Capabilities()
		handoff = handoff.WithDeviceState(map[string]any{
			"fork":             caps.FriendlyFork(),
			"firmware_version": caps.FirmwareVersion,
			"hardware_name":    caps.HardwareName,
			"hardware_uid":     caps.HardwareUID,
		})
	}
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
		obs.Default().Warn("session_autosave_failed", "session_id", a.sessionID, "err", err)
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
