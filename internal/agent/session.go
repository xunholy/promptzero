package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/session"
)

// HandoffResumeSentinel is the prefix used on the synthetic user message
// injected on resume so the model sees the structured handoff. UI code
// strips messages with this prefix from rendered transcripts.
const HandoffResumeSentinel = "<handoff-resume>"

// titleMaxLen caps auto-derived session titles so the sidebar stays readable.
const titleMaxLen = 60

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
		// UnixNano so quick SetSessionStore/NewSession cycles in
		// the same second don't collide on the file path.
		a.sessionID = fmt.Sprintf("session-%d", time.Now().UnixNano())
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
	return HandoffResumeSentinel + "\n" + string(raw) + "\n</handoff-resume>\n\n" +
		"This session was resumed. The block above summarises what happened before the break. Prioritise the open_threads; avoid retrying tools listed in blocked."
}

// TranscriptEvent is one frontend-renderable record produced from a
// persisted session.Message. Kinds: "user_text", "assistant_text",
// "tool_use", "tool_result". Empty kinds are skipped by callers.
type TranscriptEvent struct {
	Kind      string          `json:"kind"`
	Text      string          `json:"text,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	Output    string          `json:"output,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

// SessionTranscript flattens a saved session's messages into the
// frontend-renderable event stream. Synthetic <handoff-resume> messages
// are dropped so resumed sessions don't show internal context as a chat
// bubble. Tool inputs are passed through as raw JSON; tool results are
// rendered as plain text (the SDK's tool_result content is already a
// list of text blocks for the formats we use).
func SessionTranscript(state *session.State) []TranscriptEvent {
	if state == nil {
		return nil
	}
	out := make([]TranscriptEvent, 0, len(state.Messages))
	for _, m := range state.Messages {
		if len(m.Raw) == 0 {
			// Legacy / hand-edited entries fall back to plain text.
			isUser := m.Role != string(anthropic.MessageParamRoleAssistant)
			var text string
			if isUser {
				text = extractUserContent(m.Content)
			} else {
				text = strings.TrimSpace(m.Content)
			}
			if text == "" {
				continue
			}
			kind := "user_text"
			if !isUser {
				kind = "assistant_text"
			}
			out = append(out, TranscriptEvent{Kind: kind, Text: text})
			continue
		}
		var param anthropic.MessageParam
		if err := json.Unmarshal(m.Raw, &param); err != nil {
			continue
		}
		isUser := param.Role == anthropic.MessageParamRoleUser
		for _, block := range param.Content {
			switch {
			case block.OfText != nil:
				text := block.OfText.Text
				kind := "assistant_text"
				if isUser {
					kind = "user_text"
					text = extractUserContent(text)
				}
				if text == "" {
					continue
				}
				out = append(out, TranscriptEvent{Kind: kind, Text: text})
			case block.OfToolUse != nil:
				out = append(out, TranscriptEvent{
					Kind:      "tool_use",
					ToolUseID: block.OfToolUse.ID,
					Name:      block.OfToolUse.Name,
					Input:     toolUseInputJSON(block.OfToolUse),
				})
			case block.OfToolResult != nil:
				ev := TranscriptEvent{
					Kind:      "tool_result",
					ToolUseID: block.OfToolResult.ToolUseID,
					IsError:   toolResultIsError(block.OfToolResult),
				}
				ev.Output = toolResultText(block.OfToolResult)
				out = append(out, ev)
			}
		}
	}
	return out
}

// toolUseInputJSON marshals a ToolUseBlockParam's Input field, which is
// declared as `any`. Returns nil JSON when marshaling fails so the API
// just omits the field rather than 500-ing.
func toolUseInputJSON(b *anthropic.ToolUseBlockParam) json.RawMessage {
	if b == nil {
		return nil
	}
	raw, err := json.Marshal(b.Input)
	if err != nil {
		// Returning nil is the documented graceful behaviour, but
		// also log so the saved session's missing input data has a
		// breadcrumb. Operators reviewing /sessions later won't have
		// to guess whether the field was empty by design or dropped.
		obs.Default().Warn("session_tool_input_marshal_failed",
			"tool", b.Name, "tool_use_id", b.ID, "err", err)
		return nil
	}
	return raw
}

// toolResultText concatenates a tool_result block's content into a single
// string. The SDK models it as a slice of text/image content blocks; the
// renderer only cares about the textual portion (images surface as their
// type tag).
func toolResultText(b *anthropic.ToolResultBlockParam) string {
	if b == nil {
		return ""
	}
	var sb strings.Builder
	for _, c := range b.Content {
		if c.OfText != nil {
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(c.OfText.Text)
		}
	}
	return sb.String()
}

// NewSession resets the in-memory history and starts a fresh session id
// so subsequent turns persist under a new file. Returns the new id. No-op
// when no session store is configured beyond clearing history.
func (a *Agent) NewSession() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.history = nil
	// UnixNano so two NewSession() calls in the same second don't
	// produce the same id and overwrite each other's saved state.
	a.sessionID = fmt.Sprintf("session-%d", time.Now().UnixNano())
	return a.sessionID
}

// RenameSession sets the human-friendly title on a saved session. Empty
// title clears it (the UI will fall back to a derived preview).
func (a *Agent) RenameSession(id, title string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sessionStore == nil {
		return fmt.Errorf("session store not configured")
	}
	if id == "" {
		return fmt.Errorf("session id is empty")
	}
	state, err := a.sessionStore.Load(id)
	if err != nil {
		return err
	}
	state.Title = strings.TrimSpace(title)
	return a.sessionStore.Save(state)
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
		// Preserve an operator-set title when /save overwrites an
		// existing slot — matches the preservation autoSaveLocked
		// already does on the active session. Pre-fix, /save my-name
		// silently clobbered any title set by /api/sessions PATCH
		// or by Haiku title generation. /save's intent is "update
		// the content of slot <name>", not "wipe its sidebar label".
		if strings.TrimSpace(existing.Title) != "" {
			state.Title = existing.Title
		}
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
	// Capture whether the operator is deleting the currently-active
	// session so we can rotate in-memory state after the disk delete
	// completes. Without this rotation /forget <current-id> would
	// silently undo itself: autosave on the next turn re-creates
	// id.json from a.history, and the next snapshot recreates
	// snapshots/<id>/ — the operator thinks the session is gone but
	// it reappears on the next REPL turn.
	isCurrent := id != "" && id == a.sessionID
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
	if isCurrent {
		a.mu.Lock()
		// Re-check under the lock — a concurrent ResumeSession /
		// NewSession could have rotated sessionID after we snapshotted
		// isCurrent. Only rotate when the field still matches the id
		// the operator asked us to forget.
		if a.sessionID == id {
			a.history = nil
			a.sessionID = fmt.Sprintf("session-%d", time.Now().UnixNano())
		}
		a.mu.Unlock()
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
		Title:     deriveTitle(a.history),
	}
	if existing, err := a.sessionStore.Load(a.sessionID); err == nil {
		state.CreatedAt = existing.CreatedAt
		// Preserve an operator-set title over the auto-derived one
		// so /api/sessions PATCH (rename) survives the next autosave.
		if strings.TrimSpace(existing.Title) != "" {
			state.Title = existing.Title
		}
	}
	if err := a.sessionStore.Save(state); err != nil {
		obs.Default().Warn("session_autosave_failed", "session_id", a.sessionID, "err", err)
	}

	a.maybeGenerateTitleLocked(state)
}

// maybeGenerateTitleLocked spawns a one-shot Haiku call to write a short
// human-friendly session title — same behaviour as Claude Desktop /
// ChatGPT. Gated on:
//   - a live anthropic client (skipped in tests / offline).
//   - an empty or auto-derived title (operator renames are preserved).
//   - at least one user→assistant exchange in history.
//   - one inflight per session per process.
//
// Caller MUST hold a.mu — the function only reads under the lock and
// dispatches the network call from a goroutine that re-acquires the
// lock before persisting.
func (a *Agent) maybeGenerateTitleLocked(state *session.State) {
	if a.client == nil || a.sessionStore == nil {
		return
	}
	id := state.ID
	if id == "" {
		return
	}
	if a.titleGenInflight == nil {
		a.titleGenInflight = make(map[string]bool)
	}
	if a.titleGenInflight[id] {
		return
	}
	// Operator-set titles look distinct from the auto-derived preview,
	// so once the persisted title is anything other than the verbatim
	// first-message clip we leave it alone. This catches both /api
	// PATCH renames and any future operator-driven entry point.
	derived := deriveTitle(a.history)
	if state.Title != "" && state.Title != derived {
		return
	}
	if !hasFirstAssistantTurn(a.history) {
		return
	}
	model := a.modelForLocked(TierClassify)
	historyCopy := make([]anthropic.MessageParam, len(a.history))
	copy(historyCopy, a.history)
	a.titleGenInflight[id] = true

	// Wrap in obs.SafeGo so a panic inside the title-generation
	// goroutine (nil pointer in an SDK response, marshal failure
	// in callTitleAPI, etc.) is recovered + logged with a stack
	// trace instead of crashing the whole agent process. Title
	// generation is a best-effort sidebar label — the cost of a
	// failure should be a missing label, not a process exit.
	obs.SafeGo("agent.title_generation", func() {
		a.runTitleGeneration(id, model, derived, historyCopy)
	})
}

// runTitleGeneration is the goroutine launched by maybeGenerateTitleLocked.
// Errors are best-effort: a failure leaves the auto-derived title in
// place, no surface to the operator. Five-second cap on the call so a
// stuck network never accumulates goroutines across many sessions.
//
// derivedSnapshot is the auto-derived title at the moment the goroutine
// was spawned. Before persisting we verify the on-disk title still
// matches it (or is still empty) so an operator rename that lands during
// the network call wins over the LLM result.
//
// Clears the in-flight marker on exit so a transient network failure
// (callTitleAPI returns "" on error) doesn't permanently lock the
// session out of future title generations. Pre-fix the flag was set
// before spawning but never cleared, so a single 5-second timeout or
// rate-limit response left the session stuck with the auto-derived
// title forever — every subsequent autosave saw inflight=true and
// skipped maybeGenerateTitleLocked. On the success path the flag
// clear is a no-op against retry: line 428's
// `state.Title != "" && state.Title != derived` already short-circuits
// once a real title has been persisted.
func (a *Agent) runTitleGeneration(id, model, derivedSnapshot string, history []anthropic.MessageParam) {
	defer func() {
		a.mu.Lock()
		delete(a.titleGenInflight, id)
		a.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	title := a.callTitleAPI(ctx, model, history)
	if title == "" {
		return
	}

	a.mu.Lock()
	store := a.sessionStore
	a.mu.Unlock()
	if store == nil {
		return
	}
	state, err := store.Load(id)
	if err != nil {
		return
	}
	current := strings.TrimSpace(state.Title)
	if current != "" && current != derivedSnapshot {
		return
	}
	state.Title = title
	if err := store.Save(state); err != nil {
		obs.Default().Warn("session_title_persist_failed", "session_id", id, "err", err)
	}
}

// callTitleAPI runs the actual Haiku call. Split out so tests can
// override the dispatch path without touching the autosave loop.
func (a *Agent) callTitleAPI(ctx context.Context, model string, history []anthropic.MessageParam) string {
	const system = "Summarise this conversation in 4 to 7 plain words for a sidebar label. " +
		"Output ONLY the title — no quotes, no trailing period, no preamble. Lowercase except proper nouns. " +
		"Examples: 'scan wifi networks', 'replay subghz capture', 'mifare key recovery'."

	userText := buildTitlePrompt(history)
	if userText == "" {
		return ""
	}

	resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 32,
		System:    []anthropic.TextBlockParam{{Text: system}},
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(userText))},
	})
	if err != nil {
		return ""
	}
	for _, block := range resp.Content {
		if block.Type == "text" && block.Text != "" {
			return clipTitle(strings.Trim(block.Text, "\"'.\n "))
		}
	}
	return ""
}

// buildTitlePrompt extracts up to the first 1500 characters of the
// user/assistant text from history so the Haiku summariser sees the
// gist without a token blowout. Tool blocks are skipped — their
// payloads are typically machine output the title shouldn't echo.
func buildTitlePrompt(history []anthropic.MessageParam) string {
	const cap = 1500
	var sb strings.Builder
	for _, m := range history {
		role := "user"
		if m.Role == anthropic.MessageParamRoleAssistant {
			role = "assistant"
		}
		for _, block := range m.Content {
			if block.OfText == nil {
				continue
			}
			text := block.OfText.Text
			if role == "user" {
				text = extractUserContent(text)
			} else {
				text = strings.TrimSpace(text)
			}
			if text == "" {
				continue
			}
			sb.WriteString(role)
			sb.WriteString(": ")
			sb.WriteString(text)
			sb.WriteString("\n")
			if sb.Len() > cap {
				return sb.String()[:cap]
			}
		}
	}
	return sb.String()
}

// hasFirstAssistantTurn reports whether the in-memory history contains
// at least one user message followed by an assistant message — the
// minimum signal that there's actual conversation to summarise.
func hasFirstAssistantTurn(history []anthropic.MessageParam) bool {
	sawUser := false
	for _, m := range history {
		switch m.Role {
		case anthropic.MessageParamRoleUser:
			sawUser = true
		case anthropic.MessageParamRoleAssistant:
			if sawUser {
				return true
			}
		}
	}
	return false
}

// DeriveTitleFromMessages reads the persisted message slice and returns
// a one-line preview of the first non-handoff user message — same shape
// as the live-history derivation in deriveTitle, just operating on the
// disk wire format. Used as the /api/sessions fallback for sessions
// saved before the Title field existed (and for any future state that
// somehow reached the wire without a title).
func DeriveTitleFromMessages(msgs []session.Message) string {
	for _, m := range msgs {
		if m.Role != string(anthropic.MessageParamRoleUser) {
			continue
		}
		var text string
		if len(m.Raw) > 0 {
			var param anthropic.MessageParam
			if err := json.Unmarshal(m.Raw, &param); err == nil {
				for _, block := range param.Content {
					if block.OfText != nil {
						text = block.OfText.Text
						break
					}
				}
			}
		}
		if text == "" {
			text = m.Content
		}
		clean := extractUserContent(text)
		if clean == "" {
			continue
		}
		return clipTitle(clean)
	}
	return ""
}

// clipTitle is the shared title-shaping helper: strip newlines / runs of
// whitespace, then truncate to titleMaxLen with an ellipsis so long
// prompts don't overflow the sidebar. UTF-8-aware: when the cap lands
// in the middle of a multi-byte rune we walk back to the previous rune
// start so the returned string is always valid UTF-8 (no replacement
// glyphs in the sidebar). Mirrors the discipline in
// toolerror.truncateExcerpt.
func clipTitle(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	if len(text) <= titleMaxLen {
		return text
	}
	cut := titleMaxLen - 1
	// UTF-8 continuation bytes match 0b10xxxxxx (b&0xC0 == 0x80).
	// Walk left until we hit a leading byte (or hit zero).
	for cut > 0 && text[cut]&0xC0 == 0x80 {
		cut--
	}
	return text[:cut] + "…"
}

// contextPrefixTags lists the XML-style wrapper tags the agent injects
// in front of user text — device-state oracle, web UI navigation hint,
// and the resume handoff envelope. The title-derivation walk strips any
// leading run of these so the sidebar shows the operator's actual
// prompt, not the synthetic grounding block.
//
// Allowlisted (rather than "any leading <tag>") so a user prompt that
// legitimately starts with markup (e.g. an example tag they want the
// model to evaluate) is preserved.
var contextPrefixTags = []string{"device-state", "ui-context"}

// extractUserContent reads a persisted user-message text and returns
// just the operator-typed portion. Returns "" when the message is
// purely synthetic (the resume-handoff envelope) so callers skip it
// instead of titling sessions with "This session was resumed…" or
// echoing it into the chat replay.
func extractUserContent(text string) string {
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, HandoffResumeSentinel) {
		return ""
	}
	return strings.TrimSpace(stripContextPrefixes(text))
}

// stripContextPrefixes peels off any leading allowlisted wrapper blocks
// from text so the remainder is whatever the operator actually typed.
// Handles both paired (<tag ...>...</tag>) and self-closing (<tag .../>)
// forms; runs to a fixed point so chained prefixes (ui-context +
// device-state) all come off.
func stripContextPrefixes(text string) string {
	for {
		text = strings.TrimLeft(text, " \t\r\n")
		if !strings.HasPrefix(text, "<") {
			return text
		}
		matched := false
		for _, tag := range contextPrefixTags {
			open := "<" + tag
			if !strings.HasPrefix(text, open) {
				continue
			}
			// Tag must be followed by a tag-closing rune so we don't
			// match a hypothetical "<device-state-2>".
			tail := text[len(open):]
			if tail == "" || (tail[0] != ' ' && tail[0] != '>' && tail[0] != '/') {
				continue
			}
			gt := strings.Index(text, ">")
			if gt < 0 {
				return text
			}
			// Self-closing: <tag .../>
			if gt > 0 && text[gt-1] == '/' {
				text = text[gt+1:]
				matched = true
				break
			}
			// Paired: skip past the matching close tag.
			closeTag := "</" + tag + ">"
			ci := strings.Index(text, closeTag)
			if ci < 0 {
				return text
			}
			text = text[ci+len(closeTag):]
			matched = true
			break
		}
		if !matched {
			return text
		}
	}
}

// deriveTitle pulls a one-line preview from the first non-handoff user
// message, truncated for the sidebar. Empty when the session has no
// user content yet (a brand-new session before its first turn).
func deriveTitle(history []anthropic.MessageParam) string {
	for _, m := range history {
		if m.Role != anthropic.MessageParamRoleUser {
			continue
		}
		var text string
		for _, block := range m.Content {
			if block.OfText != nil {
				text = block.OfText.Text
				break
			}
		}
		clean := extractUserContent(text)
		if clean == "" {
			continue
		}
		return clipTitle(clean)
	}
	return ""
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
