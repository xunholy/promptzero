package agent

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
)

// HandoffArtifact is a structured summary of what happened in a session,
// emitted whenever history is compacted or an operator asks for a
// resumable snapshot. Callers (/report, /session resume, future
// Campaigns runner) consume the JSON shape directly rather than
// scraping prose out of the conversation.
//
// The schema is deliberately shallow and grep-friendly so the LLM can
// reason over it without deep destructuring:
//
//	{
//	  "findings":      [{"tool":"...","count":N,"last_seen":"..."}, ...],
//	  "open_threads":  [{"text":"...","role":"user"}, ...],
//	  "blocked":       [{"tool":"...","code":"...","message":"..."}, ...],
//	  "turns_covered": N,
//	  "generated_at":  RFC3339
//	}
type HandoffArtifact struct {
	Findings     []HandoffFinding `json:"findings,omitempty"`
	OpenThreads  []HandoffThread  `json:"open_threads,omitempty"`
	Blocked      []HandoffBlocked `json:"blocked,omitempty"`
	TurnsCovered int              `json:"turns_covered"`
	GeneratedAt  time.Time        `json:"generated_at"`

	// DeviceStateAtCompact pins the Flipper snapshot we had at
	// handoff-generation time (fork, firmware, battery, SD info). Used
	// by /session resume and /report to render "session state at
	// pause" without re-probing the device. Optional — BuildHandoff
	// leaves it nil and callers who have a flipper.State on hand call
	// WithDeviceState on the result.
	DeviceStateAtCompact json.RawMessage `json:"device_state_at_compact,omitempty"`
}

// WithDeviceState stamps the given device state (marshalled as JSON)
// onto the artifact. Returns the mutated receiver so callers can
// chain: `BuildHandoff(history).WithDeviceState(state)`. Pass a nil
// value to clear.
func (h HandoffArtifact) WithDeviceState(state any) HandoffArtifact {
	if state == nil {
		h.DeviceStateAtCompact = nil
		return h
	}
	if b, err := json.Marshal(state); err == nil {
		h.DeviceStateAtCompact = b
	}
	return h
}

// HandoffFinding counts tool invocations of one kind. Useful because a
// session that ran 12 wifi_scan_ap calls is telling a different story
// from one that ran 1 wifi_deauth.
type HandoffFinding struct {
	Tool     string `json:"tool"`
	Count    int    `json:"count"`
	LastSeen string `json:"last_seen,omitempty"` // best-effort preview of the last result
}

// HandoffThread captures an unresolved user request — a user message
// that wasn't followed by an assistant "done" response yet.
type HandoffThread struct {
	Text string `json:"text"`
	Role string `json:"role"`
}

// HandoffBlocked captures a tool failure so resumption can prefer
// different tactics instead of re-running the same doomed call.
// Populated by parsing structured ToolError JSON out of tool_result
// blocks; free-form error strings fall back to the Message field.
type HandoffBlocked struct {
	Tool    string `json:"tool"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// BuildHandoff derives a HandoffArtifact from a conversation history
// via pure heuristics — no LLM call. Designed to be cheap enough that
// it can run on every autosave without introducing latency.
//
// Future enhancement (tracked as follow-up to P1-08): synthesize a
// richer narrative via Haiku at TierClassify when available. The shape
// stays the same; the heuristic fields just get smarter.
func BuildHandoff(history []anthropic.MessageParam) HandoffArtifact {
	out := HandoffArtifact{
		GeneratedAt: time.Now(),
	}

	// Count tool invocations and remember the last output per tool.
	tallies := map[string]int{}
	lastSeen := map[string]string{}
	order := []string{} // preserve first-seen order for stable output

	// Collect blocked tools by correlating tool_use / tool_result
	// blocks. An error result with JSON shape {"code":..., "tool":...}
	// gets parsed; everything else keeps its raw message.
	toolUsesByID := map[string]string{}

	// Candidate open threads = user text messages without a matching
	// assistant "text" reply after them. Simplified for MVP: last
	// pure-user-text message that hasn't been followed by a text-only
	// assistant message is treated as open.
	var lastUserText string

	for _, msg := range history {
		out.TurnsCovered++
		for _, block := range msg.Content {
			switch {
			case block.OfToolUse != nil:
				name := block.OfToolUse.Name
				if _, seen := tallies[name]; !seen {
					order = append(order, name)
				}
				tallies[name]++
				toolUsesByID[block.OfToolUse.ID] = name
			case block.OfToolResult != nil:
				// Capture error + success previews.
				tr := block.OfToolResult
				var preview string
				for _, c := range tr.Content {
					if c.OfText != nil {
						preview = c.OfText.Text
						break
					}
				}
				name := toolUsesByID[tr.ToolUseID]
				if name != "" && preview != "" {
					lastSeen[name] = truncatePreview(preview, 120)
				}
				if toolResultIsError(tr) && name != "" {
					out.Blocked = append(out.Blocked, extractBlocked(name, preview))
				}
			case block.OfText != nil:
				txt := strings.TrimSpace(block.OfText.Text)
				if msg.Role == anthropic.MessageParamRoleUser && txt != "" {
					// Skip our own synthetic state-oracle / quarantine prefixes.
					if !strings.HasPrefix(txt, "<device-state>") && !strings.HasPrefix(txt, "<handoff>") {
						lastUserText = txt
					}
				}
				if msg.Role == anthropic.MessageParamRoleAssistant && txt != "" {
					// Assistant produced a final text reply — clear the
					// open-thread candidate. Tool-use-only turns don't
					// contribute a text block, so they leave the user
					// turn still "open" per this heuristic.
					lastUserText = ""
				}
			}
		}
	}

	// Materialize findings in first-seen order for determinism.
	for _, name := range order {
		out.Findings = append(out.Findings, HandoffFinding{
			Tool:     name,
			Count:    tallies[name],
			LastSeen: lastSeen[name],
		})
	}

	if lastUserText != "" {
		out.OpenThreads = append(out.OpenThreads, HandoffThread{
			Role: "user",
			Text: truncatePreview(lastUserText, 300),
		})
	}
	return out
}

// JSON serialises the artifact to a compact wire representation. Used
// both for session.State persistence and for injection into the model
// turn as a <handoff> prefix.
func (h HandoffArtifact) JSON() string {
	b, err := json.Marshal(h)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// toolResultIsError reports whether a tool_result block is flagged as
// an error. The SDK's IsError is a param.Opt[bool] with a Valid() /
// Value pair; the helper centralises the access pattern so callers
// don't reach into SDK internals.
func toolResultIsError(tr *anthropic.ToolResultBlockParam) bool {
	if tr == nil {
		return false
	}
	return tr.IsError.Valid() && tr.IsError.Value
}

// extractBlocked tries to parse a ToolError JSON body out of the
// failed tool_result text. Falls back to a free-form Message when the
// payload isn't structured — keeps older (pre-P1-18) sessions
// readable.
func extractBlocked(toolName, rawResult string) HandoffBlocked {
	// Quick sniff: if the payload doesn't start with "{" it's free-form.
	trimmed := strings.TrimSpace(rawResult)
	if !strings.HasPrefix(trimmed, "{") {
		return HandoffBlocked{Tool: toolName, Message: truncatePreview(trimmed, 200)}
	}
	var te ToolError
	if err := json.Unmarshal([]byte(trimmed), &te); err == nil && te.Code != "" {
		return HandoffBlocked{Tool: toolName, Code: te.Code, Message: truncatePreview(te.Message, 200)}
	}
	return HandoffBlocked{Tool: toolName, Message: truncatePreview(trimmed, 200)}
}

// truncatePreview cuts s to n bytes, using "…" to mark the boundary.
// Distinct from the ToolError excerpt helper because previews prefer
// the head (first sentence of tool output usually carries the useful
// summary), whereas error excerpts prefer the tail. UTF-8-safe: backs
// off the head boundary to the nearest rune start so we never split
// a multi-byte character on the way out.
func truncatePreview(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	// Walk backwards from n while we're sitting inside a
	// continuation-byte run (10xxxxxx). Keeps the head clean at the
	// cost of at most 3 bytes of slack.
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}
