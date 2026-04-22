// Package trainset exports the audit log as a fine-tuning dataset.
// Each exported record captures one tool call — the tool name,
// parameters the model chose, observed output, success/risk labels,
// and ATT&CK technique tags — in a JSONL format compatible with the
// common training pipelines (Hugging Face Datasets, OpenAI fine-tune,
// LoRA/QLoRA toolkits).
//
// Two output formats are supported:
//
//   - FormatJSONL (default): one JSON object per line carrying the
//     raw tool-call shape. Cheapest to produce and easiest to filter
//     downstream. Use when you want to run your own templating.
//
//   - FormatChat: the OpenAI "messages" conversation format. Each
//     row becomes a 3-message chat (system → user → assistant) where
//     the assistant message embeds the tool call and its observed
//     output. Use when the training pipeline consumes chat
//     transcripts directly.
//
// The package is intentionally decoupled from the live audit.Log
// interface (take a slice of Entries, return writes on an io.Writer)
// so CLI commands, ad-hoc scripts, and future fine-tuning harnesses
// can all share the same serialisation rules.
package trainset

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/xunholy/promptzero/internal/audit"
)

// Format selects the output serialisation.
type Format string

const (
	FormatJSONL Format = "jsonl"
	FormatChat  Format = "chat"
)

// Options controls the export.
type Options struct {
	// Format is the output serialisation. Empty defaults to JSONL.
	Format Format

	// SuccessOnly filters out entries where Success==false. The
	// default (false) exports everything — failed calls still carry
	// training signal, especially for reflexion-style fine-tunes.
	SuccessOnly bool

	// MinLevel drops entries below this risk level. Empty = no filter.
	// Useful for producing datasets focused on critical/high-risk
	// behaviours without the noise of low-risk read-only calls.
	MinLevel audit.Level

	// SystemPrompt is the chat-format system message. Ignored for
	// JSONL. When empty, a sensible default is used.
	SystemPrompt string
}

// Record is the JSONL-format row. Fields mirror audit.Entry but
// omit internal bookkeeping (DB row ID, lock state).
type Record struct {
	Timestamp    time.Time       `json:"timestamp"`
	Tool         string          `json:"tool"`
	Input        json.RawMessage `json:"input"`
	Output       string          `json:"output"`
	Success      bool            `json:"success"`
	Risk         string          `json:"risk"`
	Level        string          `json:"level"`
	Duration     int64           `json:"duration_ms"`
	TechniqueIDs []string        `json:"technique_ids,omitempty"`
	SessionID    string          `json:"session_id,omitempty"`
}

// ChatMessage is one message in the OpenAI chat format.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRow is one JSONL row when Format=FormatChat.
type ChatRow struct {
	Messages []ChatMessage  `json:"messages"`
	Meta     map[string]any `json:"meta,omitempty"`
}

const defaultChatSystemPrompt = "You are PromptZero, a hardware-pentest CLI agent. When the operator describes a goal, select a tool and produce its JSON arguments."

// knownLevels enumerates the audit.Level values Export recognises.
// Extracted so Validate and levelAtLeast share one source of truth.
var knownLevels = map[audit.Level]int{
	audit.LevelInfo:     1,
	audit.LevelAction:   2,
	audit.LevelWarning:  3,
	audit.LevelCritical: 4,
}

// Export writes each filtered entry to w according to opts.Format.
// Returns the number of rows emitted and the first write/encode error.
// An unknown opts.MinLevel is rejected upfront rather than silently
// failing open — a typo like --min-level=warnig must not quietly drop
// the filter.
func Export(entries []audit.Entry, w io.Writer, opts Options) (int, error) {
	if opts.Format == "" {
		opts.Format = FormatJSONL
	}
	if opts.MinLevel != "" {
		if _, ok := knownLevels[opts.MinLevel]; !ok {
			return 0, fmt.Errorf("unknown min_level %q (valid: info, action, warning, critical)", opts.MinLevel)
		}
	}
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	enc := json.NewEncoder(bw)
	var count int
	for _, e := range entries {
		if !keep(e, opts) {
			continue
		}
		switch opts.Format {
		case FormatJSONL:
			rec := toRecord(e)
			if err := enc.Encode(rec); err != nil {
				return count, fmt.Errorf("encode jsonl row %d: %w", count, err)
			}
		case FormatChat:
			row := toChatRow(e, opts.SystemPrompt)
			if err := enc.Encode(row); err != nil {
				return count, fmt.Errorf("encode chat row %d: %w", count, err)
			}
		default:
			return count, fmt.Errorf("unknown format: %s", opts.Format)
		}
		count++
	}
	return count, nil
}

func keep(e audit.Entry, opts Options) bool {
	if opts.SuccessOnly && !e.Success {
		return false
	}
	if opts.MinLevel != "" && !levelAtLeast(e.Level, opts.MinLevel) {
		return false
	}
	return true
}

// levelAtLeast reports whether got is at least want in the audit.Level
// ordering. Unknown got is treated as below every known want so a
// malformed DB row can't accidentally leak through a MinLevel filter
// (want is validated in Export before we get here).
func levelAtLeast(got, want audit.Level) bool {
	gotRank, gotOk := knownLevels[got]
	if !gotOk {
		return false
	}
	return gotRank >= knownLevels[want]
}

func toRecord(e audit.Entry) Record {
	input := json.RawMessage(e.Input)
	if len(input) == 0 || !json.Valid(input) {
		// Fallback: wrap the raw string so the row is still valid JSON.
		b, _ := json.Marshal(e.Input)
		input = b
	}
	return Record{
		Timestamp:    e.Timestamp,
		Tool:         e.Tool,
		Input:        input,
		Output:       e.Output,
		Success:      e.Success,
		Risk:         e.Risk,
		Level:        string(e.Level),
		Duration:     e.Duration,
		TechniqueIDs: e.TechniqueIDs,
		SessionID:    e.SessionID,
	}
}

func toChatRow(e audit.Entry, systemPrompt string) ChatRow {
	if systemPrompt == "" {
		systemPrompt = defaultChatSystemPrompt
	}
	// User role: a short directive describing the goal. Audit entries
	// don't preserve the natural-language user turn, so synthesise a
	// minimal one from the tool + risk framing. Downstream users who
	// want real user turns can join on session transcripts.
	user := fmt.Sprintf("Execute %s (risk=%s).", e.Tool, e.Risk)
	// Assistant role: the tool_use+tool_result paired as compact JSON.
	assistant := fmt.Sprintf("```json\n{\"tool\": %q, \"input\": %s}\n```\nResult: %s",
		e.Tool, e.Input, e.Output)
	return ChatRow{
		Messages: []ChatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: user},
			{Role: "assistant", Content: assistant},
		},
		Meta: map[string]any{
			"tool":          e.Tool,
			"success":       e.Success,
			"level":         string(e.Level),
			"technique_ids": e.TechniqueIDs,
		},
	}
}
