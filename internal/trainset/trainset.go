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
	"strings"
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

	// Since drops entries with Timestamp strictly before this cutoff.
	// Zero (the default) disables the filter and exports everything.
	// Roadmap P3-32 calls this out explicitly: a `--since <date>`
	// filter so an operator can carve a fine-tune dataset out of the
	// most recent N weeks of audit history without dragging in
	// pre-improvement noise.
	Since time.Time

	// PersonaVersions, when non-empty, restricts the export to entries
	// whose Entry.PersonaVersion is in this set. Pairs with the P3-31
	// versioning work: an operator who fixes a prompt typo bumps
	// PersonaVersion from "1.0.0" → "1.0.1" and exports only the
	// post-fix sessions for fine-tuning. Empty disables the filter.
	PersonaVersions []string
}

// Record is the JSONL-format row. Fields mirror audit.Entry but
// omit internal bookkeeping (DB row ID, lock state). PersonaVersion +
// PromptHash were added with P3-31 so a downstream fine-tune pipeline
// can filter / weight rows by the exact prompt + persona config that
// produced them.
type Record struct {
	Timestamp      time.Time       `json:"timestamp"`
	Tool           string          `json:"tool"`
	Input          json.RawMessage `json:"input"`
	Output         string          `json:"output"`
	Success        bool            `json:"success"`
	Risk           string          `json:"risk"`
	Level          string          `json:"level"`
	Duration       int64           `json:"duration_ms"`
	TechniqueIDs   []string        `json:"technique_ids,omitempty"`
	SessionID      string          `json:"session_id,omitempty"`
	PersonaVersion string          `json:"persona_version,omitempty"`
	PromptHash     string          `json:"prompt_hash,omitempty"`
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

// ValidateOptions checks an Options for shape errors without opening
// the destination file. Callers should run this before truncating
// the output target so a typo in --format or --min-level doesn't zap
// a pre-existing file. Returns nil for valid options including
// empty defaults (Format="" → FormatJSONL inside Export).
func ValidateOptions(opts Options) error {
	if opts.Format != "" && opts.Format != FormatJSONL && opts.Format != FormatChat {
		return fmt.Errorf("unknown format %q (valid: %s, %s)", opts.Format, FormatJSONL, FormatChat)
	}
	if opts.MinLevel != "" {
		if _, ok := knownLevels[opts.MinLevel]; !ok {
			return fmt.Errorf("unknown min_level %q (valid: info, action, warning, critical)", opts.MinLevel)
		}
	}
	return nil
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
	// Explicit Flush at the end (rather than `defer bw.Flush()`) so a
	// final-flush error is surfaced. A deferred ignore would silently
	// truncate the export when the underlying writer fails on the
	// last buffer drain — operators see "wrote N rows" for a
	// half-written file.
	bw := bufio.NewWriter(w)
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
	if err := bw.Flush(); err != nil {
		return count, fmt.Errorf("flush: %w", err)
	}
	return count, nil
}

// ParseSince parses a `--since` flag value into a UTC time.Time.
// Accepts either an ISO-8601 date ("2026-04-01") or a full RFC3339
// timestamp ("2026-04-01T12:00:00Z"). The date-only form anchors at
// midnight UTC — that's what an operator typing "since April 1st"
// almost always means; running with a local-tz cutoff would surprise
// pipelines that consume the JSONL.
//
// Empty input yields a zero time.Time so opts.Since stays disabled,
// which lets the CLI handler treat `--since=` (with an explicit empty
// value) as "no filter" rather than an error.
func ParseSince(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unrecognised date %q (want YYYY-MM-DD or RFC3339)", s)
}

// containsString reports whether s appears in xs. Linear scan; the
// PersonaVersions slice is operator-supplied and tiny (typically 1-3
// entries) so a map allocation isn't worth the per-call overhead.
func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func keep(e audit.Entry, opts Options) bool {
	if opts.SuccessOnly && !e.Success {
		return false
	}
	if opts.MinLevel != "" && !levelAtLeast(e.Level, opts.MinLevel) {
		return false
	}
	if !opts.Since.IsZero() && e.Timestamp.Before(opts.Since) {
		return false
	}
	if len(opts.PersonaVersions) > 0 && !containsString(opts.PersonaVersions, e.PersonaVersion) {
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
		Timestamp:      e.Timestamp,
		Tool:           e.Tool,
		Input:          input,
		Output:         e.Output,
		Success:        e.Success,
		Risk:           e.Risk,
		Level:          string(e.Level),
		Duration:       e.Duration,
		TechniqueIDs:   e.TechniqueIDs,
		SessionID:      e.SessionID,
		PersonaVersion: e.PersonaVersion,
		PromptHash:     e.PromptHash,
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
	// Assistant role: the tool_use+tool_result paired as compact JSON
	// inside a markdown fence. Build the inner JSON via json.Marshal so
	// control bytes in e.Tool (which would otherwise hit Sprintf's
	// `%q` → strconv.Quote and produce Go-string escapes like `\a` /
	// `\v` / `\xNN` invalid in JSON) survive as `\u00NN`. e.Input is
	// already-serialised JSON from the audit Record path; embed it as
	// a json.RawMessage when it parses, else fall back to JSON null so
	// the outer object is always parseable. Same v0.150-v0.152 contract.
	innerInput := json.RawMessage("null")
	if json.Valid([]byte(e.Input)) {
		innerInput = json.RawMessage(e.Input)
	}
	innerJSON, mErr := json.Marshal(map[string]any{
		"tool":  e.Tool,
		"input": innerInput,
	})
	if mErr != nil {
		// json.Marshal of a map[string]any with a string + RawMessage
		// can't actually fail under encoding/json once we've gated on
		// json.Valid, but degrade gracefully to a minimal envelope so
		// the trainset writer always produces a row.
		innerJSON = []byte(`{"tool":"","input":null}`)
	}
	assistant := fmt.Sprintf("```json\n%s\n```\nResult: %s", innerJSON, e.Output)
	return ChatRow{
		Messages: []ChatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: user},
			{Role: "assistant", Content: assistant},
		},
		Meta: map[string]any{
			"tool":            e.Tool,
			"success":         e.Success,
			"level":           string(e.Level),
			"technique_ids":   e.TechniqueIDs,
			"persona_version": e.PersonaVersion,
			"prompt_hash":     e.PromptHash,
		},
	}
}
