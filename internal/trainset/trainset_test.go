package trainset

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/audit"
)

func sampleEntries() []audit.Entry {
	return []audit.Entry{
		{
			ID:           1,
			Timestamp:    time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC),
			Tool:         "wifi_scan_ap",
			Input:        `{"duration":30}`,
			Output:       `{"aps":3}`,
			Risk:         "Low",
			Level:        audit.LevelInfo,
			SessionID:    "s1",
			Duration:     120,
			Success:      true,
			TechniqueIDs: []string{"T1040"},
		},
		{
			ID:        2,
			Timestamp: time.Date(2026, 4, 22, 10, 1, 0, 0, time.UTC),
			Tool:      "wifi_deauth",
			Input:     `{"bssid":"aa:bb:cc:dd:ee:ff"}`,
			Output:    `{"ack_frames":23}`,
			Risk:      "High",
			Level:     audit.LevelCritical,
			SessionID: "s1",
			Duration:  10000,
			Success:   true,
		},
		{
			ID:        3,
			Timestamp: time.Date(2026, 4, 22, 10, 2, 0, 0, time.UTC),
			Tool:      "subghz_transmit",
			Input:     `{"file":"/ext/subghz/x.sub"}`,
			Output:    "transmission failed: no radio",
			Risk:      "Medium",
			Level:     audit.LevelWarning,
			Success:   false,
		},
	}
}

// TestExport_SinceFilter pins the P3-32 "since" filter behaviour:
// entries strictly before the cutoff are dropped; entries at or after
// it survive. Date-only input anchors at midnight UTC.
func TestExport_SinceFilter(t *testing.T) {
	entries := []audit.Entry{
		{Tool: "early", Timestamp: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC), Input: `{}`, Level: audit.LevelInfo},
		{Tool: "boundary", Timestamp: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), Input: `{}`, Level: audit.LevelInfo},
		{Tool: "after", Timestamp: time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC), Input: `{}`, Level: audit.LevelInfo},
	}
	cutoff, err := ParseSince("2026-04-01")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	n, err := Export(entries, &buf, Options{Since: cutoff})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if n != 2 {
		t.Errorf("rows = %d, want 2 (boundary + after)", n)
	}
	if !strings.Contains(buf.String(), `"tool":"boundary"`) {
		t.Error("boundary entry should survive the cutoff")
	}
	if strings.Contains(buf.String(), `"tool":"early"`) {
		t.Error("early entry should be dropped")
	}
}

func TestExport_PersonaVersionFilter(t *testing.T) {
	entries := []audit.Entry{
		{Tool: "v1tool", PersonaVersion: "1.0.0", Input: `{}`, Level: audit.LevelInfo, Timestamp: time.Now()},
		{Tool: "v2tool", PersonaVersion: "2.0.0", Input: `{}`, Level: audit.LevelInfo, Timestamp: time.Now()},
		{Tool: "noversion", PersonaVersion: "", Input: `{}`, Level: audit.LevelInfo, Timestamp: time.Now()},
	}
	var buf bytes.Buffer
	n, err := Export(entries, &buf, Options{PersonaVersions: []string{"2.0.0"}})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if n != 1 {
		t.Errorf("rows = %d, want 1 (only v2)", n)
	}
	if !strings.Contains(buf.String(), `"tool":"v2tool"`) {
		t.Errorf("v2tool not in output: %s", buf.String())
	}
}

func TestExport_RecordIncludesPersonaVersionAndPromptHash(t *testing.T) {
	hash := strings.Repeat("a", 64)
	entries := []audit.Entry{{
		Tool:           "x",
		Input:          `{}`,
		Level:          audit.LevelInfo,
		Timestamp:      time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC),
		PersonaVersion: "1.2.3",
		PromptHash:     hash,
	}}
	var buf bytes.Buffer
	if _, err := Export(entries, &buf, Options{}); err != nil {
		t.Fatal(err)
	}
	var rec Record
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("decode JSONL row: %v", err)
	}
	if rec.PersonaVersion != "1.2.3" {
		t.Errorf("PersonaVersion = %q, want 1.2.3", rec.PersonaVersion)
	}
	if rec.PromptHash != hash {
		t.Errorf("PromptHash = %q", rec.PromptHash)
	}
}

func TestExport_ChatMetaIncludesPersonaVersionAndPromptHash(t *testing.T) {
	entries := []audit.Entry{{
		Tool:           "x",
		Input:          `{}`,
		Level:          audit.LevelInfo,
		Timestamp:      time.Now(),
		PersonaVersion: "v9",
		PromptHash:     "deadbeef",
	}}
	var buf bytes.Buffer
	if _, err := Export(entries, &buf, Options{Format: FormatChat}); err != nil {
		t.Fatal(err)
	}
	var row ChatRow
	if err := json.Unmarshal(buf.Bytes(), &row); err != nil {
		t.Fatalf("decode chat row: %v", err)
	}
	if got := row.Meta["persona_version"]; got != "v9" {
		t.Errorf("Meta.persona_version = %v, want v9", got)
	}
	if got := row.Meta["prompt_hash"]; got != "deadbeef" {
		t.Errorf("Meta.prompt_hash = %v", got)
	}
}

func TestParseSince(t *testing.T) {
	cases := []struct {
		in       string
		wantZero bool
		wantErr  bool
		want     time.Time
	}{
		{in: "", wantZero: true},
		{in: "   ", wantZero: true},
		{in: "2026-04-01", want: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)},
		{in: "2026-04-01T15:30:00Z", want: time.Date(2026, 4, 1, 15, 30, 0, 0, time.UTC)},
		{in: "garbage", wantErr: true},
		{in: "2026-13-99", wantErr: true},
	}
	for _, tc := range cases {
		got, err := ParseSince(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseSince(%q): expected error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSince(%q): unexpected error %v", tc.in, err)
			continue
		}
		if tc.wantZero {
			if !got.IsZero() {
				t.Errorf("ParseSince(%q) = %v, want zero", tc.in, got)
			}
			continue
		}
		if !got.Equal(tc.want) {
			t.Errorf("ParseSince(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestExport_JSONLDefault(t *testing.T) {
	var buf bytes.Buffer
	n, err := Export(sampleEntries(), &buf, Options{})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if n != 3 {
		t.Errorf("emitted rows = %d, want 3", n)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("line count = %d, want 3", len(lines))
	}
	var first Record
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("first row not valid JSON: %v", err)
	}
	if first.Tool != "wifi_scan_ap" {
		t.Errorf("Tool = %q", first.Tool)
	}
	// Input must round-trip as a JSON object, not a quoted string.
	var inputObj map[string]any
	if err := json.Unmarshal(first.Input, &inputObj); err != nil {
		t.Errorf("Input not object-shaped: %v (%s)", err, first.Input)
	}
	if inputObj["duration"] == nil {
		t.Errorf("Input missing duration: %v", inputObj)
	}
}

func TestExport_SuccessOnlyDropsFailures(t *testing.T) {
	var buf bytes.Buffer
	n, err := Export(sampleEntries(), &buf, Options{SuccessOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("success-only rows = %d, want 2", n)
	}
	if strings.Contains(buf.String(), "subghz_transmit") {
		t.Error("failed entry leaked past SuccessOnly")
	}
}

func TestExport_MinLevelFilters(t *testing.T) {
	var buf bytes.Buffer
	n, err := Export(sampleEntries(), &buf, Options{MinLevel: audit.LevelCritical})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("critical-only rows = %d, want 1", n)
	}
	if !strings.Contains(buf.String(), "wifi_deauth") {
		t.Error("critical entry missing from export")
	}
}

func TestExport_ChatFormatWrapsInMessages(t *testing.T) {
	var buf bytes.Buffer
	n, err := Export(sampleEntries(), &buf, Options{Format: FormatChat})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("chat rows = %d, want 3", n)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	var row ChatRow
	if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
		t.Fatalf("chat row not valid JSON: %v", err)
	}
	if len(row.Messages) != 3 {
		t.Errorf("messages = %d, want 3 (system+user+assistant)", len(row.Messages))
	}
	roles := []string{row.Messages[0].Role, row.Messages[1].Role, row.Messages[2].Role}
	for i, want := range []string{"system", "user", "assistant"} {
		if roles[i] != want {
			t.Errorf("messages[%d].Role = %q, want %q", i, roles[i], want)
		}
	}
	if !strings.Contains(row.Messages[2].Content, "wifi_scan_ap") {
		t.Errorf("assistant message missing tool name: %q", row.Messages[2].Content)
	}
	if row.Meta["tool"] != "wifi_scan_ap" {
		t.Errorf("meta.tool = %v", row.Meta["tool"])
	}
}

func TestExport_ChatUsesCustomSystemPrompt(t *testing.T) {
	var buf bytes.Buffer
	_, err := Export(sampleEntries()[:1], &buf, Options{Format: FormatChat, SystemPrompt: "CUSTOM"})
	if err != nil {
		t.Fatal(err)
	}
	var row ChatRow
	_ = json.Unmarshal(bytes.TrimRight(buf.Bytes(), "\n"), &row)
	if row.Messages[0].Content != "CUSTOM" {
		t.Errorf("system prompt = %q, want CUSTOM", row.Messages[0].Content)
	}
}

// TestExport_ChatAssistantInnerJSONValid pins the v0.153 contract:
// the `{"tool":..., "input":...}` JSON embedded inside the assistant
// message's markdown fence must be valid JSON regardless of what
// bytes the e.Tool field contains. Pre-fix the assistant was built
// via fmt.Sprintf("...%q...", e.Tool, ...) — strconv.Quote semantics
// — and an audit row with a tool name containing a BEL byte (\x07)
// produced inner JSON with `\a` that downstream parsers reject.
// Tool names never normally carry control bytes, but defense in
// depth: an attacker who can write directly to the audit DB (or a
// future federated-tool name escape) shouldn't be able to corrupt
// the exported training set.
func TestExport_ChatAssistantInnerJSONValid(t *testing.T) {
	// Stage an audit entry with a hostile tool name carrying every
	// JSON-invalid control byte the v0.150-v0.152 arc cared about.
	entries := []audit.Entry{{
		Tool:   "wifi\x07scan\x0Bap\x00",
		Input:  `{"duration":30}`,
		Output: "ok",
		Risk:   "Low",
		Level:  audit.LevelInfo,
	}}
	var buf bytes.Buffer
	if _, err := Export(entries, &buf, Options{Format: FormatChat}); err != nil {
		t.Fatal(err)
	}
	var row ChatRow
	if err := json.Unmarshal(bytes.TrimRight(buf.Bytes(), "\n"), &row); err != nil {
		t.Fatalf("outer chat row not valid JSON: %v", err)
	}
	content := row.Messages[2].Content
	// Extract the JSON between the ```json ... ``` fence.
	const fenceOpen = "```json\n"
	const fenceClose = "\n```"
	openIdx := strings.Index(content, fenceOpen)
	closeIdx := strings.Index(content, fenceClose)
	if openIdx < 0 || closeIdx < 0 || closeIdx <= openIdx {
		t.Fatalf("expected markdown fence in assistant content: %q", content)
	}
	inner := content[openIdx+len(fenceOpen) : closeIdx]
	var parsed map[string]any
	if err := json.Unmarshal([]byte(inner), &parsed); err != nil {
		t.Fatalf("inner JSON inside markdown fence is not valid: %v\ninner=%q", err, inner)
	}
	if _, hasTool := parsed["tool"]; !hasTool {
		t.Errorf("inner JSON missing tool field: %v", parsed)
	}
}

// TestExport_ChatAssistantHandlesEmptyInput pins the fallback path:
// when e.Input is empty (COALESCE NULL → "") or otherwise not valid
// JSON, the inner envelope still parses with input=null.
func TestExport_ChatAssistantHandlesEmptyInput(t *testing.T) {
	entries := []audit.Entry{{
		Tool:   "x",
		Input:  "", // simulate the legacy/NULL path
		Output: "ok",
		Level:  audit.LevelInfo,
	}}
	var buf bytes.Buffer
	if _, err := Export(entries, &buf, Options{Format: FormatChat}); err != nil {
		t.Fatal(err)
	}
	var row ChatRow
	_ = json.Unmarshal(bytes.TrimRight(buf.Bytes(), "\n"), &row)
	content := row.Messages[2].Content
	if !strings.Contains(content, `"input":null`) {
		t.Errorf("expected input:null fallback in assistant content; got %q", content)
	}
}

func TestExport_UnknownFormatErrors(t *testing.T) {
	var buf bytes.Buffer
	_, err := Export(sampleEntries()[:1], &buf, Options{Format: "invalid"})
	if err == nil {
		t.Error("unknown format should error")
	}
}

func TestExport_EmptyInputStillValidJSON(t *testing.T) {
	// Audit rows from older DBs may carry Input as an unwrapped string
	// that isn't itself valid JSON. toRecord must still produce a row
	// whose Input field round-trips.
	entries := []audit.Entry{{
		Tool:    "x",
		Input:   "raw string not json",
		Output:  "ok",
		Level:   audit.LevelInfo,
		Success: true,
	}}
	var buf bytes.Buffer
	_, err := Export(entries, &buf, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var rec Record
	if err := json.Unmarshal(bytes.TrimRight(buf.Bytes(), "\n"), &rec); err != nil {
		t.Fatalf("row not valid JSON: %v (%s)", err, buf.String())
	}
	var s string
	if err := json.Unmarshal(rec.Input, &s); err != nil {
		t.Errorf("Input fallback not a quoted string: %s", rec.Input)
	}
	if s != "raw string not json" {
		t.Errorf("Input roundtrip = %q", s)
	}
}

// failingWriter returns the configured error after `goodBytes` bytes
// have been written. Models a destination whose final flush fails
// (e.g. ENOSPC mid-flush, fsync error on a network FS).
type failingWriter struct {
	written   int
	goodBytes int
	err       error
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.written+len(p) > f.goodBytes {
		// Accept whatever fits before the failure point, then fail.
		fits := f.goodBytes - f.written
		if fits < 0 {
			fits = 0
		}
		f.written += fits
		return fits, f.err
	}
	f.written += len(p)
	return len(p), nil
}

// TestExport_FlushErrorSurfaced pins the contract: when bufio.Writer's
// final Flush() fails (the underlying writer returns an error after
// rows have been encoded into the buffer), Export must return that
// error instead of silently reporting success with the row count.
// Previously a `defer bw.Flush()` discarded the flush error and
// callers saw "wrote N rows" for half-written exports.
func TestExport_FlushErrorSurfaced(t *testing.T) {
	// Default bufio.Writer buffer is 4 KiB; one sample entry encodes
	// to ~250 bytes of JSONL. Set goodBytes=10 so the buffer holds
	// rows but the eventual Flush hits the failure.
	w := &failingWriter{goodBytes: 10, err: errSimulatedDiskFull}
	_, err := Export(sampleEntries(), w, Options{Format: FormatJSONL})
	if err == nil {
		t.Fatal("Export returned nil error despite Flush failure")
	}
	if !strings.Contains(err.Error(), "flush") {
		t.Errorf("error %q should mention flush", err.Error())
	}
}

var errSimulatedDiskFull = &exportTestError{"simulated ENOSPC"}

type exportTestError struct{ msg string }

func (e *exportTestError) Error() string { return e.msg }

func TestExport_UnknownMinLevelRejected(t *testing.T) {
	// Regression: --min-level=warnig used to silently pass every row
	// because levelAtLeast mapped both unknown got and want to 0,
	// making 0 >= 0 always true. Export now validates up front.
	var buf bytes.Buffer
	_, err := Export(sampleEntries(), &buf, Options{MinLevel: audit.Level("warnig")})
	if err == nil {
		t.Fatal("unknown min_level should error")
	}
	if !strings.Contains(err.Error(), "warnig") {
		t.Errorf("error should echo bad value: %v", err)
	}
}

// TestValidateOptions covers the pre-flight check operators get
// before Export truncates the destination file. Catches typos in
// --format / --min-level so a bad option doesn't zap a valid file.
func TestValidateOptions(t *testing.T) {
	t.Run("zero_value_ok", func(t *testing.T) {
		if err := ValidateOptions(Options{}); err != nil {
			t.Errorf("zero Options should validate: %v", err)
		}
	})
	t.Run("valid_jsonl", func(t *testing.T) {
		if err := ValidateOptions(Options{Format: FormatJSONL}); err != nil {
			t.Errorf("FormatJSONL should validate: %v", err)
		}
	})
	t.Run("valid_chat_with_minlevel", func(t *testing.T) {
		if err := ValidateOptions(Options{Format: FormatChat, MinLevel: audit.LevelWarning}); err != nil {
			t.Errorf("Chat + warning should validate: %v", err)
		}
	})
	t.Run("rejects_unknown_format", func(t *testing.T) {
		err := ValidateOptions(Options{Format: "csv"})
		if err == nil {
			t.Error("Format=csv should error")
		}
	})
	t.Run("rejects_unknown_minlevel", func(t *testing.T) {
		err := ValidateOptions(Options{MinLevel: audit.Level("warnig")})
		if err == nil {
			t.Error("MinLevel=warnig should error")
		}
	})
}

func TestLevelAtLeast_UnknownGotBelowEverything(t *testing.T) {
	if levelAtLeast(audit.Level("bogus"), audit.LevelInfo) {
		t.Error("unknown got should never be >= any known want")
	}
	if !levelAtLeast(audit.LevelCritical, audit.LevelWarning) {
		t.Error("critical should rank above warning")
	}
}

func TestExport_EmptyEntriesWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	n, err := Export(nil, &buf, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("empty input emitted %d rows", n)
	}
	if buf.Len() != 0 {
		t.Errorf("empty input wrote bytes: %q", buf.String())
	}
}
