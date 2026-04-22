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
