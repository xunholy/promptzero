package companion

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MaxDetailLen caps the "detail" string written to the FAP. The
// Flipper OLED at the standard font fits ~21 chars per line; we
// allow a bit more so the FAP can ellipsise to taste at render
// time, but not enough to balloon the JSON payload size.
const MaxDetailLen = 32

// ellipsis is appended in place of truncated suffixes. Three bytes
// in UTF-8 — the truncation helpers below account for that so the
// final string fits inside MaxDetailLen *bytes*, which is what the
// FAP's parser counts when sizing its render buffer.
const ellipsis = "…"

// summaryFields is the priority list of input fields surfaced as
// the one-line "detail" in a Busy event. Mirrors the ordering in
// agent.previewFieldOrder so the screen and the host terminal
// never disagree on which field is "the" point of the action.
var summaryFields = []string{
	"frequency", "freq",
	"protocol",
	"file", "path", "filename",
	"address", "target", "host",
	"command",
	"channel", "ch",
	"target_os",
	"data", "key_hex", "hex",
	"duration_seconds",
}

// SummarizeInput pulls the most operator-relevant field out of a
// tool's JSON input and renders it as a short "key value" string
// suitable for the FAP's detail line. Returns "" when no
// recognised field is present — the caller should fall back to
// just the tool name.
//
// The function never panics on malformed JSON; it returns "" so
// the FAP keeps showing the previous detail rather than flashing
// an error.
func SummarizeInput(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var params map[string]any
	if err := json.Unmarshal(raw, &params); err != nil {
		return ""
	}
	for _, key := range summaryFields {
		v, ok := params[key]
		if !ok {
			continue
		}
		val := formatSummaryValue(key, v)
		if val == "" {
			continue
		}
		out := key + " " + val
		return clip(out, MaxDetailLen)
	}
	return ""
}

// clip truncates s to fit within max *bytes*, appending the
// ellipsis when truncation occurred. Safe for ASCII inputs (the
// only thing the Flipper's font renders cleanly anyway); a
// truncation that lands inside a multi-byte rune is rare in
// practice — tool inputs are paths, hex, frequencies — but
// callers should still avoid feeding multibyte data here.
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - len(ellipsis)
	if cut < 0 {
		cut = 0
	}
	return s[:cut] + ellipsis
}

// formatSummaryValue is the FAP-side equivalent of
// agent.formatPreviewValue. Tighter — every byte that lands on the
// SD status file is one byte the FAP has to parse, so we avoid the
// "Hz (MHz)" double-render and emit a single compact form.
func formatSummaryValue(key string, v any) string {
	switch t := v.(type) {
	case string:
		return clip(strings.TrimSpace(t), MaxDetailLen)
	case float64:
		// Sub-GHz / WiFi 5 GHz frequencies render in MHz.
		if (key == "frequency" || key == "freq") && t > 100_000 {
			return fmt.Sprintf("%.2f MHz", t/1_000_000)
		}
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	case bool:
		return fmt.Sprintf("%t", t)
	default:
		return ""
	}
}
