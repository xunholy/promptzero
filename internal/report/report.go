// Package report renders engagement reports from PromptZero session
// audit data. A report aggregates:
//
//   - timeline of tool invocations with timestamps and durations
//   - per-risk-tier counts (low / medium / high / critical)
//   - MITRE ATT&CK coverage heatmap — computed via internal/attack
//   - aggregate success / failure / confirmation-denied totals
//   - session metadata (id, span, tool count)
//
// Output is Markdown by default — small, portable, and readable both
// in the terminal and rendered in a GitHub / Obsidian / Notion pane.
// Future formats (HTML, PDF) can be added as new Renderer
// implementations without changing the session-summary math in
// Summarise.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/attack"
	"github.com/xunholy/promptzero/internal/audit"
)

// jsonUnmarshal is a package-private alias so jsonUnmarshalVerdict
// can depend on encoding/json without re-importing it across files
// of this package.
var jsonUnmarshal = json.Unmarshal

// Summary is the intermediate, format-agnostic aggregate of a session's
// activity. Renderer implementations consume Summary to produce concrete
// output bytes; tests exercise Summarise independently of rendering.
type Summary struct {
	SessionID string
	StartedAt time.Time
	EndedAt   time.Time

	// Counts, populated by walking the audit entries.
	TotalEntries int
	BySuccess    map[bool]int   // true=success, false=failure
	ByRisk       map[string]int // "low" / "medium" / "high" / "critical" / ""
	ByLevel      map[audit.Level]int
	ByTool       map[string]int

	// ATT&CK coverage. Each technique ID maps to the number of tool
	// invocations that contributed to it.
	ATTACKCoverage map[string]int

	// DetectorVerdicts groups the verdicts the DetectorEngine
	// emitted during the session. Extracted from each audit entry's
	// Output by matching the <detector-verdict>{...}</detector-verdict>
	// block appended by appendDetectorVerdicts. Keyed by detector
	// name for heatmap display.
	DetectorVerdicts []DetectorVerdictSummary

	// Timeline is the chronologically ordered entry list. Callers that
	// only want the summary counts can ignore this; the markdown
	// renderer uses it for the timeline section.
	Timeline []audit.Entry

	// TotalDuration sums all entry.Duration fields (in milliseconds).
	// Gives the report a "hands-on" time estimate distinct from
	// StartedAt/EndedAt which span idle periods too.
	TotalDurationMs int64
}

// DetectorVerdictSummary is one detector's verdict attached to one
// tool invocation, flattened for report rendering. Auxiliary fields
// (confidence, evidence) are kept so the Markdown renderer can
// explain why a verdict landed the way it did.
type DetectorVerdictSummary struct {
	Tool       string  `json:"tool"`
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	DetectedBy string  `json:"detected_by"`
	Evidence   string  `json:"evidence,omitempty"`
}

// Summarise folds a slice of audit entries into a Summary. Entries
// need not be sorted on input; the summary sorts the timeline by
// timestamp. sessionID is carried through verbatim so callers whose
// entries came from a Filter don't have to re-stamp them.
func Summarise(sessionID string, entries []audit.Entry, idx *attack.Index) Summary {
	s := Summary{
		SessionID:      sessionID,
		BySuccess:      map[bool]int{},
		ByRisk:         map[string]int{},
		ByLevel:        map[audit.Level]int{},
		ByTool:         map[string]int{},
		ATTACKCoverage: map[string]int{},
	}
	if len(entries) == 0 {
		return s
	}

	sorted := make([]audit.Entry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	s.StartedAt = sorted[0].Timestamp
	s.EndedAt = sorted[len(sorted)-1].Timestamp
	s.Timeline = sorted
	s.TotalEntries = len(sorted)

	for _, e := range sorted {
		s.BySuccess[e.Success]++
		s.ByRisk[e.Risk]++
		s.ByLevel[e.Level]++
		s.ByTool[e.Tool]++
		s.TotalDurationMs += e.Duration
		if idx != nil {
			for _, tid := range idx.TechniquesForTool(e.Tool) {
				s.ATTACKCoverage[tid]++
			}
		}
		// Detector verdicts piggyback inside the tool output as
		// <detector-verdict>{json}</detector-verdict> blocks (see
		// internal/agent/detectors.go). Extract them and flatten
		// into the summary so the renderer can surface them.
		for _, v := range extractVerdicts(e.Output) {
			s.DetectorVerdicts = append(s.DetectorVerdicts, DetectorVerdictSummary{
				Tool:       e.Tool,
				Verdict:    v.Verdict,
				Confidence: v.Confidence,
				DetectedBy: v.DetectedBy,
				Evidence:   v.Evidence,
			})
		}
	}
	return s
}

// extractVerdicts pulls every <detector-verdict>{...}</detector-verdict>
// payload out of an audit entry's output string. Multiple verdicts
// per output are supported (multi-detector on a single tool).
// Malformed blocks are skipped — detector output is advisory, never
// load-bearing.
func extractVerdicts(output string) []rulesVerdictShape {
	if !strings.Contains(output, "<detector-verdict>") {
		return nil
	}
	const openTag = "<detector-verdict>"
	const closeTag = "</detector-verdict>"
	var out []rulesVerdictShape
	s := output
	for {
		i := strings.Index(s, openTag)
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], closeTag)
		if j < 0 {
			break
		}
		body := s[i+len(openTag) : i+j]
		var v rulesVerdictShape
		if err := jsonUnmarshalVerdict(body, &v); err == nil && v.Verdict != "" {
			out = append(out, v)
		}
		s = s[i+j+len(closeTag):]
	}
	return out
}

// rulesVerdictShape mirrors rules.Verdict without importing the rules
// package — report stays dependency-light. Kept private to this
// package so the rules package remains the sole source of truth for
// the wire shape.
type rulesVerdictShape struct {
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	DetectedBy string  `json:"detected_by"`
	Evidence   string  `json:"evidence"`
}

// jsonUnmarshalVerdict is a shim around encoding/json specialised to
// the verdict shape. Extracted so tests can fuzz it without an
// encoding/json import dance.
func jsonUnmarshalVerdict(s string, v *rulesVerdictShape) error {
	return jsonUnmarshal([]byte(s), v)
}

// Renderer turns a Summary into concrete output bytes. Additional
// implementations (HTML, PDF, JSON) can plug in by satisfying the
// same interface — Summarise is the shared input contract.
type Renderer interface {
	Render(s Summary) ([]byte, error)
}

// MarkdownRenderer emits a GFM-compatible markdown report. Zero-value
// is usable; no configuration surface today.
type MarkdownRenderer struct{}

// JSONRenderer emits a structured JSON dump of the Summary suitable
// for downstream tooling — engagement-tracking systems, custom
// dashboards, programmatic verification of session contents. Pretty-
// printed with two-space indent so the output is human-readable as
// well. Zero-value is usable.
type JSONRenderer struct{}

// jsonSummary mirrors Summary but rewrites the boolean-keyed map
// (BySuccess) into a struct so the encoder accepts it. Keeps the
// in-memory Summary shape unchanged.
type jsonSummary struct {
	SessionID        string                   `json:"session_id"`
	StartedAt        time.Time                `json:"started_at,omitempty"`
	EndedAt          time.Time                `json:"ended_at,omitempty"`
	TotalEntries     int                      `json:"total_entries"`
	Success          int                      `json:"success_count"`
	Failure          int                      `json:"failure_count"`
	ByRisk           map[string]int           `json:"by_risk,omitempty"`
	ByLevel          map[audit.Level]int      `json:"by_level,omitempty"`
	ByTool           map[string]int           `json:"by_tool,omitempty"`
	ATTACKCoverage   map[string]int           `json:"attack_coverage,omitempty"`
	DetectorVerdicts []DetectorVerdictSummary `json:"detector_verdicts,omitempty"`
	TotalDurationMs  int64                    `json:"total_duration_ms"`
}

// Render implements Renderer for JSONRenderer.
func (JSONRenderer) Render(s Summary) ([]byte, error) {
	js := jsonSummary{
		SessionID:        s.SessionID,
		StartedAt:        s.StartedAt,
		EndedAt:          s.EndedAt,
		TotalEntries:     s.TotalEntries,
		Success:          s.BySuccess[true],
		Failure:          s.BySuccess[false],
		ByRisk:           s.ByRisk,
		ByLevel:          s.ByLevel,
		ByTool:           s.ByTool,
		ATTACKCoverage:   s.ATTACKCoverage,
		DetectorVerdicts: s.DetectorVerdicts,
		TotalDurationMs:  s.TotalDurationMs,
	}
	return json.MarshalIndent(js, "", "  ")
}

// Render implements Renderer.
func (MarkdownRenderer) Render(s Summary) ([]byte, error) {
	var b strings.Builder

	fmt.Fprintf(&b, "# PromptZero Session Report\n\n")
	fmt.Fprintf(&b, "**Session ID:** `%s`  \n", mdEscape(s.SessionID))
	if !s.StartedAt.IsZero() {
		fmt.Fprintf(&b, "**Span:** %s → %s  \n",
			s.StartedAt.UTC().Format(time.RFC3339),
			s.EndedAt.UTC().Format(time.RFC3339),
		)
		fmt.Fprintf(&b, "**Wall time:** %s  \n", s.EndedAt.Sub(s.StartedAt).Round(time.Second))
	}
	fmt.Fprintf(&b, "**Hands-on time:** %s  \n",
		time.Duration(s.TotalDurationMs)*time.Millisecond)
	fmt.Fprintf(&b, "**Total tool invocations:** %d\n\n", s.TotalEntries)

	if s.TotalEntries == 0 {
		fmt.Fprintf(&b, "_No audit entries recorded in this session._\n")
		return []byte(b.String()), nil
	}

	// Risk-tier summary.
	fmt.Fprintf(&b, "## Risk tier breakdown\n\n")
	for _, tier := range []string{"critical", "high", "medium", "low"} {
		if n, ok := s.ByRisk[tier]; ok && n > 0 {
			fmt.Fprintf(&b, "- **%s:** %d\n", tier, n)
		}
	}
	if untiered, ok := s.ByRisk[""]; ok && untiered > 0 {
		fmt.Fprintf(&b, "- _unclassified:_ %d\n", untiered)
	}
	fmt.Fprintf(&b, "\n")

	// Success / failure.
	success := s.BySuccess[true]
	failure := s.BySuccess[false]
	fmt.Fprintf(&b, "## Outcomes\n\n")
	fmt.Fprintf(&b, "- ✓ success: %d\n- ✗ failure: %d\n\n", success, failure)

	// Top tools used.
	fmt.Fprintf(&b, "## Tool usage\n\n")
	type toolCount struct {
		name string
		n    int
	}
	tools := make([]toolCount, 0, len(s.ByTool))
	for n, c := range s.ByTool {
		tools = append(tools, toolCount{name: n, n: c})
	}
	sort.Slice(tools, func(i, j int) bool {
		if tools[i].n != tools[j].n {
			return tools[i].n > tools[j].n
		}
		return tools[i].name < tools[j].name
	})
	fmt.Fprintf(&b, "| Tool | Invocations |\n|---|---|\n")
	for _, tc := range tools {
		fmt.Fprintf(&b, "| `%s` | %d |\n", mdEscape(tc.name), tc.n)
	}
	fmt.Fprintf(&b, "\n")

	// ATT&CK coverage. v0.21.0 adds a visual heatmap alongside the
	// table — a bar chart of relative technique frequency makes
	// "what we did the most of" jump out of the report at a glance.
	if len(s.ATTACKCoverage) > 0 {
		fmt.Fprintf(&b, "## MITRE ATT&CK coverage\n\n")
		ids := make([]string, 0, len(s.ATTACKCoverage))
		max := 0
		for id, n := range s.ATTACKCoverage {
			ids = append(ids, id)
			if n > max {
				max = n
			}
		}
		sort.Slice(ids, func(i, j int) bool {
			if s.ATTACKCoverage[ids[i]] != s.ATTACKCoverage[ids[j]] {
				return s.ATTACKCoverage[ids[i]] > s.ATTACKCoverage[ids[j]]
			}
			return ids[i] < ids[j]
		})
		fmt.Fprintf(&b, "| Technique | Count | Frequency |\n|---|---|---|\n")
		for _, id := range ids {
			n := s.ATTACKCoverage[id]
			bar := heatmapBar(n, max, 20)
			fmt.Fprintf(&b, "| [`%s`](https://attack.mitre.org/techniques/%s/) | %d | `%s` |\n",
				id, mitreSlug(id), n, bar)
		}
		fmt.Fprintf(&b, "\n")
	}

	// Detector verdicts section — surfaces the rules engine's
	// LLM-as-judge output. Grouped by verdict class (failure +
	// suspicious first since those need operator attention; success
	// + unknown last).
	if len(s.DetectorVerdicts) > 0 {
		fmt.Fprintf(&b, "## Detector verdicts\n\n")
		fmt.Fprintf(&b, "| Tool | Verdict | Confidence | Detector | Evidence |\n|---|---|---|---|---|\n")
		// Stable ordering: failures / suspicious first, then success,
		// then unknown. Inside each bucket preserve timeline order.
		order := map[string]int{"failure": 0, "suspicious": 1, "success": 2, "unknown": 3}
		sorted := make([]DetectorVerdictSummary, len(s.DetectorVerdicts))
		copy(sorted, s.DetectorVerdicts)
		sort.SliceStable(sorted, func(i, j int) bool {
			return order[sorted[i].Verdict] < order[sorted[j].Verdict]
		})
		for _, v := range sorted {
			fmt.Fprintf(&b, "| `%s` | **%s** | %.2f | `%s` | %s |\n",
				mdEscape(v.Tool),
				mdEscape(v.Verdict),
				v.Confidence,
				mdEscape(v.DetectedBy),
				mdEscape(shortEvidence(v.Evidence)),
			)
		}
		fmt.Fprintf(&b, "\n")
	}

	// Timeline (compact — one line per entry).
	fmt.Fprintf(&b, "## Timeline\n\n")
	for _, e := range s.Timeline {
		marker := "✓"
		if !e.Success {
			marker = "✗"
		}
		fmt.Fprintf(&b, "- `%s` %s **%s** _(risk: %s)_ — %dms\n",
			e.Timestamp.UTC().Format("15:04:05"),
			marker,
			mdEscape(e.Tool),
			mdEscape(e.Risk),
			e.Duration,
		)
	}
	fmt.Fprintf(&b, "\n---\n_Generated by PromptZero report._\n")

	return []byte(b.String()), nil
}

// mdEscape escapes the handful of markdown metacharacters that can
// appear in tool names / session ids and confuse a renderer. Keeps
// the implementation small — we're emitting our own content, not
// user-controlled prose.
// heatmapBar renders n out of max as a width-character monospace bar
// using Unicode block fills. width controls the total cell length; the
// filled portion uses '█', the empty portion uses '░' so the column
// stays the same width across all rows. max == 0 returns an empty bar
// (defensive — caller shouldn't call with no data).
func heatmapBar(n, max, width int) string {
	if max <= 0 || width <= 0 {
		return ""
	}
	filled := (n * width) / max
	if filled < 1 && n > 0 {
		filled = 1 // any non-zero count gets at least one cell so it's visible
	}
	if filled > width {
		filled = width
	}
	out := make([]rune, 0, width)
	for i := 0; i < filled; i++ {
		out = append(out, '█')
	}
	for i := filled; i < width; i++ {
		out = append(out, '░')
	}
	return string(out)
}

// mdEscape sanitises a string for embedding in a Markdown table cell.
// Escapes pipe and backtick (table delimiter + inline-code marker) and
// flattens \r\n / \n / \r to a single space — embedded newlines break
// every row in a Markdown table because the renderer reads end-of-line
// as end-of-row. shortEvidence already strips newlines for the
// evidence column; mdEscape now provides the same guarantee for every
// other call site (Tool, Verdict, DetectedBy, Risk) where a multi-line
// payload from a misbehaving tool could otherwise corrupt the report.
func mdEscape(s string) string {
	r := strings.NewReplacer(
		"|", "\\|",
		"`", "\\`",
		"\r\n", " ",
		"\n", " ",
		"\r", " ",
	)
	return r.Replace(s)
}

// mitreSlug normalises an ATT&CK technique ID into the URL slug MITRE
// uses: "T1557.004" -> "T1557/004". Used for heatmap deep-links.
func mitreSlug(id string) string {
	return strings.Replace(id, ".", "/", 1)
}

// shortEvidence truncates a verdict's evidence string to a single
// short clause so the detector-verdict table stays readable. Keeps
// the first sentence up to 120 characters.
func shortEvidence(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		s = s[:117] + "…"
	}
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
