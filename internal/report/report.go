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
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/attack"
	"github.com/xunholy/promptzero/internal/audit"
)

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

	// Timeline is the chronologically ordered entry list. Callers that
	// only want the summary counts can ignore this; the markdown
	// renderer uses it for the timeline section.
	Timeline []audit.Entry

	// TotalDuration sums all entry.Duration fields (in milliseconds).
	// Gives the report a "hands-on" time estimate distinct from
	// StartedAt/EndedAt which span idle periods too.
	TotalDurationMs int64
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
	}
	return s
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

	// ATT&CK coverage.
	if len(s.ATTACKCoverage) > 0 {
		fmt.Fprintf(&b, "## MITRE ATT&CK coverage\n\n")
		fmt.Fprintf(&b, "| Technique | Count |\n|---|---|\n")
		ids := make([]string, 0, len(s.ATTACKCoverage))
		for id := range s.ATTACKCoverage {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Fprintf(&b, "| [`%s`](https://attack.mitre.org/techniques/%s/) | %d |\n",
				id, mitreSlug(id), s.ATTACKCoverage[id])
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
func mdEscape(s string) string {
	r := strings.NewReplacer("|", "\\|", "`", "\\`")
	return r.Replace(s)
}

// mitreSlug normalises an ATT&CK technique ID into the URL slug MITRE
// uses: "T1557.004" -> "T1557/004". Used for heatmap deep-links.
func mitreSlug(id string) string {
	return strings.Replace(id, ".", "/", 1)
}
