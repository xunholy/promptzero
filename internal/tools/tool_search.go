// tool_search.go — task-oriented discovery over the tool registry.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/toolsearch"
)

func init() { //nolint:gochecknoinits
	Register(toolSearchSpec)
}

var toolSearchSpec = Spec{ //nolint:gochecknoglobals
	Name:    "tool_search",
	Aliases: []string{"find_tool", "search_tools"},
	Description: "Find the right PromptZero tool for a task by free-text query — the discovery " +
		"layer over the 600+ tool registry. Use when you know WHAT you want to do but not the " +
		"exact tool name: 'garage door', 'wifi password', 'decode an nfc card', 'crack a hash'. " +
		"Returns the top matching tools ranked by relevance, each with its group, risk level and " +
		"a one-line summary, so you can pick the right primitive (and see its risk) before calling " +
		"it. Ranking is deterministic and offline — a weighted token overlap over every tool's " +
		"name / aliases / group / description plus a curated pentest/RF/credential synonym map (so " +
		"'garage' reaches the Sub-GHz tools, 'password' reaches the PMKID/hash family). A ranking " +
		"is advisory: a weak match is simply lower-ranked, never asserted as the answer.\n\n" +
		"Wrap-vs-native: native — a tokenizer + set-overlap scorer (internal/toolsearch), stdlib " +
		"only, no search-index dependency.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"query":{"type":"string","description":"Free-text task or keywords, e.g. 'garage door', 'wifi password', 'decode nfc'."},
			"limit":{"type":"integer","description":"Max results to return (default 10, capped at 50)."}
		},
		"required":["query"]
	}`),
	Required:  []string{"query"},
	Risk:      risk.Low,
	Group:     GroupMetaUtil,
	AgentOnly: false,
	Handler:   toolSearchHandler,
}

func toolSearchHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	query := strings.TrimSpace(str(p, "query"))
	if query == "" {
		return "", fmt.Errorf("tool_search: 'query' is required")
	}
	limit := intOr(p, "limit", 10)
	if limit <= 0 {
		limit = 10
	}
	if limit > 50 {
		limit = 50
	}

	specs := All()
	docs := make([]toolsearch.Doc, 0, len(specs))
	for _, s := range specs {
		docs = append(docs, toolsearch.Doc{
			Name:        s.Name,
			Aliases:     s.Aliases,
			Group:       string(s.Group),
			Description: s.Description,
		})
	}

	hits := toolsearch.Search(docs, query, limit)

	type match struct {
		Name    string   `json:"name"`
		Group   string   `json:"group"`
		Risk    string   `json:"risk"`
		Summary string   `json:"summary"`
		Score   float64  `json:"score"`
		Matched []string `json:"matched,omitempty"`
	}
	out := make([]match, 0, len(hits))
	for _, h := range hits {
		spec, ok := Get(h.Name)
		if !ok {
			continue
		}
		out = append(out, match{
			Name:    h.Name,
			Group:   string(spec.Group),
			Risk:    risk.Classify(h.Name).String(),
			Summary: firstSentence(spec.Description),
			Score:   h.Score,
			Matched: h.Matched,
		})
	}

	body, _ := json.MarshalIndent(map[string]any{
		"query":   query,
		"count":   len(out),
		"matches": out,
	}, "", "  ")
	if len(out) == 0 {
		return fmt.Sprintf("%s\n\n// no tools matched %q — try broader keywords (e.g. a protocol or action word)", string(body), query), nil
	}
	return string(body), nil
}

// firstSentence returns the leading sentence of a description, trimmed to a
// scannable length for the search result summary.
func firstSentence(desc string) string {
	desc = strings.TrimSpace(desc)
	if i := strings.Index(desc, ". "); i > 0 && i < 160 {
		return desc[:i+1]
	}
	if len(desc) > 160 {
		return strings.TrimSpace(desc[:160]) + "…"
	}
	return desc
}
