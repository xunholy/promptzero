package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/xunholy/promptzero/internal/discover"
	"github.com/xunholy/promptzero/internal/rag"
	"github.com/xunholy/promptzero/internal/risk"
)

// rag.go registers the discover_apps and docs_search tools.
// Both are AgentOnly:true — discover_apps requires a live Flipper transport
// and docs_search's index is lazily constructed in-process.

//nolint:gochecknoinits
func init() {
	Register(Spec{
		Name: "discover_apps",
		Description: "Scan the Flipper Zero SD card and discover all installed FAP applications, saved signals, " +
			"BadUSB scripts, NFC tags, RFID tags, and other files. Returns a categorized inventory of " +
			"everything available on the device.",
		Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
		Required:  nil,
		Risk:      risk.Low,
		Group:     GroupMetaUtil,
		AgentOnly: true,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			apps, err := discover.ScanApps(d.Flipper)
			if err != nil {
				return "", err
			}
			return discover.FormatApps(apps), nil
		},
	})

	Register(Spec{
		Name: "docs_search",
		Description: "Lexical (BM25) search over the bundled PromptZero documentation — tool reference, " +
			"scenario recipes, prompt patterns. Use when you need exact-term grounding: protocol names " +
			"(EM4100, PT2240), register quirks (ATQA/SAK), CLI flags, file-format field names. Returns " +
			"up to K ranked snippets with source paths; read the full doc via fileformat_read or by name.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"query":{"type":"string","description":"Search terms. Space-separated keywords; exact technical terms rank highest."},` +
			`"k":{"type":"integer","description":"Number of results (default 5, max 20)"}` +
			`}}`),
		Required:  []string{"query"},
		Risk:      risk.Low,
		Group:     GroupMetaUtil,
		AgentOnly: true,
		Handler:   docsSearchHandler,
	})
}

// ragOnce / ragDefault lazily build the embedded RAG corpus on first call.
// Using sync.Once ensures the corpus is built exactly once across concurrent
// tool invocations.
var (
	ragOnce    sync.Once
	ragDefault *rag.Index
)

func getDefaultRAGIndex() *rag.Index {
	ragOnce.Do(func() { ragDefault = rag.DefaultIndex() })
	return ragDefault
}

func docsSearchHandler(_ context.Context, d *Deps, p map[string]any) (string, error) {
	query := str(p, "query")
	if query == "" {
		return "", fmt.Errorf("query required")
	}
	k := intOr(p, "k", 5)
	if k <= 0 {
		k = 5
	}
	if k > 20 {
		k = 20
	}

	// Prefer the injected RAG index (test/plugin scenario), then the
	// lazily-built global default.
	idx := d.RAG
	if idx == nil {
		idx = getDefaultRAGIndex()
	}

	hits := idx.Search(query, k)
	if len(hits) == 0 {
		return fmt.Sprintf("no results for %q", query), nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d results for %q:\n", len(hits), query)
	for _, h := range hits {
		fmt.Fprintf(&b, "\n## %s (%s) — score %.2f\n%s\n",
			h.Doc.Title, h.Doc.Source, h.Score, rag.Snippet(h.Doc.Body, query, 400))
	}
	return b.String(), nil
}
