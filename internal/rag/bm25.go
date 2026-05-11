// Package rag provides lexical retrieval over the bundled PromptZero
// documentation corpus. The agent uses it to ground tool arguments
// in authoritative reference material (cheat sheets, scenario recipes,
// tool documentation) without shipping an embedding provider or a
// separate retrieval service.
//
// This is the lexical half of a future hybrid retrieval stack.
// BM25 covers rare-term queries where a dense embedding model would
// over-generalise — "OOK650Async", "ATQA", "T5577", "NTAG215" are all
// exact terms the operator will use verbatim, and BM25 rewards that.
// A dense-embedding layer and a cross-encoder reranker can be added
// later without changing this package's public surface; the hybrid
// merger simply interleaves results from both retrievers.
package rag

import (
	"embed"
	"io/fs"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

// BM25 hyper-parameters. k1 controls term-frequency saturation
// (higher values weight repeated terms more); b controls the
// length-normalisation pressure (0 = no normalisation, 1 = full).
// The 1.5 / 0.75 defaults are the canonical values from Manning &
// Schütze; tuning them against the PromptZero corpus is a future
// exercise once we have a golden query set.
const (
	bm25K1 = 1.5
	bm25B  = 0.75
)

// Document is one indexed unit. A document can be a full markdown
// file or a paragraph-sized chunk; the indexer doesn't care. Title
// is shown in result snippets; Source is the original path so the
// agent can read the full file if it wants more context.
type Document struct {
	ID     string
	Title  string
	Body   string
	Source string
}

// Hit is a ranked retrieval result.
type Hit struct {
	Doc   Document
	Score float64
}

// Index is the immutable BM25 retriever. Build once at startup; Search
// is read-only and safe for concurrent use.
type Index struct {
	docs    []Document
	termDF  map[string]int   // term → number of docs containing it
	termTF  []map[string]int // per-doc term frequency
	docLens []int            // per-doc token count
	avgDL   float64          // average document length
	numDocs int
}

// BuildIndex tokenises each document and precomputes term-frequency
// statistics. Runs in one pass over the corpus.
func BuildIndex(docs []Document) *Index {
	idx := &Index{
		docs:    docs,
		termDF:  map[string]int{},
		termTF:  make([]map[string]int, len(docs)),
		docLens: make([]int, len(docs)),
		numDocs: len(docs),
	}
	var totalLen int
	for i, d := range docs {
		tokens := tokenize(d.Title + " " + d.Body)
		tf := map[string]int{}
		for _, t := range tokens {
			tf[t]++
		}
		idx.termTF[i] = tf
		idx.docLens[i] = len(tokens)
		totalLen += len(tokens)
		for t := range tf {
			idx.termDF[t]++
		}
	}
	if len(docs) > 0 {
		idx.avgDL = float64(totalLen) / float64(len(docs))
	}
	return idx
}

// Search returns the top-K documents by BM25 score for the given
// query. A zero or negative k defaults to 5. An empty query returns
// nil. Ties break by document ID for determinism.
func (i *Index) Search(query string, k int) []Hit {
	if i == nil || i.numDocs == 0 {
		return nil
	}
	if k <= 0 {
		k = 5
	}
	qTokens := tokenize(query)
	if len(qTokens) == 0 {
		return nil
	}
	scores := make([]float64, i.numDocs)
	for _, qt := range qTokens {
		df := i.termDF[qt]
		if df == 0 {
			continue
		}
		// Classic BM25 IDF with +0.5 smoothing; clamp to 0 so common
		// terms (df close to N) don't generate negative scores that
		// subtract from useful signal.
		idf := math.Log((float64(i.numDocs)-float64(df)+0.5)/(float64(df)+0.5) + 1)
		for d := 0; d < i.numDocs; d++ {
			tf := float64(i.termTF[d][qt])
			if tf == 0 {
				continue
			}
			dl := float64(i.docLens[d])
			norm := 1 - bm25B + bm25B*dl/i.avgDL
			scores[d] += idf * (tf * (bm25K1 + 1)) / (tf + bm25K1*norm)
		}
	}
	hits := make([]Hit, 0, i.numDocs)
	for d, s := range scores {
		if s > 0 {
			hits = append(hits, Hit{Doc: i.docs[d], Score: s})
		}
	}
	sort.Slice(hits, func(a, b int) bool {
		if hits[a].Score != hits[b].Score {
			return hits[a].Score > hits[b].Score
		}
		return hits[a].Doc.ID < hits[b].Doc.ID
	})
	if len(hits) > k {
		hits = hits[:k]
	}
	return hits
}

// tokenize lower-cases the input and splits on runs of non-letter /
// non-digit characters. Underscore-joined tokens ("wifi_sniff_pmkid")
// emit both the full joined form AND each sub-part so a query for
// either "pmkid" or "wifi_sniff_pmkid" matches the doc. No stop-word
// filter — the corpus is technical enough that stop words rarely
// dominate, and dropping them would lose "evil portal" / "evil_portal"
// equivalence.
func tokenize(s string) []string {
	s = strings.ToLower(s)
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		tok := cur.String()
		out = append(out, tok)
		if strings.Contains(tok, "_") {
			for _, part := range strings.Split(tok, "_") {
				if part != "" && part != tok {
					out = append(out, part)
				}
			}
		}
		cur.Reset()
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			cur.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return out
}

//go:embed corpus/*.md
var embeddedCorpus embed.FS

// DefaultIndex builds an index over the bundled documentation corpus.
// Returns an empty index if the embed FS is unexpectedly missing files
// (keeps the tool path fail-closed — no panics at startup).
func DefaultIndex() *Index {
	var docs []Document
	_ = fs.WalkDir(embeddedCorpus, "corpus", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".md" {
			return nil
		}
		body, err := embeddedCorpus.ReadFile(path)
		if err != nil {
			return nil
		}
		docs = append(docs, Document{
			ID:     filepath.Base(path),
			Title:  strings.TrimSuffix(filepath.Base(path), ".md"),
			Body:   string(body),
			Source: path,
		})
		return nil
	})
	return BuildIndex(docs)
}

// Snippet renders a short excerpt of the document body around the
// first matching query term, up to maxLen characters. Falls back to
// the opening of the body when no query term is present (e.g. when
// the caller scored on title-only matches). Intended for shaping the
// search result payload the model sees.
func Snippet(body, query string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 300
	}
	lowerBody := strings.ToLower(body)
	var bestIdx = -1
	for _, q := range tokenize(query) {
		if idx := strings.Index(lowerBody, q); idx >= 0 {
			if bestIdx == -1 || idx < bestIdx {
				bestIdx = idx
			}
		}
	}
	start := 0
	if bestIdx > 60 {
		start = bestIdx - 60
	}
	end := start + maxLen
	if end > len(body) {
		end = len(body)
	}
	// UTF-8 boundary safety: a markdown corpus can contain multi-byte
	// runes (smart quotes, em-dashes, emoji in examples), and naive
	// byte-cuts could land mid-rune — producing an invalid-UTF-8
	// snippet that downstream JSON marshalling renders as U+FFFD or
	// rejects outright. Walk both boundaries back to the previous
	// rune start. Mirrors session.clipTitle / generate.capSize /
	// validator.truncate / agent.truncatePreview.
	start = backToRuneStart(body, start)
	end = backToRuneStart(body, end)
	snippet := strings.TrimSpace(body[start:end])
	if start > 0 {
		snippet = "…" + snippet
	}
	if end < len(body) {
		snippet = snippet + "…"
	}
	return snippet
}

// backToRuneStart returns the largest index <= i that is at a UTF-8
// leading byte (or 0 / len(s)). Continuation bytes match
// 10xxxxxx (b & 0xC0 == 0x80); walking backwards from those lands on
// the rune's lead byte. Used by Snippet to clip its body window
// without splitting a multi-byte rune.
func backToRuneStart(s string, i int) int {
	if i <= 0 {
		return 0
	}
	if i >= len(s) {
		return len(s)
	}
	for i > 0 && s[i]&0xC0 == 0x80 {
		i--
	}
	return i
}
