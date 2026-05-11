package rag

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTokenize(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"Hello World", []string{"hello", "world"}},
		// Snake-case emits the joined form + each sub-part so queries
		// for either "pmkid" or the full tool name both match the doc.
		{"wifi_sniff_pmkid", []string{"wifi_sniff_pmkid", "wifi", "sniff", "pmkid"}},
		{"PT2240/SC5262 @ 433.92MHz", []string{"pt2240", "sc5262", "433", "92mhz"}},
		{"", nil},
		{"   ", nil},
	}
	for _, c := range cases {
		got := tokenize(c.in)
		if len(got) != len(c.want) {
			t.Errorf("tokenize(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("tokenize(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestBuildIndex_EmptyCorpus(t *testing.T) {
	idx := BuildIndex(nil)
	if got := idx.Search("anything", 5); got != nil {
		t.Errorf("empty index should return nil, got %v", got)
	}
}

func TestSearch_RanksExactMatchHighest(t *testing.T) {
	docs := []Document{
		{ID: "a", Title: "Sub-GHz cheat", Body: "Princeton PT2240 uses 24-bit keys at 433.92 MHz."},
		{ID: "b", Title: "NFC cheat", Body: "Mifare Classic 1K has 4-byte UID; NTAG215 has 7."},
		{ID: "c", Title: "Wifi cheat", Body: "Deauth frames precede PMKID capture."},
	}
	idx := BuildIndex(docs)
	hits := idx.Search("PT2240", 3)
	if len(hits) == 0 {
		t.Fatal("exact-term query should hit")
	}
	if hits[0].Doc.ID != "a" {
		t.Errorf("top hit = %q, want %q", hits[0].Doc.ID, "a")
	}
}

func TestSearch_TopKLimit(t *testing.T) {
	docs := []Document{
		{ID: "a", Body: "alpha beta gamma"},
		{ID: "b", Body: "alpha beta delta"},
		{ID: "c", Body: "alpha epsilon"},
		{ID: "d", Body: "alpha zeta"},
	}
	idx := BuildIndex(docs)
	hits := idx.Search("alpha", 2)
	if len(hits) != 2 {
		t.Errorf("len(hits) = %d, want 2", len(hits))
	}
}

func TestSearch_NoResultsWhenNoTermHit(t *testing.T) {
	docs := []Document{{ID: "a", Body: "one two three"}}
	idx := BuildIndex(docs)
	if hits := idx.Search("missing_term_xyz", 5); len(hits) != 0 {
		t.Errorf("expected zero hits for miss, got %d", len(hits))
	}
}

func TestSearch_EmptyQueryReturnsNil(t *testing.T) {
	docs := []Document{{ID: "a", Body: "one"}}
	idx := BuildIndex(docs)
	if hits := idx.Search("", 5); hits != nil {
		t.Errorf("empty query should return nil, got %v", hits)
	}
}

func TestSearch_TieBreakByDocID(t *testing.T) {
	// Identical bodies → identical scores → deterministic order by ID.
	docs := []Document{
		{ID: "zebra", Body: "alpha"},
		{ID: "apple", Body: "alpha"},
		{ID: "mango", Body: "alpha"},
	}
	idx := BuildIndex(docs)
	hits := idx.Search("alpha", 3)
	if len(hits) != 3 {
		t.Fatalf("want 3 hits, got %d", len(hits))
	}
	if hits[0].Doc.ID != "apple" || hits[1].Doc.ID != "mango" || hits[2].Doc.ID != "zebra" {
		t.Errorf("tie-break order wrong: %q/%q/%q", hits[0].Doc.ID, hits[1].Doc.ID, hits[2].Doc.ID)
	}
}

func TestSnippet_CentersAroundMatch(t *testing.T) {
	body := strings.Repeat("xxx ", 50) + "needle " + strings.Repeat("yyy ", 50)
	snip := Snippet(body, "needle", 120)
	if !strings.Contains(snip, "needle") {
		t.Errorf("snippet missing match: %q", snip)
	}
	if !strings.HasPrefix(snip, "…") {
		t.Errorf("snippet should have leading ellipsis: %q", snip)
	}
}

func TestSnippet_ShortBodyNoEllipsis(t *testing.T) {
	snip := Snippet("hello needle world", "needle", 300)
	if strings.HasPrefix(snip, "…") || strings.HasSuffix(snip, "…") {
		t.Errorf("short snippet shouldn't have ellipses: %q", snip)
	}
}

// TestSnippet_UTF8BoundaryStart pins the rune-aware start clip.
// Pre-fix the byte-cut `body[start:end]` could land mid-rune when
// the match landed >60 bytes in and a multi-byte rune sat at the
// `bestIdx-60` boundary. Result: invalid-UTF-8 snippet that
// downstream JSON marshalling renders as U+FFFD or rejects.
//
// Construct a body where the 4-byte emoji 🛂 (F0 9F 9B 82) sits at
// bytes 60–63 and the search term lands at byte 121 — bestIdx=121
// minus the 60-byte lead drops start to 61, which lands on byte 2
// of the emoji.
func TestSnippet_UTF8BoundaryStart(t *testing.T) {
	prefix := strings.Repeat("x", 60)
	// 60 'x' + 4-byte emoji = 64 bytes, then 57 more 'x' lands needle
	// at byte 121. With bestIdx=121, start = 121-60 = 61, in the
	// middle of the 4-byte emoji.
	body := prefix + "🛂" + strings.Repeat("x", 57) + "needle"
	snip := Snippet(body, "needle", 80)
	if !utf8.ValidString(snip) {
		t.Errorf("Snippet produced invalid UTF-8: %q", snip)
	}
}

// TestSnippet_UTF8BoundaryEnd pins the rune-aware end clip. Same
// failure mode at the trailing edge: end = start + maxLen could
// land in the middle of a rune. Place the emoji near the end of
// the maxLen window.
func TestSnippet_UTF8BoundaryEnd(t *testing.T) {
	// "needle " (7 bytes) + 50 'x' (=57 total) + emoji at 57-60.
	// With start=0, maxLen=58, end=58 lands at byte 2 of the emoji.
	body := "needle " + strings.Repeat("x", 50) + "🛂" + strings.Repeat("x", 30)
	snip := Snippet(body, "needle", 58)
	if !utf8.ValidString(snip) {
		t.Errorf("Snippet produced invalid UTF-8: %q", snip)
	}
}

func TestDefaultIndex_LoadsBundledCorpus(t *testing.T) {
	// The embedded corpus ships with PromptZero. A regression where
	// the embed.FS is empty should trip this test loudly.
	idx := DefaultIndex()
	if idx.numDocs == 0 {
		t.Fatal("default index has no documents — corpus/ not embedded?")
	}
	hits := idx.Search("badusb", 3)
	if len(hits) == 0 {
		t.Error("default index missing BadUSB coverage")
	}
}

// Lock a small set of technical terms the operator is virtually
// guaranteed to type. A regression that drops the relevant doc from
// the bundle should fail here with a clear diagnostic.
func TestDefaultIndex_CoversHighPriorityTerms(t *testing.T) {
	idx := DefaultIndex()
	terms := []string{"PMKID", "T5577", "evil_portal", "NTAG", "BadUSB"}
	for _, term := range terms {
		if len(idx.Search(term, 1)) == 0 {
			t.Errorf("term %q not found in default corpus", term)
		}
	}
}
