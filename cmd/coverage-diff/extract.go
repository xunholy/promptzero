package main

import (
	"regexp"
	"strings"
)

// maxTokenLen is the maximum length of a canonical token (after stripping
// delimiters) that is still considered a plausible tool/verb identifier.
// Concatenated link descriptions like "allthepluginslargecollection..." are
// filtered out by this ceiling.
const maxTokenLen = 32

// canonicalize returns s lowercased with every character that is not a
// lowercase ASCII letter or ASCII digit removed. The result is a minimal
// canonical form so that "nfc-magic", "nfc_magic", "NFC Magic", "`nfc_magic`",
// and "NFCMAGIC" all collapse to "nfcmagic". The same function is applied to
// both upstream tokens and registered tool names so that delimiter-style
// differences (hyphens, underscores, spaces, backticks) never create
// spurious gaps.
func canonicalize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// stopwords is the set of common English words that are not meaningful
// tool/verb identifiers. Tokens whose canonical form matches an entry here
// are silently dropped during extraction.
var stopwords = map[string]struct{}{
	"this": {}, "that": {}, "with": {}, "from": {}, "have": {}, "will": {},
	"your": {}, "they": {}, "what": {}, "been": {}, "more": {}, "also": {},
	"some": {}, "such": {}, "into": {}, "when": {}, "then": {}, "than": {},
	"only": {}, "just": {}, "make": {}, "made": {}, "take": {}, "time": {},
	"very": {}, "here": {}, "there": {}, "where": {}, "about": {}, "would": {},
	"could": {}, "should": {}, "their": {}, "other": {}, "after": {}, "before": {},
	"first": {}, "which": {}, "these": {}, "those": {}, "each": {}, "many": {},
	"most": {}, "over": {}, "same": {}, "back": {}, "used": {}, "like": {},
	"look": {}, "work": {}, "even": {}, "well": {}, "need": {}, "does": {},
	"good": {}, "much": {}, "know": {}, "want": {}, "give": {}, "both": {},
	"come": {}, "find": {}, "long": {}, "down": {}, "open": {}, "using": {},
	"http": {}, "https": {}, "github": {}, "awesome": {}, "apps": {},
	"view": {}, "show": {}, "help": {}, "note": {}, "page": {},
	"repo": {}, "main": {}, "read": {}, "file": {},
}

var (
	// linkRe extracts [link text](url) markdown hyperlinks.
	linkRe = regexp.MustCompile(`\[([^\]\n]+)\]\([^)\n]*\)`)

	// fenceRe matches fenced code blocks (```lang\n...\n```).
	fenceRe = regexp.MustCompile("(?s)```[a-zA-Z]*\n(.*?)```")

	// inlineCodeRe matches `inline code` spans (excluding multi-line).
	inlineCodeRe = regexp.MustCompile("`([^`\n]+)`")

	// wordSplitRe splits a string on any character that is not
	// alphanumeric, hyphen, or underscore.
	wordSplitRe = regexp.MustCompile(`[^a-zA-Z0-9\-_]+`)
)

// ExtractTokens pulls candidate tool/verb tokens from raw markdown content.
//
// It reads three markdown constructs:
//   - Link texts from [text](url) hyperlinks — the most reliable source of
//     upstream tool/app names.
//   - Lines inside fenced code blocks — commands or filenames often appear
//     here.
//   - Inline `code` spans — short identifiers embedded in prose.
//
// Each raw string is first added in full (after canonicalization), then split
// on word boundaries so that multi-word identifiers like "NFC Magic" also
// contribute their individual parts. Tokens shorter than 4 characters,
// longer than maxTokenLen characters, or matching the stopwords list are
// dropped. The returned slice is deduplicated and preserves first-seen order.
func ExtractTokens(content []byte) []string {
	seen := make(map[string]struct{})
	var tokens []string

	add := func(canon string) {
		if len(canon) < 4 || len(canon) > maxTokenLen {
			return
		}
		if _, stop := stopwords[canon]; stop {
			return
		}
		if _, dup := seen[canon]; dup {
			return
		}
		seen[canon] = struct{}{}
		tokens = append(tokens, canon)
	}

	// addRaw adds the full canonical form of raw and also each individual
	// word extracted by splitting on non-identifier characters.
	addRaw := func(raw string) {
		// Full form: strip all non-alphanumeric characters (including delimiters
		// and punctuation like backticks embedded in link texts).
		add(canonicalize(raw))

		// Individual words: split on non-alphanumeric-hyphen-underscore, then
		// canonicalize each part so "NFC-Magic" → ["nfc", "magic"] too.
		for _, part := range wordSplitRe.Split(raw, -1) {
			if part == "" {
				continue
			}
			add(canonicalize(part))
		}
	}

	s := string(content)

	// 1. Markdown link texts (highest-signal source).
	for _, m := range linkRe.FindAllStringSubmatch(s, -1) {
		addRaw(m[1])
	}

	// 2. Fenced code block lines.
	for _, m := range fenceRe.FindAllStringSubmatch(s, -1) {
		for _, line := range strings.Split(m[1], "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			addRaw(line)
		}
	}

	// 3. Inline code spans.
	for _, m := range inlineCodeRe.FindAllStringSubmatch(s, -1) {
		addRaw(m[1])
	}

	return tokens
}
