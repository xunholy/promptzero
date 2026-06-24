// SPDX-License-Identifier: AGPL-3.0-or-later

// Package toolsearch ranks registry tools against a free-text query so an
// operator can find the right tool by task ("garage door", "wifi password",
// "decode nfc card") instead of guessing its exact name. With 600+ tools, the
// only discovery affordance was a name-substring filter; this adds task-oriented
// search across every surface that reaches the registry.
//
// The ranking is deterministic and offline: the same query always yields the
// same order (ties broken by tool name — a tiebreak-less sort would flake, see
// the Sub-GHz classifier fix), and the score is a field-weighted token overlap
// over each tool's name / aliases / group / description, plus a small curated
// domain synonym map so task words reach the technical terms the tools actually
// use. No "confidently wrong" risk: a ranking is advisory; a poor match is
// merely lower-ranked, never asserted as the answer.
//
// Wrap-vs-native: native — a tokenizer + weighted set-overlap scorer, stdlib
// only, no search-index or embedding dependency.
package toolsearch

import (
	"sort"
	"strings"
)

// Doc is one searchable tool: the registry fields the ranker scores over.
type Doc struct {
	Name        string
	Aliases     []string
	Group       string
	Description string
}

// Result is one ranked match. Matched lists the query/synonym terms that hit,
// sorted, so the caller can show why a tool surfaced.
type Result struct {
	Name    string   `json:"name"`
	Score   float64  `json:"score"`
	Matched []string `json:"matched,omitempty"`
}

// Field weights: a term hit in the tool name is worth far more than one in the
// description. Exact / prefix name matches add a large bonus on top (see Search)
// so a precise name lookup always ranks first.
const (
	wName  = 6.0
	wAlias = 5.0
	wGroup = 3.0
	wDesc  = 1.0

	bonusExactName  = 50.0
	bonusPrefixName = 12.0
	bonusSubName    = 8.0
)

// synonyms maps a task/domain word to the technical terms that actually appear
// in tool names and descriptions, so "garage" reaches the Sub-GHz tooling and
// "password" reaches the credential/hash family. Deliberately small and
// curated for the pentest/RF/credential domain; an unknown query word simply
// matches literally.
var synonyms = map[string][]string{ //nolint:gochecknoglobals
	"garage": {"subghz", "door", "gate", "rolling"},
	"door":   {"subghz", "rfid", "nfc", "access"},
	"gate":   {"subghz", "door", "rolling"},
	"car":    {"subghz", "keyfob", "tpms", "rolling", "obd2", "uds", "canbus", "dtc"},
	"keyfob": {"subghz", "keyfob", "rolling"},
	// Automotive diagnostics: the OBD-II / UDS / CAN tool family was previously
	// unreachable by natural diagnostic queries (the only "car" mapping pointed
	// at the RF keyfob domain). These route engine / ECU / fault-code queries to
	// obd2_pid_decode / obd2_dtc_decode / uds_decode / uds_dtc_status_decode /
	// canbus_* / vin_decode / automotive_j1850_decode, whose names carry those
	// exact tokens.
	"vehicle":    {"obd2", "uds", "canbus", "vin", "automotive"},
	"engine":     {"obd2", "pid", "dtc"},
	"diagnostic": {"obd2", "uds", "dtc", "canbus"},
	"obd":        {"obd2", "pid", "dtc"},
	"ecu":        {"uds", "obd2", "xcp", "ccp"},
	"automotive": {"obd2", "uds", "canbus", "vin", "j1850"},
	"dtc":        {"dtc", "obd2", "uds"},
	"fault":      {"dtc", "obd2", "uds"},
	"remote":     {"ir", "subghz", "rolling"},
	"tire":       {"tpms", "weather"},
	"wifi":       {"wifi", "80211", "wpa", "marauder"},
	"wireless":   {"wifi", "ble", "subghz", "nrf24"},
	"deauth":     {"deauth", "wifi"},
	"password":   {"password", "pmkid", "hash", "cred", "secret"},
	"passwords":  {"password", "pmkid", "hash", "cred", "secret"},
	"creds":      {"cred", "password", "hash", "secret"},
	"hash":       {"hash", "crack", "ntlm", "md5", "hashcat"},
	"nfc":        {"nfc", "mifare", "iso14443", "ndef"},
	"mifare":     {"mifare", "nfc", "crypto1", "mfkey"},
	"rfid":       {"rfid", "em4100", "t5577", "indala"},
	"card":       {"nfc", "mifare", "rfid", "emv"},
	"badge":      {"nfc", "rfid", "wiegand", "pacs"},
	// Financial-data triage: the IBAN / LEI / ISIN / ABA-routing decoder family
	// (iban_decode, lei_decode, isin_decode, aba_routing_decode) handles the
	// account / entity / security / US-bank identifiers found in BEC lures,
	// leaked spreadsheets, and wire/ACH-fraud material. Natural finance phrasings
	// ("wire transfer", "stock ticker", "what bank") otherwise ranked them out of
	// the top results. Deliberately finance-specific tokens only — "security",
	// "routing", and "account" are omitted because they collide with the
	// infosec / network-routing / service-account domains.
	"bank":       {"iban", "aba", "routing"},
	"wire":       {"iban", "aba", "routing"},
	"swift":      {"iban", "lei", "bank"},
	"iban":       {"iban", "bank"},
	"ach":        {"aba", "routing"},
	"stock":      {"isin", "securities"},
	"ticker":     {"isin", "securities"},
	"securities": {"isin", "securities"},
	"brokerage":  {"isin", "securities"},
	"financial":  {"iban", "lei", "isin", "aba"},
	"bluetooth":  {"ble", "bluetooth", "bt", "gatt"},
	"ble":        {"ble", "bluetooth", "gatt"},
	"ir":         {"ir", "infrared", "pronto"},
	"infrared":   {"ir", "infrared", "pronto"},
	"jam":        {"jammer", "jam"},
	"jammer":     {"jammer", "jam"},
	"replay":     {"replay", "bruteforce", "tx"},
	"brute":      {"bruteforce", "brute", "crack"},
	"crack":      {"crack", "hash", "bruteforce", "key"},
	"decode":     {"decode", "decrypt", "parse"},
	"decrypt":    {"decrypt", "decode"},
	"sniff":      {"sniff", "capture", "monitor"},
	"capture":    {"capture", "sniff", "monitor"},
	"weather":    {"weather", "tpms", "lacrosse", "acurite"},
	"pager":      {"pocsag", "pager"},
	"badusb":     {"badusb", "ducky", "hid", "keystroke"},
	"keystroke":  {"badusb", "hid", "usb"},
}

// Search returns the tools whose fields best match query, highest score first,
// at most limit results (limit <= 0 = unbounded). A zero-score tool is omitted.
func Search(docs []Doc, query string, limit int) []Result {
	qTerms := expand(tokenize(query))
	if len(qTerms) == 0 {
		return nil
	}
	qNorm := strings.ToLower(strings.TrimSpace(query))

	results := make([]Result, 0, len(docs))
	for _, d := range docs {
		score, matched := scoreDoc(d, qTerms)

		// A precise name lookup should always win, beyond token overlap.
		ln := strings.ToLower(d.Name)
		switch {
		case ln == qNorm:
			score += bonusExactName
		case qNorm != "" && strings.HasPrefix(ln, qNorm):
			score += bonusPrefixName
		case qNorm != "" && strings.Contains(ln, qNorm):
			score += bonusSubName
		}

		if score <= 0 {
			continue
		}
		results = append(results, Result{Name: d.Name, Score: score, Matched: matched})
	}

	// Deterministic order: score desc, then name asc. Without the name
	// tiebreak, equal-score matches would surface in arbitrary order.
	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		return results[i].Name < results[j].Name
	})

	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}
	return results
}

// scoreDoc adds, for each query term, the highest field weight at which the
// term appears in the doc (name beats alias beats group beats description).
func scoreDoc(d Doc, qTerms []string) (float64, []string) {
	name := tokenSet(d.Name)
	alias := map[string]bool{}
	for _, a := range d.Aliases {
		for t := range tokenSet(a) {
			alias[t] = true
		}
	}
	group := tokenSet(strings.ReplaceAll(d.Group, ".", " "))
	desc := tokenSet(d.Description)

	var score float64
	var matched []string
	seen := map[string]bool{}
	for _, qt := range qTerms {
		w := 0.0
		switch {
		case name[qt]:
			w = wName
		case alias[qt]:
			w = wAlias
		case group[qt]:
			w = wGroup
		case desc[qt]:
			w = wDesc
		}
		if w > 0 {
			score += w
			if !seen[qt] {
				seen[qt] = true
				matched = append(matched, qt)
			}
		}
	}
	sort.Strings(matched)
	return score, matched
}

// tokenize lower-cases s and splits on any non-alphanumeric run, dropping
// single-character fragments (too noisy to rank on).
func tokenize(s string) []string {
	var toks []string
	for _, f := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		// split on any rune that is NOT [a-z0-9] (De Morgan of the alnum test).
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if len(f) >= 2 {
			toks = append(toks, f)
		}
	}
	return toks
}

// tokenSet is tokenize as a membership set.
func tokenSet(s string) map[string]bool {
	set := map[string]bool{}
	for _, t := range tokenize(s) {
		set[t] = true
	}
	return set
}

// expand adds each token's domain synonyms, de-duplicating while preserving a
// stable first-seen order (which does not affect ranking — scoring is
// order-independent — but keeps Matched reproducible).
func expand(toks []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, t := range toks {
		add(t)
		for _, syn := range synonyms[t] {
			add(syn)
		}
	}
	return out
}
