package fileformat

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// FreqmanEntry is one row of a Freqman / PortaPack-Mayhem signal list.
//
// Freqman is the de-facto interop format shared between HackRF/PortaPack-
// Mayhem, OpenSDR, and several Flipper community tools. Each entry is a
// single comma-separated `key=value` line. There are two shapes:
//
//   - **single-frequency**: Frequency != 0, RangeStart == 0, RangeEnd == 0.
//     Encoded as `f=<Hz>,m=<mod>,bw=<n>,s=<step>,d=<desc>`.
//   - **range scan**: RangeStart != 0 && RangeEnd != 0, Frequency == 0.
//     Encoded as `a=<startHz>,b=<endHz>,m=<mod>,bw=<n>,s=<step>,d=<desc>`.
//
// All non-frequency fields are optional. Bandwidth and Step are preserved as
// strings (rather than numerics) because the upstream format mixes raw Hz,
// kHz suffixes, and named presets ("AM_DSB_5KHZ") in different forks; we
// keep what the file says verbatim so a round-trip is exact.
//
// Extra holds any `key=value` pairs we don't model (tone=, p=, etc.) so a
// firmware-fork extension survives Parse → Marshal unchanged.
type FreqmanEntry struct {
	Frequency   uint64
	RangeStart  uint64
	RangeEnd    uint64
	Modulation  string
	Bandwidth   string
	Step        string
	Description string
	Extra       map[string]string
}

// IsRange reports whether this entry is a range-scan entry.
func (e FreqmanEntry) IsRange() bool {
	return e.RangeStart != 0 && e.RangeEnd != 0
}

// FreqmanList is an ordered sequence of FreqmanEntry rows. The order
// matters: PortaPack's frequency-list browser presents entries in file
// order, so reorder-on-parse would surprise operators.
type FreqmanList struct {
	Entries []FreqmanEntry
}

// ParseFreqman parses a Freqman list. Tolerant of CRLF, blank lines, and
// `#` comment lines. Each non-empty, non-comment line MUST contain at
// least one of `f=` or `a=`+`b=` — otherwise the line is rejected so a
// malformed file fails at load rather than silently dropping signals.
//
// Parsing rules:
//   - The line is split on commas into tokens.
//   - Each token is `key=value`. The first `=` is the separator; remaining
//     `=` stay inside value (e.g. base64-encoded Extra fields).
//   - Within the *value* of `d=` (description), commas are kept verbatim
//     by treating `d=` as a sticky tail: once we see `d=`, everything
//     after it on the line — commas included — is the description. This
//     mirrors Mayhem's own emitter, which does not quote.
//   - Unknown keys go into Extra so round-trip is lossless.
func ParseFreqman(data []byte) (*FreqmanList, error) {
	list := &FreqmanList{}
	for lineno, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, err := parseFreqmanLine(line)
		if err != nil {
			return nil, fmt.Errorf("freqman: line %d: %w", lineno+1, err)
		}
		list.Entries = append(list.Entries, entry)
	}
	return list, nil
}

func parseFreqmanLine(line string) (FreqmanEntry, error) {
	var e FreqmanEntry
	// Sticky-tail rule for d=: split off description first, then parse the
	// rest as comma-separated tokens.
	rest := line
	if idx := indexFreqmanDescription(line); idx >= 0 {
		// idx points at 'd' of `d=`. Everything from idx+2 to end is description.
		e.Description = strings.TrimSpace(line[idx+2:])
		rest = strings.TrimSpace(strings.TrimSuffix(line[:idx], ","))
	}

	if rest != "" {
		for _, tok := range strings.Split(rest, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			eq := strings.IndexByte(tok, '=')
			if eq <= 0 {
				return e, fmt.Errorf("malformed token %q (expected key=value)", tok)
			}
			key := strings.TrimSpace(tok[:eq])
			val := strings.TrimSpace(tok[eq+1:])
			switch key {
			case "f":
				n, err := parseFreqmanHz(val)
				if err != nil {
					return e, fmt.Errorf("f= %q: %w", val, err)
				}
				e.Frequency = n
			case "a":
				n, err := parseFreqmanHz(val)
				if err != nil {
					return e, fmt.Errorf("a= %q: %w", val, err)
				}
				e.RangeStart = n
			case "b":
				n, err := parseFreqmanHz(val)
				if err != nil {
					return e, fmt.Errorf("b= %q: %w", val, err)
				}
				e.RangeEnd = n
			case "m":
				e.Modulation = val
			case "bw":
				e.Bandwidth = val
			case "s":
				e.Step = val
			default:
				if e.Extra == nil {
					e.Extra = map[string]string{}
				}
				e.Extra[key] = val
			}
		}
	}

	if e.Frequency == 0 && (e.RangeStart == 0 || e.RangeEnd == 0) {
		return e, fmt.Errorf("missing f= (or a=+b=) on entry")
	}
	if e.Frequency != 0 && (e.RangeStart != 0 || e.RangeEnd != 0) {
		return e, fmt.Errorf("entry has both f= and a/b= — pick one")
	}
	return e, nil
}

// indexFreqmanDescription returns the byte index of the `d` in the first
// `d=` token at top level (i.e. preceded by start-of-line or `,`), or -1
// when no description token is present.
func indexFreqmanDescription(line string) int {
	// Walk the line; a description token starts at index 0 or right after a
	// comma. We look for "d=" at one of those anchor positions.
	for i := 0; i < len(line)-1; i++ {
		if line[i] != 'd' || line[i+1] != '=' {
			continue
		}
		if i == 0 || line[i-1] == ',' {
			return i
		}
	}
	return -1
}

// parseFreqmanHz accepts a frequency in plain Hz (e.g. "433920000"). Forks
// that emit MHz floats are not supported; they're rare and an explicit
// error keeps them visible rather than silently parsed at the wrong scale.
func parseFreqmanHz(v string) (uint64, error) {
	if v == "" {
		return 0, fmt.Errorf("empty")
	}
	if strings.ContainsAny(v, ".eE") {
		return 0, fmt.Errorf("non-integer frequency %q (Hz expected)", v)
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Marshal serialises the list back to canonical Freqman bytes. Field
// emission order per entry is: f or (a,b), m, bw, s, sorted Extra, d. The
// description is emitted last because of the sticky-tail rule.
func (l *FreqmanList) Marshal() []byte {
	var b strings.Builder
	for _, e := range l.Entries {
		b.WriteString(e.marshalLine())
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func (e FreqmanEntry) marshalLine() string {
	var parts []string
	switch {
	case e.IsRange():
		parts = append(parts, "a="+strconv.FormatUint(e.RangeStart, 10))
		parts = append(parts, "b="+strconv.FormatUint(e.RangeEnd, 10))
	case e.Frequency != 0:
		parts = append(parts, "f="+strconv.FormatUint(e.Frequency, 10))
	}
	if e.Modulation != "" {
		parts = append(parts, "m="+e.Modulation)
	}
	if e.Bandwidth != "" {
		parts = append(parts, "bw="+e.Bandwidth)
	}
	if e.Step != "" {
		parts = append(parts, "s="+e.Step)
	}
	for _, k := range sortedKeys(e.Extra) {
		parts = append(parts, k+"="+e.Extra[k])
	}
	if e.Description != "" {
		parts = append(parts, "d="+e.Description)
	}
	return strings.Join(parts, ",")
}

// FreqmanPresetForModulation maps a Freqman modulation name to a Flipper
// `Preset:` header value. Best-effort: returns the empty string when no
// canonical mapping exists, leaving the caller to fall back to its own
// default (typically the firmware's `FuriHalSubGhzPresetOok650Async`).
//
// The mappings cover the modulations actually in use across PortaPack and
// the Flipper community lists; exotic forks can pass through Modulation
// verbatim and let the firmware reject unknown presets.
func FreqmanPresetForModulation(mod string) string {
	switch strings.ToUpper(mod) {
	case "AM_DSB", "AM_DSB_5KHZ", "AM650", "AM":
		return "FuriHalSubGhzPresetOok650Async"
	case "AM_DSB_2_8KHZ", "AM270":
		return "FuriHalSubGhzPresetOok270Async"
	case "NFM", "NFM_8KHZ", "FM_DEV2_4":
		return "FuriHalSubGhzPreset2FSKDev238Async"
	case "WFM", "FM_DEV4_8":
		return "FuriHalSubGhzPreset2FSKDev476Async"
	}
	return ""
}

// FreqmanModulationForPreset is the inverse mapping: Flipper preset →
// Freqman modulation. Returns empty when unknown.
func FreqmanModulationForPreset(preset string) string {
	switch preset {
	case "FuriHalSubGhzPresetOok650Async":
		return "AM_DSB"
	case "FuriHalSubGhzPresetOok270Async":
		return "AM_DSB_2_8KHZ"
	case "FuriHalSubGhzPreset2FSKDev238Async":
		return "NFM"
	case "FuriHalSubGhzPreset2FSKDev476Async":
		return "WFM"
	}
	return ""
}

// FreqmanFromSub builds a FreqmanEntry from a Flipper .sub file. Only the
// frequency, preset, and (caller-supplied) description are carried — the
// per-protocol fields (Key, TE, RAW_Data) are intentionally not surfaced
// because Freqman is a *catalogue* format, not a capture format.
//
// Returns an error if sub is nil or its Frequency is zero (a Freqman entry
// without a frequency is meaningless).
func FreqmanFromSub(sub *SubFile, description string) (*FreqmanEntry, error) {
	if sub == nil {
		return nil, fmt.Errorf("nil sub")
	}
	if sub.Frequency == 0 {
		return nil, fmt.Errorf("sub has no Frequency")
	}
	e := &FreqmanEntry{
		Frequency:   uint64(sub.Frequency),
		Modulation:  FreqmanModulationForPreset(sub.Preset),
		Description: strings.TrimSpace(description),
	}
	return e, nil
}

// ToSubLite returns a minimal *SubFile that represents this Freqman entry
// as a Flipper Sub-GHz key file. RAW_Data and protocol-specific fields are
// not populated — Freqman doesn't carry them. The caller can layer those
// in if it later captures real RF for the entry.
//
// Range entries cannot be expressed as a single .sub and yield an error.
func (e FreqmanEntry) ToSubLite() (*SubFile, error) {
	if e.IsRange() {
		return nil, fmt.Errorf("freqman: range entry has no single-frequency .sub representation")
	}
	if e.Frequency == 0 {
		return nil, fmt.Errorf("freqman: entry has no frequency")
	}
	preset := FreqmanPresetForModulation(e.Modulation)
	if preset == "" {
		preset = "FuriHalSubGhzPresetOok650Async"
	}
	return &SubFile{
		Filetype:  "Flipper SubGhz Key File",
		Version:   1,
		Frequency: uint32(e.Frequency),
		Preset:    preset,
		Headers:   map[string]string{},
	}, nil
}

// Find returns the first entry whose Description equals desc (case-
// insensitive) or matches its frequency exactly. Useful for the eventual
// signal_library_search tool. Returns nil when no match.
func (l *FreqmanList) Find(query string) *FreqmanEntry {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	if hz, err := strconv.ParseUint(q, 10, 64); err == nil {
		for i := range l.Entries {
			if l.Entries[i].Frequency == hz {
				return &l.Entries[i]
			}
		}
	}
	for i := range l.Entries {
		if strings.ToLower(l.Entries[i].Description) == q {
			return &l.Entries[i]
		}
	}
	return nil
}

// FreqmanMatch is one hit returned by SearchFreqmanDir / FilterEntries.
// File and Line locate the entry within the on-disk library so an
// operator-facing report can render an actionable pointer back into a
// firmware-fork's editor.
type FreqmanMatch struct {
	File  string       `json:"file"`
	Line  int          `json:"line"` // 1-based, matches editor convention.
	Entry FreqmanEntry `json:"entry"`
}

// SearchFreqmanDir walks root recursively, parses every `*.txt` file as a
// Freqman list, and returns matches whose Frequency, RangeStart..RangeEnd
// band, or Description matches the query.
//
// Match rules (case-insensitive on description):
//   - Pure-numeric query: parsed as Hz. Single-frequency entries match on
//     equality. Range entries match when the query Hz falls inside
//     [RangeStart, RangeEnd] inclusive.
//   - Otherwise: substring match against Description.
//
// Files that fail to parse are skipped silently (returned in the optional
// errs slice for the caller's diagnostics) — a single malformed library
// shouldn't blank the whole result set. If limit > 0, results are capped
// at limit; the walk stops early once the cap is hit. A non-existent root
// is not an error and yields zero matches.
//
// All file accesses must remain inside root (filepath.Walk handles that
// natively for non-symlinked trees; symlinks are followed only when they
// resolve back inside root, mirroring the snapshot package's policy).
func SearchFreqmanDir(root, query string, limit int) ([]FreqmanMatch, []error) {
	if root == "" {
		return nil, nil
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}
	q := strings.TrimSpace(query)
	if q == "" {
		return nil, nil
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, []error{err}
	}

	var matches []FreqmanMatch
	var errs []error
	stop := false
	_ = filepath.WalkDir(rootAbs, func(p string, d fs.DirEntry, werr error) error {
		if stop || werr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(p), ".txt") {
			return nil
		}
		// Refuse anything that resolved outside root (defence in depth
		// against tricky symlink trees the OS handed us).
		abs, aerr := filepath.Abs(p)
		if aerr != nil || !strings.HasPrefix(abs, rootAbs+string(filepath.Separator)) && abs != rootAbs {
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, rerr))
			return nil
		}
		list, perr := ParseFreqman(raw)
		if perr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, perr))
			return nil
		}
		hits := filterEntries(list.Entries, q)
		for _, h := range hits {
			matches = append(matches, FreqmanMatch{
				File:  p,
				Line:  lineOfEntry(raw, h.index),
				Entry: h.entry,
			})
			if limit > 0 && len(matches) >= limit {
				stop = true
				return filepath.SkipAll
			}
		}
		return nil
	})
	return matches, errs
}

// indexedEntry pairs an entry with its post-parse position so we can map
// hits back to their source line.
type indexedEntry struct {
	index int
	entry FreqmanEntry
}

func filterEntries(entries []FreqmanEntry, query string) []indexedEntry {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	if hz, err := strconv.ParseUint(q, 10, 64); err == nil {
		var out []indexedEntry
		for i, e := range entries {
			switch {
			case e.Frequency == hz:
				out = append(out, indexedEntry{i, e})
			case e.IsRange() && hz >= e.RangeStart && hz <= e.RangeEnd:
				out = append(out, indexedEntry{i, e})
			}
		}
		return out
	}
	var out []indexedEntry
	for i, e := range entries {
		if strings.Contains(strings.ToLower(e.Description), q) {
			out = append(out, indexedEntry{i, e})
		}
	}
	return out
}

// lineOfEntry returns the 1-based line number of the n-th non-comment,
// non-blank line in raw — matching the rule ParseFreqman uses to discard
// comments + blanks. Used to render an editor-friendly file:line pointer.
func lineOfEntry(raw []byte, entryIndex int) int {
	want := entryIndex
	lineno := 0
	for _, line := range splitLines(raw) {
		lineno++
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if want == 0 {
			return lineno
		}
		want--
	}
	return 0
}

// Sort orders entries by frequency (single first, then range by start).
// Stable on tie so the operator's original order survives within a band.
func (l *FreqmanList) Sort() {
	sort.SliceStable(l.Entries, func(i, j int) bool {
		ai := l.Entries[i].Frequency
		if ai == 0 {
			ai = l.Entries[i].RangeStart
		}
		aj := l.Entries[j].Frequency
		if aj == 0 {
			aj = l.Entries[j].RangeStart
		}
		return ai < aj
	})
}
