package flipper

import (
	"regexp"
	"strconv"
	"strings"
)

// Deterministic parsers for Flipper CLI output (P1-17 follow-up).
// Each parser converts a free-form response into a typed Go value so
// the agent can ship structured JSON to the model instead of the raw
// serial transcript. Parsers are forgiving: unknown lines preserve in
// RawLines / RawExcerpt fields, structural failures return zero values
// without erroring so the LLM still has the raw string to reason
// over.

// ----- NFC detect (scanner) -----

// NFCDetectResult captures the structured shape of an NFC subshell
// scanner response. At least one of UID/Type is set when a card was
// detected.
type NFCDetectResult struct {
	Detected   bool   `json:"detected"`
	Type       string `json:"type,omitempty"`       // "NTAG215", "MIFARE Classic 1K", ...
	Technology string `json:"technology,omitempty"` // "ISO14443-3a (NFC-A)" etc.
	UID        string `json:"uid,omitempty"`
	ATQA       string `json:"atqa,omitempty"`
	SAK        string `json:"sak,omitempty"`
	Raw        string `json:"raw,omitempty"`
}

var (
	nfcUIDRE      = regexp.MustCompile(`(?im)^\s*UID\s*[:=]\s*([0-9a-fA-F\s:]+)\s*$`)
	nfcATQARE     = regexp.MustCompile(`(?im)^\s*ATQA\s*[:=]\s*([0-9a-fA-F\s:]+)\s*$`)
	nfcSAKRE      = regexp.MustCompile(`(?im)^\s*SAK\s*[:=]\s*([0-9a-fA-F\s:]+)\s*$`)
	nfcTypeRE     = regexp.MustCompile(`(?im)^\s*Type\s*[:=]\s*(.+)\s*$`)
	nfcTechRE     = regexp.MustCompile(`\[([^\]]+)\]`)
	nfcNotFoundRE = regexp.MustCompile(`(?i)(target lost|no.{0,10}(tag|card)|not found|timeout)`)
)

// ParseNFCDetect parses the output of the nfc subshell scanner
// subcommand into a structured result. A successfully parsed card
// sets Detected=true plus whatever fields the firmware emitted;
// empty / timeout output sets Detected=false.
func ParseNFCDetect(raw string) NFCDetectResult {
	r := NFCDetectResult{Raw: strings.TrimSpace(raw)}

	if m := nfcUIDRE.FindStringSubmatch(raw); m != nil {
		r.UID = normaliseNFCHex(m[1])
	}
	if m := nfcATQARE.FindStringSubmatch(raw); m != nil {
		r.ATQA = normaliseNFCHex(m[1])
	}
	if m := nfcSAKRE.FindStringSubmatch(raw); m != nil {
		r.SAK = normaliseNFCHex(m[1])
	}
	if m := nfcTypeRE.FindStringSubmatch(raw); m != nil {
		r.Type = strings.TrimSpace(m[1])
	}
	if m := nfcTechRE.FindStringSubmatch(raw); m != nil {
		r.Technology = strings.TrimSpace(m[1])
	}

	// A card is detected when we saw *any* of the identifying fields.
	// The "target lost" / "no tag" / "timeout" patterns explicitly
	// clear Detected even if a leftover UID line was captured from a
	// prior scan.
	r.Detected = r.UID != "" || r.Type != ""
	if nfcNotFoundRE.MatchString(raw) {
		r.Detected = false
	}
	return r
}

// normaliseNFCHex strips whitespace, separators, and lowercases, then
// re-formats as space-separated upper-case byte pairs. Odd-length
// inputs are returned trimmed-but-unformatted so the caller can still
// see the raw hex in the audit log.
func normaliseNFCHex(s string) string {
	cleaned := strings.NewReplacer(" ", "", "\t", "", ":", "").Replace(s)
	cleaned = strings.TrimSpace(strings.ToUpper(cleaned))
	if cleaned == "" {
		return ""
	}
	if len(cleaned)%2 != 0 {
		return cleaned // odd-length — return as-is for audit visibility
	}
	var b strings.Builder
	for i := 0; i < len(cleaned); i += 2 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(cleaned[i : i+2])
	}
	return b.String()
}

// ----- storage stat -----

// StorageStatResult captures the structured shape of `storage stat
// <path>` output. The Flipper firmware emits a short line per
// attribute: "File, size: 1234" for regular files, "Directory" for
// directories, "Storage error: <msg>" on failure.
type StorageStatResult struct {
	Exists    bool   `json:"exists"`
	IsDir     bool   `json:"is_dir"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
	Error     string `json:"error,omitempty"`
	Raw       string `json:"raw,omitempty"`
}

var (
	storageSizeRE  = regexp.MustCompile(`(?i)size\s*[:=]?\s*(\d+)`)
	storageErrorRE = regexp.MustCompile(`(?im)^\s*Storage error:\s*(.+)$`)
	storageDirRE   = regexp.MustCompile(`(?im)^\s*Directory\s*$`)
	storageFileRE  = regexp.MustCompile(`(?im)^\s*File`)
)

// ParseStorageStat parses `storage stat <path>` output. Order matters:
// the "Storage error:" check runs FIRST so interleaved output like
// "File\nStorage error: not found" (seen on some firmware forks)
// doesn't produce a false-positive Exists=true. When both markers
// appear, the error takes precedence — the file-regex matches anywhere
// on any line (case-insensitive), so a naked File/Directory check
// without the error gate would misclassify the error path.
func ParseStorageStat(raw string) StorageStatResult {
	r := StorageStatResult{Raw: strings.TrimSpace(raw)}
	// Error path wins: even if a "File" line is present, an error
	// banner means the path doesn't resolve.
	if m := storageErrorRE.FindStringSubmatch(raw); m != nil {
		r.Error = strings.TrimSpace(m[1])
		return r
	}
	if storageDirRE.MatchString(raw) {
		r.Exists = true
		r.IsDir = true
		return r
	}
	if storageFileRE.MatchString(raw) {
		r.Exists = true
		if m := storageSizeRE.FindStringSubmatch(raw); m != nil {
			if n, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				r.SizeBytes = n
			}
		}
		return r
	}
	// No recognisable header — treat as unknown; Exists stays false.
	return r
}

// ----- subghz receive (summary) -----

// SubGHzReceiveResult summarises the output of `subghz rx` / the
// subghz_receive tool. The Flipper emits detected protocol candidates
// as blocks like:
//
//	[Protocol: Princeton]
//	  Frequency: 433920000
//	  Key: 00 00 00 1A 2B 3C 4D 00
//	  Bit: 24
//
// The parser collects one Candidate per block; unstructured noise
// lines go into RawLines.
type SubGHzReceiveResult struct {
	Candidates []SubGHzCandidate `json:"candidates,omitempty"`
	Count      int               `json:"count"`
	RawLines   []string          `json:"raw_lines,omitempty"`
}

// SubGHzCandidate is one detected protocol / key block.
type SubGHzCandidate struct {
	Protocol  string `json:"protocol,omitempty"`
	Frequency uint32 `json:"frequency,omitempty"`
	Key       string `json:"key,omitempty"`
	Bit       int    `json:"bit,omitempty"`
	TE        int    `json:"te,omitempty"`
	RSSI      int    `json:"rssi,omitempty"`
}

var (
	sgProtocolRE  = regexp.MustCompile(`(?i)\[?\s*Protocol\s*[:=]\s*([^,\]\n]+)`)
	sgFrequencyRE = regexp.MustCompile(`(?i)Frequency\s*[:=]\s*(\d+)`)
	sgKeyRE       = regexp.MustCompile(`(?im)^\s*Key\s*[:=]\s*([0-9a-fA-F\s]+)$`)
	sgBitRE       = regexp.MustCompile(`(?i)Bit\s*[:=]\s*(\d+)`)
	sgTERE        = regexp.MustCompile(`(?i)(?:^|\s)TE\s*[:=]\s*(\d+)`)
	sgRSSIRE      = regexp.MustCompile(`(?i)RSSI\s*[:=]\s*(-?\d+)`)
)

// ParseSubGHzReceive parses the output of subghz_receive. Detects
// one or more "Protocol:" blocks and extracts the common fields of
// each. Lines that don't belong to a block are preserved in
// RawLines.
func ParseSubGHzReceive(raw string) SubGHzReceiveResult {
	res := SubGHzReceiveResult{}

	// Split into blocks on "Protocol:" markers. Anything before the
	// first Protocol line is preserved as a header segment; anything
	// with no Protocol line at all returns zero candidates.
	text := strings.TrimSpace(raw)
	if text == "" {
		return res
	}

	// Find every Protocol start.
	matches := sgProtocolRE.FindAllStringIndex(text, -1)
	if len(matches) == 0 {
		// No protocol candidates — every line is "raw".
		for _, line := range strings.Split(text, "\n") {
			if trimmed := strings.TrimSpace(line); trimmed != "" {
				res.RawLines = append(res.RawLines, trimmed)
			}
		}
		return res
	}

	// Slice into one block per protocol hit.
	for i, m := range matches {
		start := m[0]
		end := len(text)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		block := text[start:end]
		res.Candidates = append(res.Candidates, parseSubGHzBlock(block))
	}
	res.Count = len(res.Candidates)
	return res
}

func parseSubGHzBlock(block string) SubGHzCandidate {
	c := SubGHzCandidate{}
	if m := sgProtocolRE.FindStringSubmatch(block); m != nil {
		c.Protocol = strings.TrimSpace(strings.Trim(m[1], "]"))
	}
	if m := sgFrequencyRE.FindStringSubmatch(block); m != nil {
		if n, err := strconv.ParseUint(m[1], 10, 32); err == nil {
			c.Frequency = uint32(n)
		}
	}
	if m := sgKeyRE.FindStringSubmatch(block); m != nil {
		c.Key = normaliseNFCHex(m[1])
	}
	if m := sgBitRE.FindStringSubmatch(block); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			c.Bit = n
		}
	}
	if m := sgTERE.FindStringSubmatch(block); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			c.TE = n
		}
	}
	if m := sgRSSIRE.FindStringSubmatch(block); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			c.RSSI = n
		}
	}
	return c
}
