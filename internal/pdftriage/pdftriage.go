// Package pdftriage decodes a PDF's standard-security encryption dictionary into
// its password-cracking triage facts.
//
// Encrypted PDFs (financial, legal, scanned documents) are among the most
// common high-value loot artifacts, and the operator's first question is "can I
// crack this, and with which hashcat mode?". The answer is fully determined by
// the PDF Standard security handler's algorithm (/V), revision (/R), key length,
// and — for /V 4 — the crypt-filter method (/CFM): RC4-40 (R2) → hashcat 10400,
// RC4-128 (R3, or R4 with /V2) → 10500, AES-128 (R4 with /AESV2) → 10600, and
// AES-256 (R5/R6, /AESV3) → 10700. This extracts those parameters offline.
//
// The PDF spec (ISO 32000-1 §7.6.1) requires the /Encrypt dictionary to be a
// DIRECT, uncompressed object — it must be readable before anything else can be
// decrypted — so scanning the raw bytes for the `/Filter /Standard` handler
// dictionary is reliable, not a heuristic shortcut.
//
// No confidently-wrong output: it reports the encryption *parameters* only — it
// does not crack, decrypt, or emit the pdf2john hash; a PDF with no /Encrypt is
// reported as not password-protected (nothing to crack); a non-Standard
// (public-key) handler is named but not given a password hashcat mode; and
// non-PDF input is rejected.
//
// Wrap-vs-native: native — a byte scan over the documented PDF encryption
// dictionary; stdlib only, no new go.mod dependency. Anchored to real
// pikepdf/qpdf-generated encrypted PDFs (R4 RC4, R4 AES-128, R6 AES-256).
package pdftriage

import (
	"bytes"
	"fmt"
	"strconv"
)

// Result is the decoded PDF encryption posture.
type Result struct {
	Format          string `json:"format"`
	PDFVersion      string `json:"pdf_version,omitempty"`
	Encrypted       bool   `json:"encrypted"`
	SecurityHandler string `json:"security_handler,omitempty"`

	V       int `json:"v,omitempty"`
	R       int `json:"r,omitempty"`
	KeyBits int `json:"key_bits,omitempty"`

	Cipher      string `json:"cipher,omitempty"`
	Permissions int    `json:"permissions,omitempty"`

	HashcatMode     int    `json:"hashcat_mode"`
	HashcatModeNote string `json:"hashcat_mode_note,omitempty"`
	JohnTool        string `json:"john_tool"`
	Note            string `json:"note"`
}

// Decode parses a PDF's encryption dictionary from its raw bytes.
func Decode(raw []byte) (*Result, error) {
	if !bytes.HasPrefix(raw, []byte("%PDF-")) {
		return nil, fmt.Errorf("pdftriage: not a PDF (missing %%PDF- header)")
	}
	res := &Result{
		Format:     "PDF",
		PDFVersion: parseVersion(raw),
		JohnTool:   "pdf2john",
		Note: "Encryption parameters only — the PDF is not cracked or decrypted, and the pdf2john hash is " +
			"not emitted.",
	}

	std := indexStandardHandler(raw)
	if std < 0 {
		if bytes.Contains(raw, []byte("/Encrypt")) {
			res.Encrypted = true
			res.SecurityHandler = detectHandler(raw)
			res.Note = "Encrypted, but not with the password-based Standard security handler (" +
				res.SecurityHandler + ") — no password hashcat mode applies. " + res.Note
			return res, nil
		}
		res.Note = "No /Encrypt dictionary — the PDF is not password-protected, so there is nothing to crack. " + res.Note
		return res, nil
	}

	res.Encrypted = true
	res.SecurityHandler = "Standard"
	obj := enclosingObject(raw, std)
	res.V = intAfter(obj, "/V")
	res.R = intAfter(obj, "/R")
	// The encryption dict's /Length is the key length in BITS (40/128/256);
	// the nested /CF /StdCF /Length is the same key in BYTES (5/16/32) and can
	// appear first. The bit-length is always the larger, so take the max.
	res.KeyBits = maxIntAfter(obj, "/Length", 40)
	res.Permissions = intAfter(obj, "/P")
	classify(res, nameAfter(obj, "/CFM"))
	return res, nil
}

// classify derives the cipher and hashcat mode from the Standard handler's
// algorithm/revision and (for V4) the crypt-filter method.
func classify(res *Result, cfm string) {
	switch {
	case res.V == 1 || res.R == 2:
		res.Cipher = "RC4-40"
		res.HashcatMode = 10400
		res.HashcatModeNote = "PDF 1.1-1.3 (Acrobat 2-4), RC4-40 — hashcat -m 10400. Weak; very fast to attack."
	case res.R == 3:
		res.Cipher = fmt.Sprintf("RC4-%d", res.KeyBits)
		res.HashcatMode = 10500
		res.HashcatModeNote = "PDF 1.4-1.6 (Acrobat 5-8), RC4 — hashcat -m 10500."
	case res.R == 4:
		if cfm == "AESV2" {
			res.Cipher = "AES-128"
			res.HashcatMode = 10600
			res.HashcatModeNote = "PDF 1.7 Level 3 (Acrobat 9), AES-128 — hashcat -m 10600."
		} else {
			res.Cipher = fmt.Sprintf("RC4-%d", res.KeyBits)
			res.HashcatMode = 10500
			res.HashcatModeNote = "PDF 1.4-1.6 (Acrobat 5-8), RC4 (V4 crypt filter) — hashcat -m 10500."
		}
	case res.R == 5 || res.R == 6:
		res.Cipher = "AES-256"
		res.HashcatMode = 10700
		res.HashcatModeNote = "PDF 1.7 Level 8 (Acrobat 10-11), AES-256 — hashcat -m 10700 (the strongest PDF scheme)."
	default:
		res.HashcatModeNote = fmt.Sprintf("unrecognised Standard handler revision R=%d / V=%d; no hashcat mode assigned.", res.R, res.V)
	}
}

// parseVersion returns the version digits after the %PDF- header (e.g. "1.7").
func parseVersion(raw []byte) string {
	end := 5
	for end < len(raw) && end < 12 {
		c := raw[end]
		if (c >= '0' && c <= '9') || c == '.' {
			end++
			continue
		}
		break
	}
	return string(raw[5:end])
}

// indexStandardHandler returns the offset of the "/Standard" security-handler
// name when it is preceded (within a short window) by "/Filter", else -1.
func indexStandardHandler(raw []byte) int {
	off := 0
	for {
		i := bytes.Index(raw[off:], []byte("/Standard"))
		if i < 0 {
			return -1
		}
		abs := off + i
		lo := abs - 32
		if lo < 0 {
			lo = 0
		}
		if bytes.Contains(raw[lo:abs], []byte("/Filter")) {
			return abs
		}
		off = abs + len("/Standard")
	}
}

// detectHandler names a non-Standard security handler when one is present.
func detectHandler(raw []byte) string {
	switch {
	case bytes.Contains(raw, []byte("/Adobe.PubSec")), bytes.Contains(raw, []byte("/Adobe.PPKLite")):
		return "public-key (Adobe.PubSec)"
	default:
		return "non-Standard / unknown"
	}
}

// enclosingObject returns the `N G obj … endobj` slice containing idx, or a
// bounded window around idx when the object delimiters cannot be located.
func enclosingObject(raw []byte, idx int) []byte {
	start := bytes.LastIndex(raw[:idx], []byte(" obj"))
	if start < 0 {
		start = idx - 400
		if start < 0 {
			start = 0
		}
	}
	endRel := bytes.Index(raw[idx:], []byte("endobj"))
	var end int
	if endRel < 0 {
		end = idx + 500
		if end > len(raw) {
			end = len(raw)
		}
	} else {
		end = idx + endRel
	}
	return raw[start:end]
}

// intAfter parses the integer token following key (key must be followed by
// whitespace so "/V" never matches "/Version"). Returns 0 if not found.
func intAfter(seg []byte, key string) int {
	return intAfterDefault(seg, key, 0)
}

// intAfterDefault is intAfter with a configurable default.
func intAfterDefault(seg []byte, key string, def int) int {
	off := 0
	for {
		i := bytes.Index(seg[off:], []byte(key))
		if i < 0 {
			return def
		}
		p := off + i + len(key)
		if p >= len(seg) || !isPDFSpace(seg[p]) {
			off = off + i + len(key)
			continue
		}
		for p < len(seg) && isPDFSpace(seg[p]) {
			p++
		}
		start := p
		if p < len(seg) && (seg[p] == '-' || seg[p] == '+') {
			p++
		}
		for p < len(seg) && seg[p] >= '0' && seg[p] <= '9' {
			p++
		}
		if p == start || (p == start+1 && (seg[start] < '0' || seg[start] > '9')) {
			off = off + i + len(key)
			continue
		}
		if v, err := strconv.Atoi(string(seg[start:p])); err == nil {
			return v
		}
		off = off + i + len(key)
	}
}

// maxIntAfter returns the largest integer token following any occurrence of
// key, or def when there are none.
func maxIntAfter(seg []byte, key string, def int) int {
	best, found := def, false
	off := 0
	for {
		i := bytes.Index(seg[off:], []byte(key))
		if i < 0 {
			break
		}
		p := off + i + len(key)
		off = p
		if p >= len(seg) || !isPDFSpace(seg[p]) {
			continue
		}
		for p < len(seg) && isPDFSpace(seg[p]) {
			p++
		}
		start := p
		for p < len(seg) && seg[p] >= '0' && seg[p] <= '9' {
			p++
		}
		if p == start {
			continue
		}
		if v, err := strconv.Atoi(string(seg[start:p])); err == nil {
			if !found || v > best {
				best, found = v, true
			}
		}
	}
	return best
}

// nameAfter returns the PDF name token following key (e.g. /CFM /AESV2 → "AESV2").
func nameAfter(seg []byte, key string) string {
	i := bytes.Index(seg, []byte(key))
	if i < 0 {
		return ""
	}
	p := i + len(key)
	for p < len(seg) && isPDFSpace(seg[p]) {
		p++
	}
	if p >= len(seg) || seg[p] != '/' {
		return ""
	}
	p++
	start := p
	for p < len(seg) && !isPDFSpace(seg[p]) && seg[p] != '/' && seg[p] != '>' && seg[p] != '<' {
		p++
	}
	return string(seg[start:p])
}

// isPDFSpace reports whether b is PDF whitespace.
func isPDFSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '\f', 0:
		return true
	}
	return false
}
