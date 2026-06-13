// Package pdfscan triages a PDF for malicious active content — the in-tree
// analogue of Didier Stevens' pdfid.
//
// A weaponised PDF is a top phishing payload: an /OpenAction or /AA that fires
// /JavaScript on open, a /Launch action that runs an external program, an
// /EmbeddedFile dropper, or an /XFA / /AcroForm + /SubmitForm credential form.
// Attackers hide these names with PDF hex-escapes (`/J#61vaScript` == /JavaScript)
// to evade naive grep. This counts the structural and dangerous keywords across
// the raw bytes — de-obfuscating name hex-escapes the way pdfid does — and flags
// the auto-run / payload signatures, without rendering or executing anything.
//
// No confidently-wrong output: the file is recognised only by its `%PDF-` header;
// each keyword is counted by an exact (hex-escape-aware) match, never inferred;
// the obfuscation flag records when a match used a `#XX` escape; the danger
// verdict is a labelled heuristic over the documented active-content keywords (a
// clean scan is not a guarantee of safety — content may sit inside a compressed
// /ObjStm, which is noted). It does not parse object structure or decompress
// streams; it never executes.
//
// Wrap-vs-native: native — a byte scan with PDF-name hex-escape handling; stdlib
// only, no new go.mod dependency. Keyword set + de-obfuscation per pdfid
// (Didier Stevens) and the PDF name-object spec (ISO 32000 §7.3.5).
package pdfscan

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// keywords is the scanned set: structural markers (context) and the
// active-content names that matter for triage.
var keywords = []string{ //nolint:gochecknoglobals
	"obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref",
	"/Page", "/Encrypt", "/ObjStm",
	"/JS", "/JavaScript", "/AA", "/OpenAction", "/AcroForm",
	"/JBIG2Decode", "/RichMedia", "/Launch", "/EmbeddedFile", "/XFA",
	"/URI", "/SubmitForm", "/GoToR", "/GoToE",
}

// dangerKeywords trigger the malicious-content verdict (active code, an external
// launch, a dropped file, or a data-exfil form).
var dangerKeywords = map[string]bool{ //nolint:gochecknoglobals
	"/JS": true, "/JavaScript": true, "/AA": true, "/OpenAction": true,
	"/Launch": true, "/EmbeddedFile": true, "/XFA": true, "/SubmitForm": true,
	"/RichMedia": true, "/GoToR": true, "/GoToE": true,
}

// Keyword is one keyword's tally.
type Keyword struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
	// Obfuscated is true when at least one occurrence used a PDF `#XX` name
	// hex-escape (a strong evasion signal).
	Obfuscated bool `json:"obfuscated,omitempty"`
}

// Result is the PDF triage.
type Result struct {
	Format        string    `json:"format"`
	Version       string    `json:"version,omitempty"`
	Keywords      []Keyword `json:"keywords"`
	Dangerous     bool      `json:"dangerous"`
	DangerReasons []string  `json:"danger_reasons,omitempty"`
	// Obfuscation is true when any keyword was found hex-escaped.
	Obfuscation bool   `json:"name_obfuscation"`
	Note        string `json:"note"`
}

// Scan triages a PDF byte stream.
func Scan(data []byte) (*Result, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pdfscan: empty input")
	}
	hdr := data
	if len(hdr) > 1024 {
		hdr = hdr[:1024]
	}
	idx := bytes.Index(hdr, []byte("%PDF-"))
	if idx < 0 {
		return nil, fmt.Errorf("pdfscan: no %%PDF- header — not a PDF")
	}
	res := &Result{Format: "pdf", Version: pdfVersion(data[idx:])}

	var reasons []string
	for _, kw := range keywords {
		n, obf := countKeyword(data, kw)
		if n == 0 {
			continue
		}
		res.Keywords = append(res.Keywords, Keyword{Name: kw, Count: n, Obfuscated: obf})
		if obf {
			res.Obfuscation = true
		}
		if dangerKeywords[kw] {
			reasons = append(reasons, kw)
		}
	}
	if len(reasons) > 0 {
		sort.Strings(reasons)
		res.Dangerous = true
		res.DangerReasons = reasons
	}
	res.Note = noteFor(res)
	return res, nil
}

// pdfVersion reads the "%PDF-1.x" version after the header.
func pdfVersion(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	end := 5
	for end < len(b) && end < 12 && b[end] != '\r' && b[end] != '\n' && b[end] != ' ' {
		end++
	}
	return string(b[5:end])
}

// countKeyword counts exact occurrences of a keyword, treating a PDF name's
// characters as matchable either literally or as a `#XX` hex-escape (only the
// characters after a leading '/' are name characters). Returns the count and
// whether any match used an escape.
func countKeyword(data []byte, kw string) (int, bool) {
	isName := strings.HasPrefix(kw, "/")
	count, obf := 0, false
	for i := 0; i < len(data); {
		matched, n, used := matchAt(data, i, kw, isName)
		if matched {
			count++
			if used {
				obf = true
			}
			i += n
		} else {
			i++
		}
	}
	return count, obf
}

// matchAt tries to match kw at data[i]. For a name keyword, every character
// after the leading '/' may appear literally or hex-escaped. Returns whether it
// matched, how many input bytes it consumed, and whether an escape was used.
func matchAt(data []byte, i int, kw string, isName bool) (bool, int, bool) {
	p := i
	used := false
	for k := 0; k < len(kw); k++ {
		if p >= len(data) {
			return false, 0, false
		}
		want := kw[k]
		// The leading '/' of a name is structural, never escaped.
		if isName && k == 0 {
			if data[p] != '/' {
				return false, 0, false
			}
			p++
			continue
		}
		switch {
		case data[p] == want:
			p++
		case isName && data[p] == '#' && p+2 < len(data) && hexByte(data[p+1], data[p+2]) == want:
			p += 3
			used = true
		default:
			return false, 0, false
		}
	}
	return true, p - i, used
}

// hexByte decodes two ASCII hex digits, or 0xFF on a non-hex digit (which can
// never equal a printable keyword byte, so the match safely fails).
func hexByte(a, b byte) byte {
	hi, ok1 := hexDigit(a)
	lo, ok2 := hexDigit(b)
	if !ok1 || !ok2 {
		return 0xFF
	}
	return hi<<4 | lo
}

func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func noteFor(res *Result) string {
	base := "Static keyword triage only — the PDF was not rendered or executed. "
	switch {
	case res.Dangerous && res.Obfuscation:
		return base + "SUSPICIOUS: active-content keywords (" + strings.Join(res.DangerReasons, ", ") +
			") AND name hex-escape obfuscation — a strong weaponised-PDF signal. Do not open from an untrusted source."
	case res.Dangerous:
		return base + "Active-content keywords present (" + strings.Join(res.DangerReasons, ", ") +
			") — a PDF that runs JavaScript / launches a program / drops a file on open. Review before opening."
	case res.Obfuscation:
		return base + "Name hex-escape obfuscation present with no flagged active-content keyword — unusual; review."
	default:
		return base + "No active-content keywords found. Not a guarantee of safety — content may be hidden inside a " +
			"compressed object stream (/ObjStm), which is not decompressed here."
	}
}
