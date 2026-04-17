// Package fileformat gives the PromptZero agent structural access to the
// Flipper file formats it already ships with — .sub, .nfc, .ir, .rfid. Raw
// `storage read` gives the LLM one giant string; these parsers surface the
// individual fields + blocks so the model can reason about them (change a
// frequency, blank a block, rename a signal) without string manipulation.
//
// Every format follows the same shape:
//   - Parse<T>(data []byte) (*T, error)  — tolerant line-oriented parser.
//   - (*T).Marshal() []byte              — canonical serializer; round-trip
//     equal under Parse(Marshal(Parse(x))) but not guaranteed byte-for-byte
//     identical to the input.
//   - apply<T>Edits(*T, map[string]interface{}) error — validates and
//     applies a top-level edit map; unknown keys fail loudly so the LLM
//     cannot silently no-op.
package fileformat

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Format identifies one of the four supported file formats. Returned by
// DetectFormat and LoadFile so callers don't have to re-sniff extensions.
type Format string

const (
	FormatSub  Format = "sub"
	FormatNFC  Format = "nfc"
	FormatIR   Format = "ir"
	FormatRFID Format = "rfid"
)

// LoadFile parses raw bytes based on path's extension and returns one of
// *SubFile / *NFCFile / *IRFile / *RFIDFile, plus the detected format.
// Unknown extensions yield an error so callers can stay strict.
func LoadFile(path string, raw []byte) (any, Format, error) {
	format, err := DetectFormat(path)
	if err != nil {
		return nil, "", err
	}
	switch format {
	case FormatSub:
		f, err := ParseSub(raw)
		return f, format, err
	case FormatNFC:
		f, err := ParseNFC(raw)
		return f, format, err
	case FormatIR:
		f, err := ParseIR(raw)
		return f, format, err
	case FormatRFID:
		f, err := ParseRFID(raw)
		return f, format, err
	}
	return nil, "", fmt.Errorf("unsupported format %q", format)
}

// SaveFile serializes a previously-parsed model back to bytes.
func SaveFile(format Format, model any) ([]byte, error) {
	switch format {
	case FormatSub:
		s, ok := model.(*SubFile)
		if !ok {
			return nil, fmt.Errorf("SaveFile: expected *SubFile, got %T", model)
		}
		return s.Marshal(), nil
	case FormatNFC:
		n, ok := model.(*NFCFile)
		if !ok {
			return nil, fmt.Errorf("SaveFile: expected *NFCFile, got %T", model)
		}
		return n.Marshal(), nil
	case FormatIR:
		i, ok := model.(*IRFile)
		if !ok {
			return nil, fmt.Errorf("SaveFile: expected *IRFile, got %T", model)
		}
		return i.Marshal(), nil
	case FormatRFID:
		r, ok := model.(*RFIDFile)
		if !ok {
			return nil, fmt.Errorf("SaveFile: expected *RFIDFile, got %T", model)
		}
		return r.Marshal(), nil
	}
	return nil, fmt.Errorf("unsupported format %q", format)
}

// DetectFormat inspects path's extension and returns the matching Format.
// Case-insensitive.
func DetectFormat(path string) (Format, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".sub":
		return FormatSub, nil
	case ".nfc":
		return FormatNFC, nil
	case ".ir":
		return FormatIR, nil
	case ".rfid":
		return FormatRFID, nil
	}
	return "", fmt.Errorf("unrecognised file extension %q (want .sub, .nfc, .ir, or .rfid)", ext)
}

// ApplyEdits dispatches the edit map to the format-specific applier.
// Unknown edit keys return an error — never silently ignored.
func ApplyEdits(format Format, model any, edits map[string]interface{}) error {
	if len(edits) == 0 {
		return fmt.Errorf("edits map is empty")
	}
	switch format {
	case FormatSub:
		s, ok := model.(*SubFile)
		if !ok {
			return fmt.Errorf("ApplyEdits: expected *SubFile, got %T", model)
		}
		return applySubEdits(s, edits)
	case FormatNFC:
		n, ok := model.(*NFCFile)
		if !ok {
			return fmt.Errorf("ApplyEdits: expected *NFCFile, got %T", model)
		}
		return applyNFCEdits(n, edits)
	case FormatIR:
		i, ok := model.(*IRFile)
		if !ok {
			return fmt.Errorf("ApplyEdits: expected *IRFile, got %T", model)
		}
		return applyIREdits(i, edits)
	case FormatRFID:
		r, ok := model.(*RFIDFile)
		if !ok {
			return fmt.Errorf("ApplyEdits: expected *RFIDFile, got %T", model)
		}
		return applyRFIDEdits(r, edits)
	}
	return fmt.Errorf("unsupported format %q", format)
}

// --- Shared parser helpers ---

// splitLines splits data on either LF or CRLF boundaries. Unlike
// strings.Split(string(data), "\n") it drops a trailing empty element when
// the input ends with a terminator so callers needn't special-case "missing
// final newline".
func splitLines(data []byte) []string {
	s := string(data)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// splitKV parses a "Key: value" line. The first ":" is the separator —
// remaining colons stay inside value. Returns false if no colon is present.
func splitKV(line string) (key, value string, ok bool) {
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
}

// writeKV appends a canonical "Key: value\n" line.
func writeKV(b *strings.Builder, key, value string) {
	b.WriteString(key)
	b.WriteString(": ")
	b.WriteString(value)
	b.WriteByte('\n')
}

// sortedKeys returns m's keys in sorted order — used so Marshal is
// deterministic regardless of insertion order.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// chunkInt32 slices s into successive sub-slices of length n (last may be
// shorter). Returns nil when s is empty so callers emit zero RAW_Data lines
// for a non-raw capture.
func chunkInt32(s []int32, n int) [][]int32 {
	if len(s) == 0 || n <= 0 {
		return nil
	}
	var out [][]int32
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}

// toInt coerces a JSON-decoded value into an int. Handles both the
// float64 values encoding/json produces by default and string forms (when
// the LLM stringifies numerics).
func toInt(v interface{}) (int, error) {
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return 0, fmt.Errorf("cannot parse %q as int: %w", n, err)
		}
		return i, nil
	}
	return 0, fmt.Errorf("expected integer, got %T", v)
}

// toUint32 coerces a JSON-decoded value into uint32. Rejects negatives.
func toUint32(v interface{}) (uint32, error) {
	switch n := v.(type) {
	case float64:
		if n < 0 {
			return 0, fmt.Errorf("negative value %v", n)
		}
		return uint32(n), nil
	case int:
		if n < 0 {
			return 0, fmt.Errorf("negative value %v", n)
		}
		return uint32(n), nil
	case int64:
		if n < 0 {
			return 0, fmt.Errorf("negative value %v", n)
		}
		return uint32(n), nil
	case string:
		parsed, err := strconv.ParseUint(strings.TrimSpace(n), 10, 32)
		if err != nil {
			return 0, fmt.Errorf("cannot parse %q as uint32: %w", n, err)
		}
		return uint32(parsed), nil
	}
	return 0, fmt.Errorf("expected integer, got %T", v)
}
