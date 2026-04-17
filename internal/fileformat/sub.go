package fileformat

import (
	"fmt"
	"strconv"
	"strings"
)

// SubFile is a parsed Flipper Sub-GHz capture file. Both the structured
// key-file layout and the RAW capture layout share this struct; RawData is
// populated only when the file is a RAW capture (Filetype contains "RAW").
//
// Headers preserves any key:value lines the parser did not promote into a
// strongly-typed field — keeps round-tripping lossless for firmware-fork
// extensions (e.g. Momentum's "Bit Raw Protocol" additions) we don't model.
type SubFile struct {
	Filetype  string
	Version   int
	Frequency uint32
	Preset    string
	Protocol  string
	Bit       int
	Key       string
	TE        int
	RawData   []int32
	Headers   map[string]string
}

// ParseSub parses a Flipper .sub capture. Accepts CRLF, LF, trailing or
// missing final newline, and ignores # comments + blank lines. Unknown
// key:value lines are preserved in Headers so marshal round-trips.
func ParseSub(data []byte) (*SubFile, error) {
	s := &SubFile{Headers: map[string]string{}}
	for _, line := range splitLines(data) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := splitKV(line)
		if !ok {
			continue
		}
		switch key {
		case "Filetype":
			s.Filetype = value
		case "Version":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("sub: invalid Version %q: %w", value, err)
			}
			s.Version = n
		case "Frequency":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("sub: invalid Frequency %q: %w", value, err)
			}
			s.Frequency = uint32(n)
		case "Preset":
			s.Preset = value
		case "Protocol":
			s.Protocol = value
		case "Bit":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("sub: invalid Bit %q: %w", value, err)
			}
			s.Bit = n
		case "Key":
			s.Key = value
		case "TE":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("sub: invalid TE %q: %w", value, err)
			}
			s.TE = n
		case "RAW_Data":
			for _, tok := range strings.Fields(value) {
				n, err := strconv.ParseInt(tok, 10, 32)
				if err != nil {
					return nil, fmt.Errorf("sub: invalid RAW_Data token %q: %w", tok, err)
				}
				s.RawData = append(s.RawData, int32(n))
			}
		default:
			s.Headers[key] = value
		}
	}
	if s.Filetype == "" {
		return nil, fmt.Errorf("sub: missing Filetype header")
	}
	return s, nil
}

// Marshal serializes s back to canonical .sub bytes. Emission order:
// Filetype, Version, Frequency, Preset, Protocol, <headers>, Bit, Key, TE,
// then RAW_Data lines chunked at rawChunkSize samples per line to match the
// Flipper firmware's own output pattern.
func (s *SubFile) Marshal() []byte {
	var b strings.Builder
	writeKV(&b, "Filetype", s.Filetype)
	if s.Version != 0 {
		writeKV(&b, "Version", strconv.Itoa(s.Version))
	}
	if s.Frequency != 0 {
		writeKV(&b, "Frequency", strconv.FormatUint(uint64(s.Frequency), 10))
	}
	if s.Preset != "" {
		writeKV(&b, "Preset", s.Preset)
	}
	if s.Protocol != "" {
		writeKV(&b, "Protocol", s.Protocol)
	}
	for _, k := range sortedKeys(s.Headers) {
		writeKV(&b, k, s.Headers[k])
	}
	if s.Bit != 0 {
		writeKV(&b, "Bit", strconv.Itoa(s.Bit))
	}
	if s.Key != "" {
		writeKV(&b, "Key", s.Key)
	}
	if s.TE != 0 {
		writeKV(&b, "TE", strconv.Itoa(s.TE))
	}
	for _, chunk := range chunkInt32(s.RawData, rawChunkSize) {
		parts := make([]string, len(chunk))
		for i, v := range chunk {
			parts[i] = strconv.FormatInt(int64(v), 10)
		}
		writeKV(&b, "RAW_Data", strings.Join(parts, " "))
	}
	return []byte(b.String())
}

// rawChunkSize is the sample count per RAW_Data line. Matches the firmware's
// chunking: larger lines work but hit firmware CLI buffer limits on replay.
const rawChunkSize = 512

// applySubEdits mutates s in place given a top-level edit map.
// Supported keys: frequency, protocol, key, te, preset.
func applySubEdits(s *SubFile, edits map[string]interface{}) error {
	for k, v := range edits {
		switch strings.ToLower(k) {
		case "frequency":
			n, err := toUint32(v)
			if err != nil {
				return fmt.Errorf("frequency: %w", err)
			}
			s.Frequency = n
		case "protocol":
			str, ok := v.(string)
			if !ok {
				return fmt.Errorf("protocol must be a string")
			}
			s.Protocol = str
		case "key":
			str, ok := v.(string)
			if !ok {
				return fmt.Errorf("key must be a string")
			}
			s.Key = str
		case "te":
			n, err := toInt(v)
			if err != nil {
				return fmt.Errorf("te: %w", err)
			}
			s.TE = n
		case "preset":
			str, ok := v.(string)
			if !ok {
				return fmt.Errorf("preset must be a string")
			}
			s.Preset = str
		default:
			return fmt.Errorf("unknown .sub edit key %q (allowed: frequency, protocol, key, te, preset)", k)
		}
	}
	return nil
}
