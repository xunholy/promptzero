package fileformat

import (
	"fmt"
	"strconv"
	"strings"
)

// RFIDFile is a parsed Flipper .rfid (125 kHz LF) capture.
type RFIDFile struct {
	Filetype string
	Version  int
	KeyType  string
	Data     string
	Headers  map[string]string
}

// ParseRFID parses a Flipper .rfid file. Accepts CRLF, LF, a missing final
// newline, and # comments.
func ParseRFID(data []byte) (*RFIDFile, error) {
	r := &RFIDFile{Headers: map[string]string{}}
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
			r.Filetype = value
		case "Version":
			v, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("rfid: invalid Version %q: %w", value, err)
			}
			r.Version = v
		case "Key type":
			r.KeyType = value
		case "Data":
			r.Data = value
		default:
			r.Headers[key] = value
		}
	}
	if r.Filetype == "" {
		return nil, fmt.Errorf("rfid: missing Filetype header")
	}
	return r, nil
}

// Marshal serializes r back to canonical .rfid bytes.
func (r *RFIDFile) Marshal() []byte {
	var b strings.Builder
	writeKV(&b, "Filetype", r.Filetype)
	if r.Version != 0 {
		writeKV(&b, "Version", strconv.Itoa(r.Version))
	}
	if r.KeyType != "" {
		writeKV(&b, "Key type", r.KeyType)
	}
	if r.Data != "" {
		writeKV(&b, "Data", r.Data)
	}
	for _, k := range sortedKeys(r.Headers) {
		writeKV(&b, k, r.Headers[k])
	}
	return []byte(b.String())
}

func applyRFIDEdits(r *RFIDFile, edits map[string]interface{}) error {
	for k, v := range edits {
		switch strings.ToLower(k) {
		case "key_type":
			str, ok := v.(string)
			if !ok {
				return fmt.Errorf("key_type must be a string")
			}
			r.KeyType = str
		case "data":
			str, ok := v.(string)
			if !ok {
				return fmt.Errorf("data must be a string")
			}
			r.Data = str
		default:
			return fmt.Errorf("unknown .rfid edit key %q (allowed: key_type, data)", k)
		}
	}
	return nil
}
