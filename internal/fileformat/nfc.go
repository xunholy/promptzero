package fileformat

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// NFCFile is a parsed Flipper NFC capture. Block contents stay as the raw
// space-separated hex strings so a round-trip preserves exactly what came
// off the wire; block numbers are their integer position for easy edits.
type NFCFile struct {
	Filetype   string
	Version    int
	DeviceType string
	UID        string
	ATQA       string
	SAK        string
	MifareType string
	Blocks     map[int]string
	Headers    map[string]string
}

// ParseNFC parses a Flipper .nfc capture file. Accepts CRLF, LF, missing
// final newline, # comments, and blank lines. Block lines ("Block 0: ...")
// become entries in Blocks; unknown headers fall through to Headers so
// round-tripping is lossless.
func ParseNFC(data []byte) (*NFCFile, error) {
	n := &NFCFile{Blocks: map[int]string{}, Headers: map[string]string{}}
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
			n.Filetype = value
		case "Version":
			v, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("nfc: invalid Version %q: %w", value, err)
			}
			n.Version = v
		case "Device type":
			n.DeviceType = value
		case "UID":
			n.UID = value
		case "ATQA":
			n.ATQA = value
		case "SAK":
			n.SAK = value
		case "Mifare Classic type", "Mifare Ultralight type":
			n.MifareType = value
		default:
			if strings.HasPrefix(key, "Block ") {
				idxStr := strings.TrimSpace(strings.TrimPrefix(key, "Block "))
				idx, err := strconv.Atoi(idxStr)
				if err != nil {
					return nil, fmt.Errorf("nfc: invalid block index %q: %w", idxStr, err)
				}
				n.Blocks[idx] = value
				continue
			}
			n.Headers[key] = value
		}
	}
	if n.Filetype == "" {
		return nil, fmt.Errorf("nfc: missing Filetype header")
	}
	return n, nil
}

// Marshal serializes n back to canonical .nfc bytes. Core headers come
// first (Filetype → Version → Device type → UID → ATQA → SAK → MifareType),
// then unknown headers in sorted order, then Block lines in ascending
// numeric order.
func (n *NFCFile) Marshal() []byte {
	var b strings.Builder
	writeKV(&b, "Filetype", n.Filetype)
	if n.Version != 0 {
		writeKV(&b, "Version", strconv.Itoa(n.Version))
	}
	if n.DeviceType != "" {
		writeKV(&b, "Device type", n.DeviceType)
	}
	if n.UID != "" {
		writeKV(&b, "UID", n.UID)
	}
	if n.ATQA != "" {
		writeKV(&b, "ATQA", n.ATQA)
	}
	if n.SAK != "" {
		writeKV(&b, "SAK", n.SAK)
	}
	if n.MifareType != "" {
		// Device type hints which sub-key is canonical; default to Classic
		// since it's by far the most common capture type.
		label := "Mifare Classic type"
		if strings.Contains(strings.ToLower(n.DeviceType), "ultralight") {
			label = "Mifare Ultralight type"
		}
		writeKV(&b, label, n.MifareType)
	}
	for _, k := range sortedKeys(n.Headers) {
		writeKV(&b, k, n.Headers[k])
	}
	indices := make([]int, 0, len(n.Blocks))
	for k := range n.Blocks {
		indices = append(indices, k)
	}
	sort.Ints(indices)
	for _, idx := range indices {
		writeKV(&b, fmt.Sprintf("Block %d", idx), n.Blocks[idx])
	}
	return []byte(b.String())
}

func applyNFCEdits(n *NFCFile, edits map[string]interface{}) error {
	for k, v := range edits {
		lk := strings.ToLower(k)
		switch {
		case lk == "uid":
			str, ok := v.(string)
			if !ok {
				return fmt.Errorf("uid must be a string")
			}
			n.UID = str
		case lk == "atqa":
			str, ok := v.(string)
			if !ok {
				return fmt.Errorf("atqa must be a string")
			}
			n.ATQA = str
		case lk == "sak":
			str, ok := v.(string)
			if !ok {
				return fmt.Errorf("sak must be a string")
			}
			n.SAK = str
		case lk == "device_type":
			str, ok := v.(string)
			if !ok {
				return fmt.Errorf("device_type must be a string")
			}
			n.DeviceType = str
		case strings.HasPrefix(lk, "block_"):
			idxStr := strings.TrimPrefix(lk, "block_")
			idx, err := strconv.Atoi(idxStr)
			if err != nil {
				return fmt.Errorf("block edit key %q: invalid index %q", k, idxStr)
			}
			str, ok := v.(string)
			if !ok {
				return fmt.Errorf("block_%d must be a string", idx)
			}
			n.Blocks[idx] = str
		default:
			return fmt.Errorf("unknown .nfc edit key %q (allowed: uid, atqa, sak, device_type, block_<n>)", k)
		}
	}
	return nil
}
