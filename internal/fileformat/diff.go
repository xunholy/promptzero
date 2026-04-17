package fileformat

import (
	"fmt"
	"sort"
)

// DiffEntry is one field-level difference between two parsed files.
// AField / BField hold the rendered values; Same is true iff they match.
type DiffEntry struct {
	Field  string `json:"field"`
	AField string `json:"a"`
	BField string `json:"b"`
	Same   bool   `json:"same"`
}

// DiffResult is the structural comparison of two parsed models. Format
// mismatches surface as SameFormat=false and an empty Entries slice.
type DiffResult struct {
	FormatA    Format      `json:"format_a"`
	FormatB    Format      `json:"format_b"`
	SameFormat bool        `json:"same_format"`
	Entries    []DiffEntry `json:"entries"`
}

// Diff compares two previously parsed models and returns per-field
// differences. Only the intersection of fields defined for a format is
// inspected — block/signal collections are expanded so the caller can see
// per-index changes. Format mismatches short-circuit with SameFormat=false.
func Diff(aFormat Format, a any, bFormat Format, b any) (*DiffResult, error) {
	out := &DiffResult{FormatA: aFormat, FormatB: bFormat, SameFormat: aFormat == bFormat}
	if !out.SameFormat {
		return out, nil
	}
	switch aFormat {
	case FormatSub:
		sa, ok := a.(*SubFile)
		if !ok {
			return nil, fmt.Errorf("Diff: a is not *SubFile")
		}
		sb, ok := b.(*SubFile)
		if !ok {
			return nil, fmt.Errorf("Diff: b is not *SubFile")
		}
		out.Entries = diffSub(sa, sb)
	case FormatNFC:
		na, ok := a.(*NFCFile)
		if !ok {
			return nil, fmt.Errorf("Diff: a is not *NFCFile")
		}
		nb, ok := b.(*NFCFile)
		if !ok {
			return nil, fmt.Errorf("Diff: b is not *NFCFile")
		}
		out.Entries = diffNFC(na, nb)
	case FormatIR:
		ia, ok := a.(*IRFile)
		if !ok {
			return nil, fmt.Errorf("Diff: a is not *IRFile")
		}
		ib, ok := b.(*IRFile)
		if !ok {
			return nil, fmt.Errorf("Diff: b is not *IRFile")
		}
		out.Entries = diffIR(ia, ib)
	case FormatRFID:
		ra, ok := a.(*RFIDFile)
		if !ok {
			return nil, fmt.Errorf("Diff: a is not *RFIDFile")
		}
		rb, ok := b.(*RFIDFile)
		if !ok {
			return nil, fmt.Errorf("Diff: b is not *RFIDFile")
		}
		out.Entries = diffRFID(ra, rb)
	default:
		return nil, fmt.Errorf("Diff: unsupported format %q", aFormat)
	}
	return out, nil
}

func diffSub(a, b *SubFile) []DiffEntry {
	return []DiffEntry{
		fieldDiff("filetype", a.Filetype, b.Filetype),
		fieldDiff("version", fmt.Sprint(a.Version), fmt.Sprint(b.Version)),
		fieldDiff("frequency", fmt.Sprint(a.Frequency), fmt.Sprint(b.Frequency)),
		fieldDiff("preset", a.Preset, b.Preset),
		fieldDiff("protocol", a.Protocol, b.Protocol),
		fieldDiff("bit", fmt.Sprint(a.Bit), fmt.Sprint(b.Bit)),
		fieldDiff("key", a.Key, b.Key),
		fieldDiff("te", fmt.Sprint(a.TE), fmt.Sprint(b.TE)),
		fieldDiff("raw_samples", fmt.Sprint(len(a.RawData)), fmt.Sprint(len(b.RawData))),
	}
}

func diffNFC(a, b *NFCFile) []DiffEntry {
	entries := []DiffEntry{
		fieldDiff("filetype", a.Filetype, b.Filetype),
		fieldDiff("version", fmt.Sprint(a.Version), fmt.Sprint(b.Version)),
		fieldDiff("device_type", a.DeviceType, b.DeviceType),
		fieldDiff("uid", a.UID, b.UID),
		fieldDiff("atqa", a.ATQA, b.ATQA),
		fieldDiff("sak", a.SAK, b.SAK),
		fieldDiff("mifare_type", a.MifareType, b.MifareType),
	}
	indices := map[int]struct{}{}
	for k := range a.Blocks {
		indices[k] = struct{}{}
	}
	for k := range b.Blocks {
		indices[k] = struct{}{}
	}
	keys := make([]int, 0, len(indices))
	for k := range indices {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		entries = append(entries, fieldDiff(fmt.Sprintf("block_%d", k), a.Blocks[k], b.Blocks[k]))
	}
	return entries
}

func diffIR(a, b *IRFile) []DiffEntry {
	entries := []DiffEntry{
		fieldDiff("filetype", a.Filetype, b.Filetype),
		fieldDiff("version", fmt.Sprint(a.Version), fmt.Sprint(b.Version)),
		fieldDiff("signal_count", fmt.Sprint(len(a.Signals)), fmt.Sprint(len(b.Signals))),
	}
	max := len(a.Signals)
	if len(b.Signals) > max {
		max = len(b.Signals)
	}
	for i := 0; i < max; i++ {
		var sa, sb IRSignal
		if i < len(a.Signals) {
			sa = a.Signals[i]
		}
		if i < len(b.Signals) {
			sb = b.Signals[i]
		}
		entries = append(entries,
			fieldDiff(fmt.Sprintf("signal_%d_name", i), sa.Name, sb.Name),
			fieldDiff(fmt.Sprintf("signal_%d_type", i), sa.Type, sb.Type),
			fieldDiff(fmt.Sprintf("signal_%d_protocol", i), sa.Protocol, sb.Protocol),
			fieldDiff(fmt.Sprintf("signal_%d_address", i), sa.Address, sb.Address),
			fieldDiff(fmt.Sprintf("signal_%d_command", i), sa.Command, sb.Command),
		)
	}
	return entries
}

func diffRFID(a, b *RFIDFile) []DiffEntry {
	return []DiffEntry{
		fieldDiff("filetype", a.Filetype, b.Filetype),
		fieldDiff("version", fmt.Sprint(a.Version), fmt.Sprint(b.Version)),
		fieldDiff("key_type", a.KeyType, b.KeyType),
		fieldDiff("data", a.Data, b.Data),
	}
}

func fieldDiff(name, a, b string) DiffEntry {
	return DiffEntry{Field: name, AField: a, BField: b, Same: a == b}
}
