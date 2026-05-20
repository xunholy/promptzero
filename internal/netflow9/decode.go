// Package netflow9 decodes NetFlow v9 (RFC 3954) packets.
// NetFlow v9 is the template-based flow-export format that
// superseded NetFlow v5 (1996; covered by `netflow_v5_decode`)
// and bridged to IPFIX (RFC 7011); it's the dominant NetFlow
// version on modern (post-2010) Cisco / Juniper / Arista
// enterprise + carrier gear. NetFlow v9's killer feature is
// template-based extensibility: instead of a hardcoded
// 48-byte record like v5, exporters define Templates that name
// the fields and their widths, then send Data FlowSets that
// reference a Template ID and contain back-to-back records in
// that template's shape.
//
// Wrap-vs-native judgement
//
//	Native. RFC 3954 is fully public; NetFlow v9 has a tight
//	20-byte header followed by N FlowSets (each: 4-byte
//	header + body). No crypto, no compression. Operators
//	paste NetFlow bytes (UDP destination port 2055 / 9555 /
//	9995) from a `tcpdump -X udp port 2055` line or a
//	Wireshark Follow-UDP-Stream view and get the documented
//	header + per-FlowSet breakdown.
//
//	The template stateful-decode gap: this decoder is
//	stateless (single-packet), so Data FlowSets are
//	surfaced as raw hex annotated with their referencing
//	Template ID. Operators correlate against the matching
//	Template FlowSet (typically in the same packet, or in
//	an earlier packet from the same exporter). A future
//	iteration could maintain a template cache across calls.
//
// What this package covers
//
//   - **20-byte header** (RFC 3954 §5.1):
//
//   - bytes 0-1: Version (uint16 BE; must be 9).
//
//   - bytes 2-3: **Count** (uint16 BE; number of
//     FlowSets in this packet).
//
//   - bytes 4-7: SysUptime (uint32 BE; ms since
//     exporter boot).
//
//   - bytes 8-11: Unix Seconds (uint32 BE; epoch
//     seconds of export).
//
//   - bytes 12-15: **Sequence Number** (uint32 BE;
//     per-source monotonic counter — gaps signal
//     collector data loss).
//
//   - bytes 16-19: **Source ID** (uint32 BE; unique
//     exporter+observation-point identifier).
//
//   - **FlowSet walker** — repeated 4-byte header
//     (FlowSet ID uint16 BE + Length uint16 BE; Length
//     includes this 4-byte header) + body.
//
//   - **Template FlowSet** (FlowSet ID = 0; RFC 3954 §5.2):
//
//   - 2-byte Template ID (uint16 BE; ≥ 256 per RFC).
//
//   - 2-byte Field Count.
//
//   - **Field Specifier × Field Count** (4 bytes each):
//
//   - 2-byte **Field Type** (uint16 BE) resolved via
//     a ~30-entry name table covering the most common
//     IANA NetFlow IPFIX Information Element IDs
//     (IN_BYTES / IN_PKTS / FLOWS / PROTOCOL / TOS /
//     TCP_FLAGS / L4_SRC_PORT / IPV4_SRC_ADDR /
//     SRC_MASK / INPUT_SNMP / L4_DST_PORT /
//     IPV4_DST_ADDR / DST_MASK / OUTPUT_SNMP /
//     IPV4_NEXT_HOP / SRC_AS / DST_AS / BGP_NEXT_HOP /
//     MUL_DST_PKTS / MUL_DST_BYTES / LAST_SWITCHED /
//     FIRST_SWITCHED / IPV6_SRC_ADDR / IPV6_DST_ADDR /
//     IPV6_SRC_MASK / IPV6_DST_MASK / FLOW_LABEL /
//     ICMP_TYPE / IGMP_TYPE / SAMPLING_INTERVAL /
//     SAMPLING_ALGORITHM / FLOW_ACTIVE_TIMEOUT /
//     FLOW_INACTIVE_TIMEOUT / ENGINE_TYPE / ENGINE_ID
//     / TOTAL_BYTES_EXP / TOTAL_PKTS_EXP / FLOW_END_
//     REASON).
//
//   - 2-byte **Field Length** (uint16 BE; bytes per
//     field in the Data FlowSet record).
//
//   - **Options Template FlowSet** (FlowSet ID = 1; RFC
//     3954 §6) — same shape as Template FlowSet plus
//     scope and option distinction (surfaced structurally;
//     option semantics deferred).
//
//   - **Data FlowSet** (FlowSet ID ≥ 256; RFC 3954 §5.3)
//     — the FlowSet ID matches the Template ID of an
//     earlier Template FlowSet. Records are back-to-back
//     in the template's field layout (no per-record
//     header). Without the matching template the decoder
//     surfaces the body as raw hex; with a same-packet
//     template the bytes-per-record calculation is done
//     implicitly but actual per-field decoding remains
//     deferred (would require a typed-by-IE-id walker).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - UDP framing — feed NetFlow bytes after the UDP
//     header strip. NetFlow ships on UDP, conventionally
//     to destination ports 2055 / 9555 / 9995.
//
//   - NetFlow v5 (use `netflow_v5_decode`) and IPFIX
//     (RFC 7011 — different envelope, warrants its own
//     Spec).
//
//   - sFlow (use `sflow_v5_decode`) — packet sampling,
//     different model.
//
//   - Stateful template cache across packets — single-
//     packet decode only; Data FlowSets without an in-
//     packet template are surfaced as raw hex annotated
//     with their referencing Template ID.
//
//   - Per-field type-aware decoding of Data FlowSets —
//     would require a full IANA IE-id type table (~500
//     entries) plus per-IE decoder; deferred.
package netflow9

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Result is the top-level decoded view of a NetFlow v9 packet.
type Result struct {
	Version            uint16    `json:"version"`
	Count              uint16    `json:"count"`
	SysUptimeMs        uint32    `json:"sys_uptime_ms"`
	UnixSeconds        uint32    `json:"unix_seconds"`
	ExportTimestampISO string    `json:"export_timestamp_iso,omitempty"`
	SequenceNumber     uint32    `json:"sequence_number"`
	SourceID           uint32    `json:"source_id"`
	FlowSets           []FlowSet `json:"flowsets"`
	TotalBytes         int       `json:"total_bytes"`
	Notes              []string  `json:"notes,omitempty"`
}

// FlowSet is one (ID, Length, Body) record from the walker.
type FlowSet struct {
	FlowSetID uint16 `json:"flowset_id"`
	Kind      string `json:"kind"`
	Length    uint16 `json:"length"`
	BodyHex   string `json:"body_hex,omitempty"`

	// Decoded forms populated for known FlowSet kinds.
	Templates       []Template       `json:"templates,omitempty"`
	OptionTemplates []Template       `json:"option_templates,omitempty"`
	DataFlowSet     *DataFlowSetBody `json:"data,omitempty"`
}

// Template is one Template definition (or Options Template).
type Template struct {
	TemplateID int         `json:"template_id"`
	FieldCount int         `json:"field_count"`
	Fields     []FieldSpec `json:"fields"`
	RecordSize int         `json:"record_size_bytes"`
}

// FieldSpec is one (Field Type, Field Length) pair from a
// Template's field list.
type FieldSpec struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Length   int    `json:"length"`
}

// DataFlowSetBody is the decoded body of a Data FlowSet
// (FlowSet ID ≥ 256). Records are surfaced as raw hex pending
// stateful template lookup.
type DataFlowSetBody struct {
	ReferencedTemplateID int    `json:"referenced_template_id"`
	RecordsHex           string `json:"records_hex"`
	BodyBytes            int    `json:"body_bytes"`
}

// Decode parses a single NetFlow v9 packet from hex.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if clean == "" {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex must have even length, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 20 {
		return nil, fmt.Errorf("NetFlow v9 packet truncated (%d bytes; need ≥20 for header)",
			len(b))
	}
	r := &Result{
		TotalBytes:     len(b),
		Version:        binary.BigEndian.Uint16(b[0:2]),
		Count:          binary.BigEndian.Uint16(b[2:4]),
		SysUptimeMs:    binary.BigEndian.Uint32(b[4:8]),
		UnixSeconds:    binary.BigEndian.Uint32(b[8:12]),
		SequenceNumber: binary.BigEndian.Uint32(b[12:16]),
		SourceID:       binary.BigEndian.Uint32(b[16:20]),
	}
	if r.Version != 9 {
		return r, fmt.Errorf("unsupported NetFlow version %d (this Spec covers v9 only)",
			r.Version)
	}
	if r.UnixSeconds != 0 {
		r.ExportTimestampISO = time.Unix(int64(r.UnixSeconds), 0).UTC().Format(time.RFC3339)
	}
	off := 20
	for off+4 <= len(b) {
		fs, used, err := decodeFlowSet(b[off:])
		if err != nil {
			r.Notes = append(r.Notes, err.Error())
			break
		}
		r.FlowSets = append(r.FlowSets, fs)
		off += used
	}
	return r, nil
}

func decodeFlowSet(b []byte) (FlowSet, int, error) {
	id := binary.BigEndian.Uint16(b[0:2])
	ln := binary.BigEndian.Uint16(b[2:4])
	if ln < 4 {
		return FlowSet{}, 0, fmt.Errorf("FlowSet ID %d declares length %d (< 4 header bytes)",
			id, ln)
	}
	if int(ln) > len(b) {
		return FlowSet{}, 0, fmt.Errorf("FlowSet ID %d declares length %d but only %d remain",
			id, ln, len(b))
	}
	body := b[4:ln]
	fs := FlowSet{
		FlowSetID: id,
		Kind:      flowSetKind(id),
		Length:    ln,
		BodyHex:   strings.ToUpper(hex.EncodeToString(body)),
	}
	switch {
	case id == 0:
		fs.Templates = decodeTemplates(body)
	case id == 1:
		fs.OptionTemplates = decodeTemplates(body)
	case id >= 256:
		fs.DataFlowSet = &DataFlowSetBody{
			ReferencedTemplateID: int(id),
			RecordsHex:           strings.ToUpper(hex.EncodeToString(body)),
			BodyBytes:            len(body),
		}
	}
	return fs, int(ln), nil
}

func decodeTemplates(b []byte) []Template {
	var out []Template
	off := 0
	for off+4 <= len(b) {
		tid := binary.BigEndian.Uint16(b[off : off+2])
		fc := binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
		t := Template{
			TemplateID: int(tid),
			FieldCount: int(fc),
		}
		need := int(fc) * 4
		if off+need > len(b) {
			break
		}
		var recSize int
		for i := 0; i < int(fc); i++ {
			ft := int(binary.BigEndian.Uint16(b[off : off+2]))
			fl := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
			t.Fields = append(t.Fields, FieldSpec{
				Type:     ft,
				TypeName: fieldTypeName(ft),
				Length:   fl,
			})
			recSize += fl
			off += 4
		}
		t.RecordSize = recSize
		out = append(out, t)
	}
	return out
}

func flowSetKind(id uint16) string {
	switch {
	case id == 0:
		return "Template FlowSet"
	case id == 1:
		return "Options Template FlowSet"
	case id < 256:
		return fmt.Sprintf("reserved FlowSet ID %d", id)
	}
	return "Data FlowSet"
}

func fieldTypeName(t int) string {
	switch t {
	case 1:
		return "IN_BYTES"
	case 2:
		return "IN_PKTS"
	case 3:
		return "FLOWS"
	case 4:
		return "PROTOCOL"
	case 5:
		return "SRC_TOS"
	case 6:
		return "TCP_FLAGS"
	case 7:
		return "L4_SRC_PORT"
	case 8:
		return "IPV4_SRC_ADDR"
	case 9:
		return "SRC_MASK"
	case 10:
		return "INPUT_SNMP"
	case 11:
		return "L4_DST_PORT"
	case 12:
		return "IPV4_DST_ADDR"
	case 13:
		return "DST_MASK"
	case 14:
		return "OUTPUT_SNMP"
	case 15:
		return "IPV4_NEXT_HOP"
	case 16:
		return "SRC_AS"
	case 17:
		return "DST_AS"
	case 18:
		return "BGP_IPV4_NEXT_HOP"
	case 19:
		return "MUL_DST_PKTS"
	case 20:
		return "MUL_DST_BYTES"
	case 21:
		return "LAST_SWITCHED"
	case 22:
		return "FIRST_SWITCHED"
	case 23:
		return "OUT_BYTES"
	case 24:
		return "OUT_PKTS"
	case 27:
		return "IPV6_SRC_ADDR"
	case 28:
		return "IPV6_DST_ADDR"
	case 29:
		return "IPV6_SRC_MASK"
	case 30:
		return "IPV6_DST_MASK"
	case 31:
		return "IPV6_FLOW_LABEL"
	case 32:
		return "ICMP_TYPE"
	case 33:
		return "MUL_IGMP_TYPE"
	case 34:
		return "SAMPLING_INTERVAL"
	case 35:
		return "SAMPLING_ALGORITHM"
	case 36:
		return "FLOW_ACTIVE_TIMEOUT"
	case 37:
		return "FLOW_INACTIVE_TIMEOUT"
	case 38:
		return "ENGINE_TYPE"
	case 39:
		return "ENGINE_ID"
	case 40:
		return "TOTAL_BYTES_EXP"
	case 41:
		return "TOTAL_PKTS_EXP"
	case 42:
		return "TOTAL_FLOWS_EXP"
	case 56:
		return "SRC_MAC"
	case 57:
		return "DST_MAC"
	case 58:
		return "SRC_VLAN"
	case 59:
		return "DST_VLAN"
	case 60:
		return "IP_PROTOCOL_VERSION"
	case 61:
		return "DIRECTION"
	case 62:
		return "IPV6_NEXT_HOP"
	case 63:
		return "BGP_IPV6_NEXT_HOP"
	case 80:
		return "IN_SRC_MAC"
	case 81:
		return "OUT_DST_MAC"
	case 136:
		return "FLOW_END_REASON"
	}
	return fmt.Sprintf("uncatalogued field type %d", t)
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
