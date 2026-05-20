// Package ipfix decodes IPFIX (IP Flow Information eXport)
// messages per RFC 7011. IPFIX is the IETF standardization of
// NetFlow v9 (covered by `netflow_v9_decode`); the two protocols
// share the same template-based philosophy, IANA Information
// Element registry, and Data Set layout, but differ in three
// notable ways:
//
//  1. 16-byte header (vs NetFlow v9's 20) — drops the Source ID
//     field in favour of an explicit Message Length and renames
//     the per-exporter identifier to Observation Domain ID.
//  2. Enterprise-bit-extended Field Specifiers — the high bit
//     of the Field Type signals presence of a 4-byte Enterprise
//     Number after the (15-bit Field Type, Length) pair, opening
//     the namespace to vendor-defined IEs.
//  3. Set IDs reserved 0-3: 2 = Template Set, 3 = Options
//     Template Set, 256+ = Data Set; IPFIX drops NetFlow v9's
//     FlowSet ID 0 / 1 distinction.
//
// IPFIX is the export format used by Linux iptables / nftables
// flow exporters, Cisco ASR / NCS, Juniper modern routers,
// ntopng, akvorado, GoFlow2, pmacct, and every modern flow
// collector. Completes the flow-telemetry quartet alongside
// `netflow_v5_decode`, `netflow_v9_decode`, and `sflow_v5_decode`.
//
// Wrap-vs-native judgement
//
//	Native. RFC 7011 is fully public; IPFIX has a tight
//	16-byte header followed by N Sets (each: 4-byte header
//	+ body). No crypto, no compression. Operators paste
//	IPFIX bytes (UDP destination port 4739 [IANA-assigned],
//	often also 2055 / 9555 / 9995 for legacy compatibility)
//	from a `tcpdump -X udp port 4739` line or a Wireshark
//	Follow-UDP-Stream view and get the documented header +
//	per-Set breakdown.
//
//	Like NetFlow v9, this decoder is stateless (single-
//	message), so Data Sets are surfaced as raw hex
//	annotated with their referencing Template ID.
//
// What this package covers
//
//   - **16-byte header** (RFC 7011 §3.1):
//
//   - bytes 0-1: Version (uint16 BE; must be 10 / 0x000A).
//
//   - bytes 2-3: **Message Length** (uint16 BE; total
//     length including header).
//
//   - bytes 4-7: Export Time (uint32 BE; epoch seconds).
//
//   - bytes 8-11: **Sequence Number** (uint32 BE; per-
//     Observation Domain monotonic — gaps signal data
//     loss).
//
//   - bytes 12-15: **Observation Domain ID** (uint32 BE;
//     unique per exporter + observation point).
//
//   - **Set walker** — repeated 4-byte header (Set ID
//     uint16 BE + Set Length uint16 BE; Length includes
//     this 4-byte header) + body.
//
//   - **3-kind name table**: Set ID 2 Template Set / 3
//     Options Template Set / ≥ 256 Data Set (Set ID
//     matches the Template ID of an earlier Template Set).
//
//   - **Template Set** (Set ID = 2; RFC 7011 §3.4.1):
//
//   - 2-byte Template ID (uint16 BE; ≥ 256).
//
//   - 2-byte Field Count.
//
//   - **Field Specifier × Field Count**, with format
//     dispatched by the high bit of Field Type:
//
//   - **Standard IE** (high bit 0): 2-byte Field Type
//
//   - 2-byte Field Length.
//
//   - **Enterprise IE** (high bit 1): 2-byte Field
//     Type (low 15 bits) + 2-byte Field Length +
//     4-byte Enterprise Number (IANA PEN).
//
//   - Field Type resolved via a **~45-entry name table**
//     covering the most common IANA IPFIX Information
//     Element IDs (shared with NetFlow v9).
//
//   - **Options Template Set** (Set ID = 3; RFC 7011 §3.4.2):
//
//   - 2-byte Template ID.
//
//   - 2-byte Field Count.
//
//   - 2-byte Scope Field Count.
//
//   - First `Scope Field Count` specifiers are scope
//     fields (e.g. meteringProcessId), remaining are
//     option fields (e.g. samplingProbability).
//
//   - **Data Set** (Set ID ≥ 256; RFC 7011 §3.4.3) —
//     records back-to-back in the matching Template's
//     field layout (no per-record header). Surfaced as
//     raw hex annotated with the referencing Template ID.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - UDP / TCP / SCTP framing — feed IPFIX bytes after the
//     transport header strip. IPFIX runs on UDP / TCP /
//     SCTP destination port 4739 (IANA-assigned), often
//     also 2055 / 9555 / 9995 for legacy compatibility.
//
//   - NetFlow v9 (use `netflow_v9_decode`); NetFlow v5
//     (use `netflow_v5_decode`); sFlow v5 (use
//     `sflow_v5_decode`).
//
//   - Stateful template cache across messages — single-
//     message decode only; Data Sets without an in-message
//     template are surfaced as raw hex annotated with
//     their referencing Template ID.
//
//   - Per-field type-aware decoding of Data Sets — would
//     require a full IANA IE-id type table (~500 entries)
//     plus per-IE decoder; deferred.
//
//   - Structured Data (RFC 6313 — basicList / subTemplate
//     List / subTemplateMultiList) and Variable-Length
//     Encoding — surfaced as raw hex within Data Sets.
package ipfix

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Result is the top-level decoded view of an IPFIX message.
type Result struct {
	Version             uint16   `json:"version"`
	MessageLength       uint16   `json:"message_length"`
	ExportTime          uint32   `json:"export_time"`
	ExportTimestampISO  string   `json:"export_timestamp_iso,omitempty"`
	SequenceNumber      uint32   `json:"sequence_number"`
	ObservationDomainID uint32   `json:"observation_domain_id"`
	Sets                []Set    `json:"sets"`
	TotalBytes          int      `json:"total_bytes"`
	Notes               []string `json:"notes,omitempty"`
}

// Set is one (ID, Length, Body) record from the Set walker.
type Set struct {
	SetID   uint16 `json:"set_id"`
	Kind    string `json:"kind"`
	Length  uint16 `json:"length"`
	BodyHex string `json:"body_hex,omitempty"`

	// Decoded forms populated for known Set kinds.
	Templates       []Template       `json:"templates,omitempty"`
	OptionTemplates []OptionTemplate `json:"option_templates,omitempty"`
	DataSet         *DataSetBody     `json:"data,omitempty"`
}

// Template is one IPFIX Template definition.
type Template struct {
	TemplateID int         `json:"template_id"`
	FieldCount int         `json:"field_count"`
	Fields     []FieldSpec `json:"fields"`
	RecordSize int         `json:"record_size_bytes"`
}

// OptionTemplate is one IPFIX Options Template definition.
type OptionTemplate struct {
	TemplateID      int         `json:"template_id"`
	FieldCount      int         `json:"field_count"`
	ScopeFieldCount int         `json:"scope_field_count"`
	ScopeFields     []FieldSpec `json:"scope_fields"`
	OptionFields    []FieldSpec `json:"option_fields"`
	RecordSize      int         `json:"record_size_bytes"`
}

// FieldSpec is one Field Specifier from a Template's field list.
type FieldSpec struct {
	Type             int    `json:"type"`
	TypeName         string `json:"type_name"`
	Length           int    `json:"length"`
	EnterpriseNumber uint32 `json:"enterprise_number,omitempty"`
	IsEnterprise     bool   `json:"is_enterprise,omitempty"`
}

// DataSetBody is the decoded body of a Data Set.
type DataSetBody struct {
	ReferencedTemplateID int    `json:"referenced_template_id"`
	RecordsHex           string `json:"records_hex"`
	BodyBytes            int    `json:"body_bytes"`
}

// Decode parses a single IPFIX message from hex.
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
	if len(b) < 16 {
		return nil, fmt.Errorf("IPFIX message truncated (%d bytes; need ≥16 for header)",
			len(b))
	}
	r := &Result{
		TotalBytes:          len(b),
		Version:             binary.BigEndian.Uint16(b[0:2]),
		MessageLength:       binary.BigEndian.Uint16(b[2:4]),
		ExportTime:          binary.BigEndian.Uint32(b[4:8]),
		SequenceNumber:      binary.BigEndian.Uint32(b[8:12]),
		ObservationDomainID: binary.BigEndian.Uint32(b[12:16]),
	}
	if r.Version != 10 {
		return r, fmt.Errorf("unsupported IPFIX version %d (this Spec covers v10 / RFC 7011 only)",
			r.Version)
	}
	if r.ExportTime != 0 {
		r.ExportTimestampISO = time.Unix(int64(r.ExportTime), 0).UTC().Format(time.RFC3339)
	}
	if int(r.MessageLength) != len(b) {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"header declares message length %d but %d bytes provided",
			r.MessageLength, len(b)))
	}
	off := 16
	for off+4 <= len(b) {
		s, used, err := decodeSet(b[off:])
		if err != nil {
			r.Notes = append(r.Notes, err.Error())
			break
		}
		r.Sets = append(r.Sets, s)
		off += used
	}
	return r, nil
}

func decodeSet(b []byte) (Set, int, error) {
	id := binary.BigEndian.Uint16(b[0:2])
	ln := binary.BigEndian.Uint16(b[2:4])
	if ln < 4 {
		return Set{}, 0, fmt.Errorf("Set ID %d declares length %d (< 4 header bytes)", id, ln)
	}
	if int(ln) > len(b) {
		return Set{}, 0, fmt.Errorf("Set ID %d declares length %d but only %d remain",
			id, ln, len(b))
	}
	body := b[4:ln]
	s := Set{
		SetID:   id,
		Kind:    setKind(id),
		Length:  ln,
		BodyHex: strings.ToUpper(hex.EncodeToString(body)),
	}
	switch {
	case id == 2:
		s.Templates = decodeTemplates(body)
	case id == 3:
		s.OptionTemplates = decodeOptionTemplates(body)
	case id >= 256:
		s.DataSet = &DataSetBody{
			ReferencedTemplateID: int(id),
			RecordsHex:           strings.ToUpper(hex.EncodeToString(body)),
			BodyBytes:            len(body),
		}
	}
	return s, int(ln), nil
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
		var recSize int
		var consumed int
		for i := 0; i < int(fc); i++ {
			f, used, ok := readFieldSpec(b[off:])
			if !ok {
				return out
			}
			t.Fields = append(t.Fields, f)
			recSize += f.Length
			off += used
			consumed += used
		}
		_ = consumed
		t.RecordSize = recSize
		out = append(out, t)
	}
	return out
}

func decodeOptionTemplates(b []byte) []OptionTemplate {
	var out []OptionTemplate
	off := 0
	for off+6 <= len(b) {
		tid := binary.BigEndian.Uint16(b[off : off+2])
		fc := binary.BigEndian.Uint16(b[off+2 : off+4])
		sfc := binary.BigEndian.Uint16(b[off+4 : off+6])
		off += 6
		t := OptionTemplate{
			TemplateID:      int(tid),
			FieldCount:      int(fc),
			ScopeFieldCount: int(sfc),
		}
		var recSize int
		for i := 0; i < int(fc); i++ {
			f, used, ok := readFieldSpec(b[off:])
			if !ok {
				return out
			}
			if i < int(sfc) {
				t.ScopeFields = append(t.ScopeFields, f)
			} else {
				t.OptionFields = append(t.OptionFields, f)
			}
			recSize += f.Length
			off += used
		}
		t.RecordSize = recSize
		out = append(out, t)
	}
	return out
}

// readFieldSpec parses one Field Specifier, returning the
// parsed FieldSpec, the number of bytes consumed, and ok.
// Standard IE is 4 bytes; enterprise-extended IE is 8 bytes.
func readFieldSpec(b []byte) (FieldSpec, int, bool) {
	if len(b) < 4 {
		return FieldSpec{}, 0, false
	}
	rawType := binary.BigEndian.Uint16(b[0:2])
	fl := int(binary.BigEndian.Uint16(b[2:4]))
	if rawType&0x8000 != 0 {
		if len(b) < 8 {
			return FieldSpec{}, 0, false
		}
		ft := int(rawType & 0x7FFF)
		en := binary.BigEndian.Uint32(b[4:8])
		return FieldSpec{
			Type:             ft,
			TypeName:         fieldTypeName(ft),
			Length:           fl,
			EnterpriseNumber: en,
			IsEnterprise:     true,
		}, 8, true
	}
	ft := int(rawType)
	return FieldSpec{
		Type:     ft,
		TypeName: fieldTypeName(ft),
		Length:   fl,
	}, 4, true
}

func setKind(id uint16) string {
	switch {
	case id == 2:
		return "Template Set"
	case id == 3:
		return "Options Template Set"
	case id < 256:
		return fmt.Sprintf("reserved Set ID %d", id)
	}
	return "Data Set"
}

// fieldTypeName resolves the IPFIX Information Element ID to a
// human-readable name. Sourced from the IANA "IPFIX Information
// Elements" registry; covers the ~45 most commonly observed
// IEs (the registry has ~500 in total).
func fieldTypeName(t int) string {
	switch t {
	case 1:
		return "octetDeltaCount"
	case 2:
		return "packetDeltaCount"
	case 3:
		return "deltaFlowCount"
	case 4:
		return "protocolIdentifier"
	case 5:
		return "ipClassOfService"
	case 6:
		return "tcpControlBits"
	case 7:
		return "sourceTransportPort"
	case 8:
		return "sourceIPv4Address"
	case 9:
		return "sourceIPv4PrefixLength"
	case 10:
		return "ingressInterface"
	case 11:
		return "destinationTransportPort"
	case 12:
		return "destinationIPv4Address"
	case 13:
		return "destinationIPv4PrefixLength"
	case 14:
		return "egressInterface"
	case 15:
		return "ipNextHopIPv4Address"
	case 16:
		return "bgpSourceAsNumber"
	case 17:
		return "bgpDestinationAsNumber"
	case 18:
		return "bgpNextHopIPv4Address"
	case 21:
		return "flowEndSysUpTime"
	case 22:
		return "flowStartSysUpTime"
	case 23:
		return "octetTotalCount"
	case 24:
		return "packetTotalCount"
	case 27:
		return "sourceIPv6Address"
	case 28:
		return "destinationIPv6Address"
	case 29:
		return "sourceIPv6PrefixLength"
	case 30:
		return "destinationIPv6PrefixLength"
	case 31:
		return "flowLabelIPv6"
	case 32:
		return "icmpTypeCodeIPv4"
	case 33:
		return "igmpType"
	case 34:
		return "samplingInterval"
	case 36:
		return "flowActiveTimeout"
	case 37:
		return "flowIdleTimeout"
	case 40:
		return "exportedOctetTotalCount"
	case 41:
		return "exportedMessageTotalCount"
	case 42:
		return "exportedFlowRecordTotalCount"
	case 52:
		return "minimumTTL"
	case 53:
		return "maximumTTL"
	case 56:
		return "sourceMacAddress"
	case 57:
		return "postDestinationMacAddress"
	case 58:
		return "vlanId"
	case 59:
		return "postVlanId"
	case 60:
		return "ipVersion"
	case 61:
		return "flowDirection"
	case 62:
		return "ipNextHopIPv6Address"
	case 63:
		return "bgpNextHopIPv6Address"
	case 80:
		return "destinationMacAddress"
	case 81:
		return "postSourceMacAddress"
	case 136:
		return "flowEndReason"
	case 138:
		return "observationPointId"
	case 139:
		return "icmpTypeCodeIPv6"
	case 150:
		return "flowStartSeconds"
	case 151:
		return "flowEndSeconds"
	case 152:
		return "flowStartMilliseconds"
	case 153:
		return "flowEndMilliseconds"
	case 234:
		return "ingressVRFID"
	case 235:
		return "egressVRFID"
	}
	return fmt.Sprintf("uncatalogued IE %d", t)
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
