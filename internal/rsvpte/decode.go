// Package rsvpte decodes RSVP-TE (Resource Reservation Protocol — Traffic
// Engineering) packets per RFC 3209 (RSVP-TE extensions) and RFC 2205 (base
// RSVP). RSVP-TE runs directly over IP (protocol number 46). It establishes
// MPLS Label Switched Paths (LSPs) with explicit routes and traffic
// engineering constraints.
//
// RSVP-TE is the MPLS TE signalling protocol — it establishes and maintains
// traffic-engineered LSPs across ISP and carrier backbone networks. Default
// RSVP has NO authentication — hop-by-hop integrity is optional via the
// INTEGRITY object (class 4, HMAC-MD5 keyed auth). Without INTEGRITY objects,
// the control plane is fully open to spoofing.
//
// The wire format leaks:
//
//   - **SESSION objects** — reveal tunnel endpoints (IPv4 tunnel_endpoint),
//     tunnel_id, and extended_tunnel_id, exposing the full TE LSP setup.
//
//   - **ERO (Explicit Route Object)** — discloses the intended LSP path
//     across the network, mapping the internal TE topology hop-by-hop.
//
//   - **RRO (Record Route Object)** — discloses the actual path traversed
//     by the LSP after it is established.
//
//   - **SESSION_ATTRIBUTE** — reveals LSP names, setup and holding
//     priorities, exposing full TE policy and topology.
//
//   - **SENDER_TEMPLATE / FILTER_SPEC** — expose sender IPv4 address and
//     LSP ID, mapping the signalling relationships.
//
//   - **LABEL** — carries the MPLS label value distributed for this LSP,
//     enabling traffic interception at the switching plane.
//
//   - **LABEL_REQUEST** — reveals the L3PID (Layer 3 Protocol ID) for which
//     a label is being requested, typically 0x0800 for IPv4.
//
//   - **HOP** — the RSVP_HOP object carries the previous/next-hop address
//     and logical interface handle, mapping adjacencies.
//
//   - **TIME_VALUES** — the refresh period reveals the keepalive tuning of
//     the RSVP session.
//
// Path message injection creates unauthorized LSPs — traffic redirection at
// MPLS TE scale. Resv message manipulation alters label bindings — MITM at
// the switching plane. Used in ISP/carrier backbone for MPLS TE, MPLS FRR
// (Fast Reroute), GMPLS optical transport.
//
// Wrap-vs-native judgement
//
//	Native. RFC 2205 and RFC 3209 are publicly available. The RSVP wire
//	format is a fixed 8-byte common header followed by TLV-style objects.
//	No crypto at the parse layer (INTEGRITY object content is opaque auth
//	data, not decryptable payload). Pure offline parser.
//
// What this package covers
//
//   - **8-byte RSVP common header**: version, flags, msg_type (12-entry name
//     table: Path/Resv/PathErr/ResvErr/PathTear/ResvTear/ResvConf/Bundle/
//     Hello/Srefresh/Notify), checksum, send_ttl, rsvp_length.
//
//   - **Object walker**: length (2 BE) + class_num (1) + c_type (1) +
//     value[length-4] for all objects present; surfaces object_count and
//     object_types list.
//
//   - **SESSION object (class 1, C-Type 7)**: LSP_TUNNEL_IPv4 —
//     tunnel_endpoint, tunnel_id, extended_tunnel_id.
//
//   - **HOP object (class 3, C-Type 1)**: IPv4 next/previous hop address
//     and logical interface handle.
//
//   - **TIME_VALUES object (class 5, C-Type 1)**: refresh period in ms.
//
//   - **LABEL object (class 16, C-Type 1)**: MPLS label value (4 BE).
//
//   - **LABEL_REQUEST object (class 19, C-Type 1)**: L3PID (2 BE).
//
//   - **SENDER_TEMPLATE object (class 11, C-Type 7)**: LSP_TUNNEL_IPv4 —
//     sender IPv4 address + LSP ID.
//
//   - **FILTER_SPEC object (class 9, C-Type 7)**: LSP_TUNNEL_IPv4 — same
//     layout as SENDER_TEMPLATE.
//
//   - **ERO object (class 20)**: Explicit Route — sub-object walker for
//     IPv4 prefix sub-objects (type 1); surfaces ero_hop_count and
//     first few ero_hops[] with IPv4, prefix_length, loose/strict.
//
//   - **RRO object (class 21)**: Record Route — same sub-object format;
//     surfaces rro_hop_count.
//
//   - **SESSION_ATTRIBUTE object (class 207, C-Type 7)**: setup_priority,
//     holding_priority, flags, session_name.
//
//   - **Classification flags**: is_path, is_resv, is_hello, is_path_tear,
//     is_resv_tear.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **INTEGRITY object (class 4)**: authentication material not surfaced.
//
//   - **FLOWSPEC / SENDER_TSPEC objects**: traffic specification parsing.
//
//   - **STYLE / RESV_CONFIRM objects**: reservation style and confirmation.
//
//   - **IPv6 address variants** in objects with C-Types for IPv6.
//
//   - **GMPLS generalized label formats** (C-Type > 1 for LABEL object).
//
//   - **Checksum verification**: header checksum field is decoded but not
//     validated.
//
//   - **IP framing**: feed bytes after IPv4 header strip — RSVP-TE rides
//     IP protocol 46 with no UDP/TCP wrapper.
package rsvpte

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// EROHop describes a single IPv4 prefix sub-object from the ERO or RRO.
type EROHop struct {
	Address      string `json:"address"`
	PrefixLength int    `json:"prefix_length"`
	Loose        bool   `json:"loose"`
}

// ObjectType summarises a parsed RSVP object for the object_types list.
type ObjectType struct {
	ClassNum  int    `json:"class_num"`
	CType     int    `json:"c_type"`
	ClassName string `json:"class_name"`
}

// Result is the structured decode of an RSVP-TE packet.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Common header fields.
	Version     int    `json:"version"`
	Flags       int    `json:"flags"`
	MsgType     int    `json:"msg_type"`
	MsgTypeName string `json:"msg_type_name"`
	Checksum    string `json:"checksum"`
	SendTTL     int    `json:"send_ttl"`
	RSVPLength  int    `json:"rsvp_length"`

	// Object summary.
	ObjectCount int          `json:"object_count"`
	ObjectTypes []ObjectType `json:"object_types"`

	// Classification booleans.
	IsPath     bool `json:"is_path"`
	IsResv     bool `json:"is_resv"`
	IsHello    bool `json:"is_hello"`
	IsPathTear bool `json:"is_path_tear"`
	IsResvTear bool `json:"is_resv_tear"`

	// SESSION object (class 1, C-Type 7 = LSP_TUNNEL_IPv4).
	HasSession       bool   `json:"has_session"`
	TunnelEndpoint   string `json:"tunnel_endpoint,omitempty"`
	TunnelID         uint16 `json:"tunnel_id,omitempty"`
	ExtendedTunnelID string `json:"extended_tunnel_id,omitempty"`

	// HOP object (class 3, C-Type 1).
	HasHop     bool   `json:"has_hop"`
	HopAddress string `json:"hop_address,omitempty"`

	// TIME_VALUES object (class 5, C-Type 1).
	HasTimeValues   bool   `json:"has_time_values"`
	RefreshPeriodMs uint32 `json:"refresh_period_ms,omitempty"`

	// LABEL object (class 16, C-Type 1).
	HasLabel   bool   `json:"has_label"`
	LabelValue uint32 `json:"label_value,omitempty"`

	// LABEL_REQUEST object (class 19, C-Type 1).
	HasLabelRequest bool   `json:"has_label_request"`
	L3PID           uint16 `json:"l3pid,omitempty"`

	// SENDER_TEMPLATE object (class 11, C-Type 7 = LSP_TUNNEL_IPv4).
	HasSenderTemplate bool   `json:"has_sender_template"`
	SenderAddress     string `json:"sender_address,omitempty"`
	LSPID             uint16 `json:"lsp_id,omitempty"`

	// ERO object (class 20).
	HasERO      bool     `json:"has_ero"`
	EROHopCount int      `json:"ero_hop_count,omitempty"`
	EROHops     []EROHop `json:"ero_hops,omitempty"`

	// RRO object (class 21).
	HasRRO      bool `json:"has_rro"`
	RROHopCount int  `json:"rro_hop_count,omitempty"`

	// SESSION_ATTRIBUTE object (class 207, C-Type 7).
	HasSessionAttribute bool   `json:"has_session_attribute"`
	SetupPriority       int    `json:"setup_priority,omitempty"`
	HoldingPriority     int    `json:"holding_priority,omitempty"`
	SessionName         string `json:"session_name,omitempty"`
}

const rsvpHeaderSize = 8

// maxEROHops caps how many ERO hops are included in EROHops to avoid
// unbounded output for large EROs.
const maxEROHops = 8

// Decode parses an RSVP-TE packet from a hex string.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < rsvpHeaderSize {
		return nil, fmt.Errorf("rsvp header truncated (%d bytes; need %d)", len(b), rsvpHeaderSize)
	}

	r := &Result{TotalBytes: len(b)}

	// Parse 8-byte RSVP common header.
	// Byte 0: [7:4] version, [3:0] flags.
	r.Version = int(b[0] >> 4)
	r.Flags = int(b[0] & 0x0F)
	r.MsgType = int(b[1])
	r.MsgTypeName = msgTypeName(r.MsgType)
	r.Checksum = fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(b[2:4]))
	r.SendTTL = int(b[4])
	// b[5] = reserved
	r.RSVPLength = int(binary.BigEndian.Uint16(b[6:8]))

	// Classify by message type.
	switch r.MsgType {
	case 1:
		r.IsPath = true
	case 2:
		r.IsResv = true
	case 5:
		r.IsPathTear = true
	case 6:
		r.IsResvTear = true
	case 12:
		r.IsHello = true
	}

	// Walk RSVP objects.
	r.ObjectTypes = []ObjectType{}
	off := rsvpHeaderSize
	for off+4 <= len(b) {
		objLen := int(binary.BigEndian.Uint16(b[off : off+2]))
		if objLen < 4 {
			// Malformed object; stop walking.
			break
		}
		if off+objLen > len(b) {
			// Truncated object value; stop walking.
			break
		}
		classNum := int(b[off+2])
		cType := int(b[off+3])

		r.ObjectCount++
		r.ObjectTypes = append(r.ObjectTypes, ObjectType{
			ClassNum:  classNum,
			CType:     cType,
			ClassName: className(classNum),
		})

		value := b[off+4 : off+objLen]
		decodeObject(r, classNum, cType, value)

		off += objLen
	}

	return r, nil
}

func decodeObject(r *Result, classNum, cType int, value []byte) {
	switch classNum {
	case 1: // SESSION
		if cType == 7 {
			decodeSessionLSPTunnelIPv4(r, value)
		}
	case 3: // HOP (RSVP_HOP)
		if cType == 1 {
			decodeHopIPv4(r, value)
		}
	case 5: // TIME_VALUES
		if cType == 1 {
			decodeTimeValues(r, value)
		}
	case 9: // FILTER_SPEC — same layout as SENDER_TEMPLATE C-Type 7
		if cType == 7 && !r.HasSenderTemplate {
			// Only decode FILTER_SPEC as sender info if SENDER_TEMPLATE not yet seen.
			decodeFilterSpecLSPTunnelIPv4(r, value)
		}
	case 11: // SENDER_TEMPLATE
		if cType == 7 {
			decodeSenderTemplateLSPTunnelIPv4(r, value)
		}
	case 16: // LABEL
		if cType == 1 {
			decodeLabelObject(r, value)
		}
	case 19: // LABEL_REQUEST
		if cType == 1 {
			decodeLabelRequest(r, value)
		}
	case 20: // EXPLICIT_ROUTE (ERO)
		decodeERO(r, value)
	case 21: // RECORD_ROUTE (RRO)
		decodeRRO(r, value)
	case 207: // SESSION_ATTRIBUTE
		if cType == 7 {
			decodeSessionAttribute(r, value)
		}
	}
}

// SESSION object, C-Type 7: LSP_TUNNEL_IPv4
// IPv4 tunnel endpoint(4) + reserved(2) + tunnel_id(2 BE) + extended_tunnel_id(4)
// Total value: 12 bytes.
func decodeSessionLSPTunnelIPv4(r *Result, value []byte) {
	if len(value) < 12 {
		return
	}
	r.HasSession = true
	r.TunnelEndpoint = net.IP(value[0:4]).String()
	// value[4:6] = reserved
	r.TunnelID = binary.BigEndian.Uint16(value[6:8])
	r.ExtendedTunnelID = net.IP(value[8:12]).String()
}

// HOP object, C-Type 1: IPv4
// next/previous_hop_address(4) + logical_interface_handle(4)
// Total value: 8 bytes.
func decodeHopIPv4(r *Result, value []byte) {
	if len(value) < 4 {
		return
	}
	r.HasHop = true
	r.HopAddress = net.IP(value[0:4]).String()
}

// TIME_VALUES object, C-Type 1:
// refresh_period(4 BE) in ms.
// Total value: 4 bytes.
func decodeTimeValues(r *Result, value []byte) {
	if len(value) < 4 {
		return
	}
	r.HasTimeValues = true
	r.RefreshPeriodMs = binary.BigEndian.Uint32(value[0:4])
}

// LABEL object, C-Type 1:
// label(4 BE) — the MPLS label value.
func decodeLabelObject(r *Result, value []byte) {
	if len(value) < 4 {
		return
	}
	r.HasLabel = true
	r.LabelValue = binary.BigEndian.Uint32(value[0:4])
}

// LABEL_REQUEST object, C-Type 1:
// reserved(2) + L3PID(2 BE) — typically 0x0800 for IPv4.
func decodeLabelRequest(r *Result, value []byte) {
	if len(value) < 4 {
		return
	}
	r.HasLabelRequest = true
	r.L3PID = binary.BigEndian.Uint16(value[2:4])
}

// SENDER_TEMPLATE object, C-Type 7: LSP_TUNNEL_IPv4
// IPv4 sender(4) + reserved(2) + lsp_id(2 BE)
// Total value: 8 bytes.
func decodeSenderTemplateLSPTunnelIPv4(r *Result, value []byte) {
	if len(value) < 8 {
		return
	}
	r.HasSenderTemplate = true
	r.SenderAddress = net.IP(value[0:4]).String()
	// value[4:6] = reserved
	r.LSPID = binary.BigEndian.Uint16(value[6:8])
}

// FILTER_SPEC object, C-Type 7: LSP_TUNNEL_IPv4
// Same layout as SENDER_TEMPLATE.
func decodeFilterSpecLSPTunnelIPv4(r *Result, value []byte) {
	if len(value) < 8 {
		return
	}
	r.HasSenderTemplate = true
	r.SenderAddress = net.IP(value[0:4]).String()
	// value[4:6] = reserved
	r.LSPID = binary.BigEndian.Uint16(value[6:8])
}

// ERO sub-object walker.
// Sub-object format: L bit(1 bit, MSB of first byte) + type(7 bits) + length(1 byte) + value.
// Type 1 = IPv4 prefix: IPv4(4) + prefix_length(1) + flags(1).
func decodeERO(r *Result, value []byte) {
	r.HasERO = true
	r.EROHops = []EROHop{}
	off := 0
	for off+2 <= len(value) {
		loose := (value[off] & 0x80) != 0
		subType := int(value[off] & 0x7F)
		subLen := int(value[off+1])
		if subLen < 2 {
			break
		}
		if off+subLen > len(value) {
			break
		}
		if subType == 1 && subLen >= 8 {
			// IPv4 prefix sub-object: L(1b)+type(7b)(1) + length(1) + IPv4(4) + prefix_len(1) + flags(1)
			r.EROHopCount++
			if len(r.EROHops) < maxEROHops {
				r.EROHops = append(r.EROHops, EROHop{
					Address:      net.IP(value[off+2 : off+6]).String(),
					PrefixLength: int(value[off+6]),
					Loose:        loose,
				})
			}
		}
		off += subLen
	}
}

// RRO sub-object walker — same format as ERO.
// We count IPv4 prefix sub-objects (type 1) for rro_hop_count.
func decodeRRO(r *Result, value []byte) {
	r.HasRRO = true
	off := 0
	for off+2 <= len(value) {
		subType := int(value[off] & 0x7F)
		subLen := int(value[off+1])
		if subLen < 2 {
			break
		}
		if off+subLen > len(value) {
			break
		}
		if subType == 1 {
			r.RROHopCount++
		}
		off += subLen
	}
}

// SESSION_ATTRIBUTE object, C-Type 7:
// setup_priority(1) + holding_priority(1) + flags(1) + name_length(1) + session_name(variable).
func decodeSessionAttribute(r *Result, value []byte) {
	if len(value) < 4 {
		return
	}
	r.HasSessionAttribute = true
	r.SetupPriority = int(value[0])
	r.HoldingPriority = int(value[1])
	// value[2] = flags (not surfaced separately)
	nameLen := int(value[3])
	if 4+nameLen > len(value) {
		nameLen = len(value) - 4
	}
	if nameLen > 0 {
		r.SessionName = string(value[4 : 4+nameLen])
	}
}

func msgTypeName(t int) string {
	switch t {
	case 1:
		return "Path"
	case 2:
		return "Resv"
	case 3:
		return "PathErr"
	case 4:
		return "ResvErr"
	case 5:
		return "PathTear"
	case 6:
		return "ResvTear"
	case 7:
		return "ResvConf"
	case 10:
		return "Bundle"
	case 12:
		return "Hello"
	case 13:
		return "Srefresh"
	case 20:
		return "Notify"
	}
	return fmt.Sprintf("msg_type_%d", t)
}

func className(n int) string {
	switch n {
	case 1:
		return "SESSION"
	case 3:
		return "HOP"
	case 4:
		return "INTEGRITY"
	case 5:
		return "TIME_VALUES"
	case 7:
		return "STYLE"
	case 8:
		return "FLOWSPEC"
	case 9:
		return "FILTER_SPEC"
	case 11:
		return "SENDER_TEMPLATE"
	case 12:
		return "SENDER_TSPEC"
	case 15:
		return "RESV_CONFIRM"
	case 16:
		return "LABEL"
	case 19:
		return "LABEL_REQUEST"
	case 20:
		return "EXPLICIT_ROUTE"
	case 21:
		return "RECORD_ROUTE"
	case 207:
		return "SESSION_ATTRIBUTE"
	}
	return fmt.Sprintf("class_%d", n)
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
