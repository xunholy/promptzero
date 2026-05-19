// Package bgp decodes BGP-4 messages per RFC 4271 plus the
// canonical extensions: RFC 4760 (Multiprotocol BGP / MP-BGP),
// RFC 5492 (Capabilities Optional Parameter), RFC 6793 (4-byte
// AS Number), and RFC 2918 / 7313 (Route Refresh).
//
// Wrap-vs-native judgement
//
//	Native. RFC 4271 is fully public; BGP-4 wire format is a
//	tight 19-byte fixed header (16-byte all-FFs Marker plus
//	2-byte Length plus 1-byte Type) followed by per-type
//	bodies that are themselves bit-packed binary fields with
//	length-prefixed sub-lists. No crypto, no compression, no
//	varints. Operators paste BGP message bytes (TCP port 179
//	is the well-known port; capture a Wireshark Follow-TCP-
//	Stream from a BGP peering session, a Quagga / FRR / GoBGP
//	/ BIRD debug log, or any BGP-speaking router's tcpdump)
//	and get the documented header + body breakdown.
//
// What this package covers
//
//   - **19-byte fixed header** (RFC 4271 §4.1):
//
//   - bytes 0-15: Marker — MUST be 16 bytes of 0xFF. The
//     all-ones marker is a relic of the BGP-3 authentication
//     scheme; BGP-4 still requires it for protocol fidelity.
//     Non-conformant markers surface a Note.
//
//   - bytes 16-17: Length (uint16 BE) — total message length
//     including the 19-byte header. Min 19, max 4096 (RFC
//     4271 §4.1) — BGP-EXT (RFC 8654) raises the max to
//     65535 for some extended messages.
//
//   - byte 18: **Type** with **5-entry name table**:
//
//   - 1 OPEN (RFC 4271 §4.2)
//
//   - 2 UPDATE (RFC 4271 §4.3)
//
//   - 3 NOTIFICATION (RFC 4271 §4.5)
//
//   - 4 KEEPALIVE (RFC 4271 §4.4 — empty body)
//
//   - 5 ROUTE-REFRESH (RFC 2918 §3 — empty payload
//     apart from a 4-byte AFI/SAFI tuple)
//
//   - **OPEN body** (RFC 4271 §4.2):
//
//   - Version (1 byte; currently 4)
//
//   - My Autonomous System (uint16 BE; 23456 = AS_TRANS
//     per RFC 6793 when 4-byte AS is signalled via
//     Capability 65)
//
//   - Hold Time (uint16 BE; seconds before peer is
//     considered dead)
//
//   - BGP Identifier (4 bytes; typically a router IPv4
//     address)
//
//   - Optional Parameters Length (1 byte)
//
//   - Optional Parameters: each is Type (1) + Length (1)
//
//   - Value. The most common Type is 2 (Capability) per
//     RFC 5492, which is itself a TLV with **6-entry
//     Capability Code name table**:
//
//   - 1 Multiprotocol Extensions (MP-BGP, RFC 4760)
//
//   - 2 Route Refresh (RFC 2918)
//
//   - 64 Graceful Restart (RFC 4724)
//
//   - 65 4-byte AS Number (RFC 6793)
//
//   - 67 Dynamic Capability (RFC 4396)
//
//   - 70 Enhanced Route Refresh (RFC 7313)
//
//   - 71 Long-Lived Graceful Restart (RFC 9494)
//
//   - **UPDATE body** (RFC 4271 §4.3):
//
//   - Withdrawn Routes Length (uint16 BE)
//
//   - Withdrawn Routes (variable; list of NLRI prefixes —
//     each is 1-byte Prefix Length + (PrefixLen/8 rounded
//     up) prefix bytes)
//
//   - Total Path Attribute Length (uint16 BE)
//
//   - Path Attributes: each is Flags (1 byte: Optional /
//     Transitive / Partial / Extended-Length) + Type Code
//     (1 byte) + Length (1 or 2 bytes per Extended-Length
//     flag) + Value. **9-entry Path Attribute Type name
//     table** (RFC 4271 + 4760):
//
//   - 1 ORIGIN
//
//   - 2 AS_PATH
//
//   - 3 NEXT_HOP
//
//   - 4 MULTI_EXIT_DISC (MED)
//
//   - 5 LOCAL_PREF
//
//   - 6 ATOMIC_AGGREGATE
//
//   - 7 AGGREGATOR
//
//   - 8 COMMUNITY (RFC 1997)
//
//   - 14 MP_REACH_NLRI (RFC 4760)
//
//   - 15 MP_UNREACH_NLRI (RFC 4760)
//
//   - 17 AS4_PATH (RFC 6793)
//
//   - 18 AS4_AGGREGATOR (RFC 6793)
//
//   - 32 LARGE_COMMUNITY (RFC 8092)
//
//   - NLRI (variable; rest of the message after path
//     attributes; same prefix encoding as Withdrawn
//     Routes).
//
//   - **NOTIFICATION body** (RFC 4271 §4.5):
//
//   - Error Code (1 byte) with **6-entry name table**:
//     1 Message Header Error, 2 OPEN Message Error,
//     3 UPDATE Message Error, 4 Hold Timer Expired,
//     5 Finite State Machine Error, 6 Cease (RFC 4486).
//
//   - Error Subcode (1 byte) decoded per Error Code with
//     per-code sub-tables.
//
//   - Data (variable, error-code-specific diagnostic).
//
//   - **KEEPALIVE body** — empty (always exactly 19 bytes
//     total). Trailing bytes surface a non-conformance Note.
//
//   - **ROUTE-REFRESH body** (RFC 2918 §3):
//
//   - AFI (uint16 BE) — Address Family Identifier (e.g.
//     1 IPv4, 2 IPv6)
//
//   - Reserved (1 byte; was Subtype in RFC 7313)
//
//   - SAFI (1 byte) — Subsequent AFI (e.g. 1 unicast,
//     2 multicast, 4 MPLS Label, 128 VPNv4)
//
// What this package does NOT cover (deliberately out of scope)
//
//   - TCP framing — feed the bytes after a TCP/179 stream
//     reassembly. BGP messages can span multiple TCP segments.
//
//   - Path Attribute deep dissection — AS_PATH segments,
//     COMMUNITY tuples, MP_REACH AFI/SAFI/Next-Hop/NLRI
//     parsing — the per-attribute body is surfaced as raw
//     hex. A future Spec would walk each attribute type.
//
//   - Capability Value deep dissection — most capabilities
//     have their own sub-format; we surface the code +
//     length + raw value.
//
//   - Route Filter / FlowSpec / RT-Constraint NLRI types —
//     specialised AFI/SAFI combinations beyond the basic
//     IPv4/IPv6 unicast.
//
//   - Multi-message TCP-stream walking — this decoder
//     handles a single BGP message; the caller frames the
//     stream into messages using the 16-byte 0xFF marker
//     and Length field.
package bgp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	MarkerValid    bool   `json:"marker_valid"`
	MarkerHex      string `json:"marker_hex,omitempty"`
	LengthDeclared int    `json:"length_declared"`
	Type           int    `json:"type"`
	TypeName       string `json:"type_name"`
	TotalBytes     int    `json:"total_bytes"`

	Open         *OpenMsg         `json:"open,omitempty"`
	Update       *UpdateMsg       `json:"update,omitempty"`
	Notification *NotificationMsg `json:"notification,omitempty"`
	Keepalive    *KeepaliveMsg    `json:"keepalive,omitempty"`
	RouteRefresh *RouteRefreshMsg `json:"route_refresh,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// OpenMsg is the body of message type 1.
type OpenMsg struct {
	Version       int        `json:"version"`
	MyAS          uint16     `json:"my_as"`
	HoldTime      uint16     `json:"hold_time_seconds"`
	BGPIdentifier string     `json:"bgp_identifier"`
	OptParamLen   int        `json:"opt_param_length"`
	OptParameters []OptParam `json:"opt_parameters,omitempty"`
}

// OptParam is one Optional Parameter inside an OPEN message.
type OptParam struct {
	Type         int          `json:"type"`
	TypeName     string       `json:"type_name"`
	Length       int          `json:"length"`
	RawHex       string       `json:"raw_hex,omitempty"`
	Capabilities []Capability `json:"capabilities,omitempty"`
}

// Capability is one Capability (RFC 5492) inside a Type 2
// Optional Parameter.
type Capability struct {
	Code     int    `json:"code"`
	CodeName string `json:"code_name"`
	Length   int    `json:"length"`
	ValueHex string `json:"value_hex,omitempty"`
}

// UpdateMsg is the body of message type 2.
type UpdateMsg struct {
	WithdrawnRoutesLength    int             `json:"withdrawn_routes_length"`
	WithdrawnRoutes          []NLRIPrefix    `json:"withdrawn_routes,omitempty"`
	TotalPathAttributeLength int             `json:"total_path_attribute_length"`
	PathAttributes           []PathAttribute `json:"path_attributes,omitempty"`
	NLRI                     []NLRIPrefix    `json:"nlri,omitempty"`
}

// NLRIPrefix is one (prefix-length + prefix-bytes) entry.
type NLRIPrefix struct {
	PrefixLength int    `json:"prefix_length"`
	PrefixHex    string `json:"prefix_hex,omitempty"`
	IPv4         string `json:"ipv4,omitempty"`
}

// PathAttribute is one TLV in the UPDATE Path Attributes
// section.
type PathAttribute struct {
	FlagsHex       string `json:"flags_hex"`
	Optional       bool   `json:"optional"`
	Transitive     bool   `json:"transitive"`
	Partial        bool   `json:"partial"`
	ExtendedLength bool   `json:"extended_length"`
	Type           int    `json:"type"`
	TypeName       string `json:"type_name"`
	Length         int    `json:"length"`
	ValueHex       string `json:"value_hex,omitempty"`
}

// NotificationMsg is the body of message type 3.
type NotificationMsg struct {
	ErrorCode        int    `json:"error_code"`
	ErrorCodeName    string `json:"error_code_name"`
	ErrorSubcode     int    `json:"error_subcode"`
	ErrorSubcodeName string `json:"error_subcode_name,omitempty"`
	DataHex          string `json:"data_hex,omitempty"`
}

// KeepaliveMsg is the body of message type 4 (always empty).
type KeepaliveMsg struct{}

// RouteRefreshMsg is the body of message type 5 (RFC 2918).
type RouteRefreshMsg struct {
	AFI      int    `json:"afi"`
	AFIName  string `json:"afi_name"`
	Reserved int    `json:"reserved"`
	SAFI     int    `json:"safi"`
	SAFIName string `json:"safi_name"`
}

// Decode parses a single BGP-4 message from hex.
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
	if len(b) < 19 {
		return nil, fmt.Errorf("BGP header truncated (%d bytes; need ≥19)", len(b))
	}

	r := &Result{
		TotalBytes:     len(b),
		LengthDeclared: int(binary.BigEndian.Uint16(b[16:18])),
		Type:           int(b[18]),
	}
	r.TypeName = typeName(r.Type)
	r.MarkerValid = isAllOnes(b[0:16])
	if !r.MarkerValid {
		r.MarkerHex = strings.ToUpper(hex.EncodeToString(b[0:16]))
		r.Notes = append(r.Notes,
			"Marker bytes are NOT all 0xFF — RFC 4271 §4.1 requires the 16-byte "+
				"marker to be all 1-bits for protocol fidelity. This may indicate "+
				"a non-BGP packet, a corrupt frame, or a legacy authentication "+
				"variant.")
	}

	if r.LengthDeclared > len(b) {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"declared Length %d exceeds buffer length %d (message truncated)",
			r.LengthDeclared, len(b)))
	}
	if r.LengthDeclared < 19 {
		return nil, fmt.Errorf("declared Length %d < 19 (impossible for a BGP message)",
			r.LengthDeclared)
	}

	body := b[19:]
	if r.LengthDeclared <= len(b) {
		body = b[19:r.LengthDeclared]
	}

	switch r.Type {
	case 1:
		om, err := decodeOpen(body)
		if err != nil {
			return nil, err
		}
		r.Open = om
	case 2:
		um, err := decodeUpdate(body)
		if err != nil {
			return nil, err
		}
		r.Update = um
	case 3:
		r.Notification = decodeNotification(body)
	case 4:
		r.Keepalive = &KeepaliveMsg{}
		if len(body) > 0 {
			r.Notes = append(r.Notes, fmt.Sprintf(
				"KEEPALIVE has %d trailing bytes; RFC 4271 §4.4 says KEEPALIVE is "+
					"exactly 19 bytes (header only)",
				len(body)))
		}
	case 5:
		rr, err := decodeRouteRefresh(body)
		if err != nil {
			return nil, err
		}
		r.RouteRefresh = rr
	default:
		r.Notes = append(r.Notes, fmt.Sprintf(
			"uncatalogued message type %d (RFC 4271 defines 1-4; RFC 2918 defines 5)",
			r.Type))
	}

	return r, nil
}

func decodeOpen(b []byte) (*OpenMsg, error) {
	if len(b) < 10 {
		return nil, fmt.Errorf("OPEN body too short (%d; need ≥10)", len(b))
	}
	o := &OpenMsg{
		Version:       int(b[0]),
		MyAS:          binary.BigEndian.Uint16(b[1:3]),
		HoldTime:      binary.BigEndian.Uint16(b[3:5]),
		BGPIdentifier: net.IPv4(b[5], b[6], b[7], b[8]).String(),
		OptParamLen:   int(b[9]),
	}
	if 10+o.OptParamLen > len(b) {
		return o, nil // surface partial decode
	}
	pp := b[10 : 10+o.OptParamLen]
	off := 0
	for off+2 <= len(pp) {
		typ := int(pp[off])
		ln := int(pp[off+1])
		if off+2+ln > len(pp) {
			break
		}
		val := pp[off+2 : off+2+ln]
		op := OptParam{
			Type:     typ,
			TypeName: optParamTypeName(typ),
			Length:   ln,
			RawHex:   strings.ToUpper(hex.EncodeToString(val)),
		}
		if typ == 2 {
			op.Capabilities = parseCapabilities(val)
		}
		o.OptParameters = append(o.OptParameters, op)
		off += 2 + ln
	}
	return o, nil
}

func parseCapabilities(b []byte) []Capability {
	var caps []Capability
	off := 0
	for off+2 <= len(b) {
		code := int(b[off])
		ln := int(b[off+1])
		if off+2+ln > len(b) {
			break
		}
		c := Capability{
			Code:     code,
			CodeName: capabilityCodeName(code),
			Length:   ln,
		}
		if ln > 0 {
			c.ValueHex = strings.ToUpper(hex.EncodeToString(b[off+2 : off+2+ln]))
		}
		caps = append(caps, c)
		off += 2 + ln
	}
	return caps
}

func decodeUpdate(b []byte) (*UpdateMsg, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("UPDATE body truncated (no withdrawn-routes length)")
	}
	um := &UpdateMsg{
		WithdrawnRoutesLength: int(binary.BigEndian.Uint16(b[0:2])),
	}
	off := 2
	if off+um.WithdrawnRoutesLength > len(b) {
		return nil, fmt.Errorf("UPDATE withdrawn-routes length %d exceeds buffer",
			um.WithdrawnRoutesLength)
	}
	um.WithdrawnRoutes = parsePrefixes(b[off : off+um.WithdrawnRoutesLength])
	off += um.WithdrawnRoutesLength

	if off+2 > len(b) {
		return nil, fmt.Errorf("UPDATE missing path-attribute length")
	}
	um.TotalPathAttributeLength = int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if off+um.TotalPathAttributeLength > len(b) {
		return nil, fmt.Errorf("UPDATE path-attribute length %d exceeds buffer",
			um.TotalPathAttributeLength)
	}
	um.PathAttributes = parsePathAttributes(b[off : off+um.TotalPathAttributeLength])
	off += um.TotalPathAttributeLength

	um.NLRI = parsePrefixes(b[off:])
	return um, nil
}

func parsePrefixes(b []byte) []NLRIPrefix {
	var out []NLRIPrefix
	off := 0
	for off < len(b) {
		plen := int(b[off])
		off++
		bytesNeeded := (plen + 7) / 8
		if off+bytesNeeded > len(b) {
			break
		}
		p := NLRIPrefix{PrefixLength: plen}
		if bytesNeeded > 0 {
			pb := b[off : off+bytesNeeded]
			p.PrefixHex = strings.ToUpper(hex.EncodeToString(pb))
			if plen <= 32 && bytesNeeded <= 4 {
				ip := make([]byte, 4)
				copy(ip, pb)
				p.IPv4 = fmt.Sprintf("%s/%d", net.IPv4(ip[0], ip[1], ip[2], ip[3]), plen)
			}
		} else {
			p.IPv4 = fmt.Sprintf("0.0.0.0/%d", plen)
		}
		out = append(out, p)
		off += bytesNeeded
	}
	return out
}

func parsePathAttributes(b []byte) []PathAttribute {
	var out []PathAttribute
	off := 0
	for off+3 <= len(b) {
		flags := b[off]
		typ := int(b[off+1])
		off += 2
		var ln int
		if flags&0x10 != 0 { // Extended Length
			if off+2 > len(b) {
				break
			}
			ln = int(binary.BigEndian.Uint16(b[off : off+2]))
			off += 2
		} else {
			ln = int(b[off])
			off++
		}
		if off+ln > len(b) {
			break
		}
		val := b[off : off+ln]
		pa := PathAttribute{
			FlagsHex:       fmt.Sprintf("0x%02X", flags),
			Optional:       flags&0x80 != 0,
			Transitive:     flags&0x40 != 0,
			Partial:        flags&0x20 != 0,
			ExtendedLength: flags&0x10 != 0,
			Type:           typ,
			TypeName:       pathAttributeTypeName(typ),
			Length:         ln,
		}
		if ln > 0 {
			pa.ValueHex = strings.ToUpper(hex.EncodeToString(val))
		}
		out = append(out, pa)
		off += ln
	}
	return out
}

func decodeNotification(b []byte) *NotificationMsg {
	n := &NotificationMsg{}
	if len(b) < 2 {
		return n
	}
	n.ErrorCode = int(b[0])
	n.ErrorSubcode = int(b[1])
	n.ErrorCodeName = errorCodeName(n.ErrorCode)
	n.ErrorSubcodeName = errorSubcodeName(n.ErrorCode, n.ErrorSubcode)
	if len(b) > 2 {
		n.DataHex = strings.ToUpper(hex.EncodeToString(b[2:]))
	}
	return n
}

func decodeRouteRefresh(b []byte) (*RouteRefreshMsg, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("ROUTE-REFRESH body truncated (%d; need 4)", len(b))
	}
	rr := &RouteRefreshMsg{
		AFI:      int(binary.BigEndian.Uint16(b[0:2])),
		Reserved: int(b[2]),
		SAFI:     int(b[3]),
	}
	rr.AFIName = afiName(rr.AFI)
	rr.SAFIName = safiName(rr.SAFI)
	return rr, nil
}

func typeName(t int) string {
	switch t {
	case 1:
		return "OPEN"
	case 2:
		return "UPDATE"
	case 3:
		return "NOTIFICATION"
	case 4:
		return "KEEPALIVE"
	case 5:
		return "ROUTE-REFRESH"
	}
	return fmt.Sprintf("uncatalogued type %d", t)
}

func optParamTypeName(t int) string {
	switch t {
	case 1:
		return "Authentication (deprecated, RFC 5492 §3)"
	case 2:
		return "Capabilities (RFC 5492)"
	}
	return fmt.Sprintf("uncatalogued opt-param type %d", t)
}

func capabilityCodeName(c int) string {
	switch c {
	case 1:
		return "Multiprotocol Extensions (MP-BGP, RFC 4760)"
	case 2:
		return "Route Refresh (RFC 2918)"
	case 64:
		return "Graceful Restart (RFC 4724)"
	case 65:
		return "4-byte AS Number (RFC 6793)"
	case 67:
		return "Dynamic Capability (RFC 4396)"
	case 70:
		return "Enhanced Route Refresh (RFC 7313)"
	case 71:
		return "Long-Lived Graceful Restart (RFC 9494)"
	}
	return fmt.Sprintf("uncatalogued capability %d", c)
}

func pathAttributeTypeName(t int) string {
	switch t {
	case 1:
		return "ORIGIN"
	case 2:
		return "AS_PATH"
	case 3:
		return "NEXT_HOP"
	case 4:
		return "MULTI_EXIT_DISC (MED)"
	case 5:
		return "LOCAL_PREF"
	case 6:
		return "ATOMIC_AGGREGATE"
	case 7:
		return "AGGREGATOR"
	case 8:
		return "COMMUNITY (RFC 1997)"
	case 9:
		return "ORIGINATOR_ID"
	case 10:
		return "CLUSTER_LIST"
	case 14:
		return "MP_REACH_NLRI (RFC 4760)"
	case 15:
		return "MP_UNREACH_NLRI (RFC 4760)"
	case 16:
		return "EXTENDED_COMMUNITIES (RFC 4360)"
	case 17:
		return "AS4_PATH (RFC 6793)"
	case 18:
		return "AS4_AGGREGATOR (RFC 6793)"
	case 32:
		return "LARGE_COMMUNITY (RFC 8092)"
	}
	return fmt.Sprintf("uncatalogued attribute %d", t)
}

func errorCodeName(c int) string {
	switch c {
	case 1:
		return "Message Header Error"
	case 2:
		return "OPEN Message Error"
	case 3:
		return "UPDATE Message Error"
	case 4:
		return "Hold Timer Expired"
	case 5:
		return "Finite State Machine Error"
	case 6:
		return "Cease (RFC 4486)"
	}
	return fmt.Sprintf("uncatalogued error %d", c)
}

func errorSubcodeName(code, sub int) string {
	switch code {
	case 1: // Message Header Error
		switch sub {
		case 1:
			return "Connection Not Synchronised"
		case 2:
			return "Bad Message Length"
		case 3:
			return "Bad Message Type"
		}
	case 2: // OPEN Message Error
		switch sub {
		case 1:
			return "Unsupported Version Number"
		case 2:
			return "Bad Peer AS"
		case 3:
			return "Bad BGP Identifier"
		case 4:
			return "Unsupported Optional Parameter"
		case 5:
			return "Authentication Failure (deprecated)"
		case 6:
			return "Unacceptable Hold Time"
		case 7:
			return "Unsupported Capability (RFC 5492)"
		}
	case 3: // UPDATE Message Error
		switch sub {
		case 1:
			return "Malformed Attribute List"
		case 2:
			return "Unrecognized Well-known Attribute"
		case 3:
			return "Missing Well-known Attribute"
		case 4:
			return "Attribute Flags Error"
		case 5:
			return "Attribute Length Error"
		case 6:
			return "Invalid ORIGIN Attribute"
		case 8:
			return "Invalid NEXT_HOP Attribute"
		case 9:
			return "Optional Attribute Error"
		case 10:
			return "Invalid Network Field"
		case 11:
			return "Malformed AS_PATH"
		}
	case 6: // Cease (RFC 4486)
		switch sub {
		case 1:
			return "Maximum Number of Prefixes Reached"
		case 2:
			return "Administrative Shutdown"
		case 3:
			return "Peer De-configured"
		case 4:
			return "Administrative Reset"
		case 5:
			return "Connection Rejected"
		case 6:
			return "Other Configuration Change"
		case 7:
			return "Connection Collision Resolution"
		case 8:
			return "Out of Resources"
		case 9:
			return "Hard Reset (RFC 8538)"
		}
	}
	return ""
}

func afiName(a int) string {
	switch a {
	case 1:
		return "IPv4"
	case 2:
		return "IPv6"
	case 25:
		return "L2VPN"
	}
	return fmt.Sprintf("uncatalogued AFI %d", a)
}

func safiName(s int) string {
	switch s {
	case 1:
		return "unicast"
	case 2:
		return "multicast"
	case 4:
		return "MPLS Label (RFC 8277)"
	case 5:
		return "MCAST-VPN"
	case 70:
		return "EVPN (RFC 7432)"
	case 71:
		return "BGP-LS (Link State, RFC 7752)"
	case 128:
		return "VPNv4 (RFC 4364)"
	case 129:
		return "VPNv6 (RFC 4659)"
	}
	return fmt.Sprintf("uncatalogued SAFI %d", s)
}

func isAllOnes(b []byte) bool {
	for _, v := range b {
		if v != 0xFF {
			return false
		}
	}
	return true
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
