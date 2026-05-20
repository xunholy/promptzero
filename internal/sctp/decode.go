// Package sctp decodes Stream Control Transmission Protocol
// (SCTP) packets per RFC 4960 (with the AUTH / ASCONF /
// RE-CONFIG / PAD / FORWARD-TSN chunk types from RFCs 4895 /
// 5061 / 6525 / 4820 / 3758).
//
// SCTP is the third pillar transport alongside TCP and UDP —
// often forgotten in security tooling, but foundational for:
//
//   - **Telco signalling** — the dominant transport for
//     SIGTRAN protocols (M2PA, M2UA, M3UA, SUA, IUA), 3GPP
//     LTE/5G control plane (S1AP, X2AP, NGAP, XnAP), Diameter
//     (RFC 6733 — 3GPP AAA successor to RADIUS).
//
//   - **WebRTC data channels** — every browser-to-browser
//     data-channel session is SCTP-over-DTLS-over-UDP per
//     RFC 8261.
//
//   - **Multipath HA pairs** — multi-homed servers use SCTP
//     to keep a session up across redundant network paths
//     without the application noticing.
//
// Wrap-vs-native judgement
//
//	Native. RFC 4960 is fully public; SCTP has a tight
//	12-byte common header followed by one or more chunks
//	(each a TLV: Type + Flags + Length + body padded to a
//	4-byte boundary). No crypto at the parse layer.
//	Operators paste SCTP bytes (IP protocol number 132)
//	from a `tcpdump -X ip proto 132` line or a Wireshark
//	Follow-SCTP-Stream view and get the documented header
//	+ chunk-by-chunk breakdown.
//
// What this package covers
//
//   - **12-byte common header** (RFC 4960 §3.1):
//
//   - bytes 0-1: Source Port (uint16 BE).
//
//   - bytes 2-3: Destination Port (uint16 BE).
//
//   - bytes 4-7: Verification Tag (uint32 BE; the tag
//     this end expects from the peer for this
//     association; zero on the first INIT).
//
//   - bytes 8-11: Checksum (uint32 BE; CRC32c per
//     RFC 3309 — surfaced as hex for traceability).
//
//   - **Chunk walker** — repeated 4-byte header (Type
//     uint8 + Flags uint8 + Length uint16 BE) + body
//     (Length - 4 bytes) + optional trailing pad bytes to
//     reach a 4-byte boundary. The 4-byte alignment is
//     critical because chunk Lengths are typically odd
//     (DATA payloads aren't 32-bit aligned).
//
//   - **20-entry chunk type name table** (RFC 4960 §3.2 +
//     IANA SCTP chunk-types registry):
//     0 DATA, 1 INIT, 2 INIT_ACK, 3 SACK, 4 HEARTBEAT,
//     5 HEARTBEAT_ACK, 6 ABORT, 7 SHUTDOWN, 8 SHUTDOWN_ACK,
//     9 ERROR, 10 COOKIE_ECHO, 11 COOKIE_ACK, 12 ECNE,
//     13 CWR, 14 SHUTDOWN_COMPLETE, 15 AUTH (RFC 4895),
//     128 ASCONF_ACK (RFC 5061), 129 RE-CONFIG (RFC 6525),
//     130 PAD (RFC 4820), 132 ASCONF (RFC 5061),
//     192 FORWARD-TSN (RFC 3758).
//
//   - **DATA chunk body** (Type 0; RFC 4960 §3.3.1):
//
//   - 4-byte TSN (Transmission Sequence Number).
//
//   - 2-byte Stream Identifier (channel within the
//     association).
//
//   - 2-byte Stream Sequence Number.
//
//   - 4-byte **Payload Protocol Identifier (PPID)**
//     with a ~25-entry name table covering the most
//     common upper-layer protocols (M2UA / M3UA / SUA /
//     IUA / M2PA / Diameter / S1AP / NGAP / X2AP /
//     BICC / TALI / etc.).
//
//   - User Data (variable).
//
//   - Flag bits (in the 1-byte Flags after Type): U =
//     Unordered, B = Beginning fragment, E = Ending
//     fragment, I = SACK Immediately.
//
//   - **INIT / INIT_ACK chunk body** (Types 1 + 2;
//     RFC 4960 §3.3.2 + §3.3.3):
//
//   - 4-byte Initiate Tag (the tag the SENDER will use
//     for the association — the peer copies this into
//     its Verification Tag field).
//
//   - 4-byte Advertised Receiver Window Credit (a_rwnd —
//     the receive buffer size in bytes).
//
//   - 2-byte Number of Outbound Streams.
//
//   - 2-byte Number of Inbound Streams.
//
//   - 4-byte Initial TSN (the TSN of the first DATA
//     chunk this sender will use).
//
//   - Variable-length parameters (TLV: 2-byte type +
//     2-byte length + value padded to 4-byte boundary;
//     walked for the most common parameter types — IPv4
//     Address / IPv6 Address / Cookie Preservative /
//     Hostname / Supported Address Types / State Cookie).
//
//   - **SACK chunk body** (Type 3; RFC 4960 §3.3.4):
//
//   - 4-byte Cumulative TSN Ack.
//
//   - 4-byte Advertised Receiver Window Credit.
//
//   - 2-byte Number of Gap Ack Blocks.
//
//   - 2-byte Number of Duplicate TSNs.
//
//   - Gap Ack Blocks (each 4 bytes: Start + End uint16
//     BE relative to Cumulative TSN Ack).
//
//   - Duplicate TSN list (uint32 BE each).
//
//   - **HEARTBEAT / HEARTBEAT_ACK chunk body** (Types 4 + 5;
//     RFC 4960 §3.3.5 + §3.3.6) — Heartbeat Info Parameter
//     (TLV with Type 1 + Length + opaque Info; surfaced as
//     hex for the operator to correlate request/reply).
//
//   - **ABORT / SHUTDOWN / ERROR chunk bodies** — surfaced
//     structurally; ABORT + ERROR carry Error Cause TLVs
//     (cause code with a 13-entry name table per IANA
//     SCTP Cause-Codes registry).
//
//   - **COOKIE_ECHO / COOKIE_ACK / SHUTDOWN_COMPLETE / CWR /
//     ECNE** — minimal bodies; surfaced via the chunk header
//     plus a hex preview.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - IP framing — feed SCTP bytes after the IPv4/IPv6
//     header strip. SCTP runs over IP protocol 132.
//
//   - CRC32c checksum verification — the checksum is
//     surfaced as hex but not re-computed; verifying it
//     would not change the decoded view.
//
//   - Upper-layer dissection — once the PPID is decoded
//     the operator feeds the DATA payload into the
//     existing application-layer Specs (Diameter would
//     warrant a future Spec; SIP / RTP / DNS / etc. are
//     already covered).
//
//   - SCTP-over-UDP (RFC 6951) and SCTP-over-DTLS (RFC 8261)
//     framing — both wrap the same SCTP common header; feed
//     bytes starting at the SCTP common header.
//
//   - Association state-machine reasoning (4-way handshake
//     INIT/INIT_ACK/COOKIE_ECHO/COOKIE_ACK, multi-homing,
//     graceful shutdown) — higher-level analysis.
package sctp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"
)

// Result is the top-level decoded view of an SCTP packet.
type Result struct {
	SourcePort      int      `json:"source_port"`
	DestinationPort int      `json:"destination_port"`
	VerificationTag uint32   `json:"verification_tag"`
	ChecksumHex     string   `json:"checksum_hex"`
	Chunks          []Chunk  `json:"chunks"`
	TotalBytes      int      `json:"total_bytes"`
	Notes           []string `json:"notes,omitempty"`
}

// Chunk is one (Type, Flags, Length, Value) record from the
// chunk walker with optional decoded body.
type Chunk struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Flags    int    `json:"flags"`
	FlagsHex string `json:"flags_hex"`
	Length   int    `json:"length"`
	BodyHex  string `json:"body_hex,omitempty"`

	// Decoded forms populated for known chunk types.
	DataChunk     *DataChunkBody `json:"data,omitempty"`
	InitChunk     *InitChunkBody `json:"init,omitempty"`
	InitAckChunk  *InitChunkBody `json:"init_ack,omitempty"`
	SACKChunk     *SACKChunkBody `json:"sack,omitempty"`
	HeartbeatInfo *HeartbeatBody `json:"heartbeat,omitempty"`
	ErrorCauses   []ErrorCause   `json:"error_causes,omitempty"`
}

// DataChunkBody is the decoded body of a Type=0 DATA chunk.
type DataChunkBody struct {
	TSN              uint32 `json:"tsn"`
	StreamIdentifier int    `json:"stream_identifier"`
	StreamSequence   int    `json:"stream_sequence_number"`
	PPID             uint32 `json:"payload_protocol_identifier"`
	PPIDName         string `json:"payload_protocol_identifier_name,omitempty"`
	UserDataBytes    int    `json:"user_data_bytes"`
	UserDataHex      string `json:"user_data_hex,omitempty"`
	FlagUnordered    bool   `json:"flag_unordered"`
	FlagBeginning    bool   `json:"flag_beginning_fragment"`
	FlagEnding       bool   `json:"flag_ending_fragment"`
	FlagSACKImm      bool   `json:"flag_sack_immediate"`
}

// InitChunkBody is the decoded body of a Type=1 INIT or
// Type=2 INIT_ACK chunk.
type InitChunkBody struct {
	InitiateTag             uint32      `json:"initiate_tag"`
	AdvReceiverWindowCredit uint32      `json:"advertised_receiver_window_credit"`
	OutboundStreams         int         `json:"outbound_streams"`
	InboundStreams          int         `json:"inbound_streams"`
	InitialTSN              uint32      `json:"initial_tsn"`
	Parameters              []Parameter `json:"parameters,omitempty"`
}

// Parameter is one variable-length parameter inside an INIT
// or INIT_ACK body.
type Parameter struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Length   int    `json:"length"`
	ValueHex string `json:"value_hex,omitempty"`

	// Decoded forms populated for known parameter types.
	IPv4Address                 string  `json:"ipv4_address,omitempty"`
	IPv6Address                 string  `json:"ipv6_address,omitempty"`
	HostnameText                string  `json:"hostname_text,omitempty"`
	SupportedAddrTypes          []int   `json:"supported_address_types,omitempty"`
	CookiePreservativeIncrement *uint32 `json:"cookie_preservative_increment,omitempty"`
}

// SACKChunkBody is the decoded body of a Type=3 SACK chunk.
type SACKChunkBody struct {
	CumulativeTSNAck  uint32        `json:"cumulative_tsn_ack"`
	AdvReceiverWindow uint32        `json:"advertised_receiver_window_credit"`
	NumGapAckBlocks   int           `json:"num_gap_ack_blocks"`
	NumDuplicateTSNs  int           `json:"num_duplicate_tsns"`
	GapAckBlocks      []GapAckBlock `json:"gap_ack_blocks,omitempty"`
	DuplicateTSNs     []uint32      `json:"duplicate_tsns,omitempty"`
}

// GapAckBlock is one (Start, End) gap-ack range inside a
// SACK chunk; offsets are relative to CumulativeTSNAck.
type GapAckBlock struct {
	Start int `json:"start_offset"`
	End   int `json:"end_offset"`
}

// HeartbeatBody is the decoded body of HEARTBEAT /
// HEARTBEAT_ACK chunks — a single Heartbeat Info parameter.
type HeartbeatBody struct {
	InfoParameterType   int    `json:"info_parameter_type"`
	InfoParameterLength int    `json:"info_parameter_length"`
	InfoHex             string `json:"info_hex,omitempty"`
}

// ErrorCause is one (Code, Length, Body) entry from an ABORT
// or ERROR chunk's variable-length error-cause list.
type ErrorCause struct {
	Code     int    `json:"code"`
	CodeName string `json:"code_name"`
	Length   int    `json:"length"`
	BodyHex  string `json:"body_hex,omitempty"`
}

// Decode parses a single SCTP packet from hex.
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
	if len(b) < 12 {
		return nil, fmt.Errorf("SCTP packet truncated (%d bytes; need ≥12 for common header)",
			len(b))
	}
	r := &Result{
		TotalBytes:      len(b),
		SourcePort:      int(binary.BigEndian.Uint16(b[0:2])),
		DestinationPort: int(binary.BigEndian.Uint16(b[2:4])),
		VerificationTag: binary.BigEndian.Uint32(b[4:8]),
		ChecksumHex:     fmt.Sprintf("0x%08X", binary.BigEndian.Uint32(b[8:12])),
	}
	off := 12
	for off+4 <= len(b) {
		c, used, err := decodeChunk(b[off:])
		if err != nil {
			r.Notes = append(r.Notes, err.Error())
			break
		}
		r.Chunks = append(r.Chunks, c)
		off += used
	}
	return r, nil
}

func decodeChunk(b []byte) (Chunk, int, error) {
	if len(b) < 4 {
		return Chunk{}, 0, fmt.Errorf("chunk header truncated")
	}
	typ := int(b[0])
	flags := int(b[1])
	ln := int(binary.BigEndian.Uint16(b[2:4]))
	if ln < 4 {
		return Chunk{}, 0, fmt.Errorf("chunk type %d declares length %d (< 4 header bytes)",
			typ, ln)
	}
	if ln > len(b) {
		return Chunk{}, 0, fmt.Errorf("chunk type %d declares length %d but only %d remain",
			typ, ln, len(b))
	}
	body := b[4:ln]
	c := Chunk{
		Type:     typ,
		TypeName: chunkTypeName(typ),
		Flags:    flags,
		FlagsHex: fmt.Sprintf("0x%02X", flags),
		Length:   ln,
		BodyHex:  strings.ToUpper(hex.EncodeToString(body)),
	}
	switch typ {
	case 0:
		c.DataChunk = decodeDataChunk(body, byte(flags))
	case 1:
		c.InitChunk = decodeInitChunk(body)
	case 2:
		c.InitAckChunk = decodeInitChunk(body)
	case 3:
		c.SACKChunk = decodeSACKChunk(body)
	case 4, 5:
		c.HeartbeatInfo = decodeHeartbeat(body)
	case 6, 9:
		c.ErrorCauses = decodeErrorCauses(body)
	}
	// Pad to 4-byte boundary.
	padded := ln + ((4 - (ln % 4)) % 4)
	if padded > len(b) {
		padded = len(b)
	}
	return c, padded, nil
}

func decodeDataChunk(b []byte, flags byte) *DataChunkBody {
	if len(b) < 12 {
		return nil
	}
	d := &DataChunkBody{
		TSN:              binary.BigEndian.Uint32(b[0:4]),
		StreamIdentifier: int(binary.BigEndian.Uint16(b[4:6])),
		StreamSequence:   int(binary.BigEndian.Uint16(b[6:8])),
		PPID:             binary.BigEndian.Uint32(b[8:12]),
		FlagUnordered:    flags&0x04 != 0,
		FlagBeginning:    flags&0x02 != 0,
		FlagEnding:       flags&0x01 != 0,
		FlagSACKImm:      flags&0x08 != 0,
	}
	d.PPIDName = ppidName(d.PPID)
	user := b[12:]
	d.UserDataBytes = len(user)
	if len(user) > 0 {
		// Cap preview to 64 bytes so big DATA payloads
		// stay within a reasonable output size.
		show := len(user)
		if show > 64 {
			show = 64
		}
		d.UserDataHex = strings.ToUpper(hex.EncodeToString(user[:show]))
	}
	return d
}

func decodeInitChunk(b []byte) *InitChunkBody {
	if len(b) < 16 {
		return nil
	}
	ic := &InitChunkBody{
		InitiateTag:             binary.BigEndian.Uint32(b[0:4]),
		AdvReceiverWindowCredit: binary.BigEndian.Uint32(b[4:8]),
		OutboundStreams:         int(binary.BigEndian.Uint16(b[8:10])),
		InboundStreams:          int(binary.BigEndian.Uint16(b[10:12])),
		InitialTSN:              binary.BigEndian.Uint32(b[12:16]),
	}
	if len(b) > 16 {
		ic.Parameters = decodeParameters(b[16:])
	}
	return ic
}

func decodeParameters(b []byte) []Parameter {
	var out []Parameter
	off := 0
	for off+4 <= len(b) {
		typ := int(binary.BigEndian.Uint16(b[off : off+2]))
		ln := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if ln < 4 || off+ln > len(b) {
			return out
		}
		v := b[off+4 : off+ln]
		p := Parameter{
			Type:     typ,
			TypeName: parameterTypeName(typ),
			Length:   ln,
			ValueHex: strings.ToUpper(hex.EncodeToString(v)),
		}
		switch typ {
		case 5: // IPv4 Address
			if len(v) == 4 {
				p.IPv4Address = net.IPv4(v[0], v[1], v[2], v[3]).String()
			}
		case 6: // IPv6 Address
			if len(v) == 16 {
				p.IPv6Address = net.IP(v).String()
			}
		case 9: // Cookie Preservative
			if len(v) == 4 {
				inc := binary.BigEndian.Uint32(v)
				p.CookiePreservativeIncrement = &inc
			}
		case 11: // Hostname
			if utf8.Valid(v) {
				p.HostnameText = strings.TrimRight(string(v), "\x00")
			}
		case 12: // Supported Address Types
			for i := 0; i+2 <= len(v); i += 2 {
				p.SupportedAddrTypes = append(p.SupportedAddrTypes,
					int(binary.BigEndian.Uint16(v[i:i+2])))
			}
		}
		out = append(out, p)
		padded := off + ln + ((4 - (ln % 4)) % 4)
		off = padded
	}
	return out
}

func decodeSACKChunk(b []byte) *SACKChunkBody {
	if len(b) < 12 {
		return nil
	}
	s := &SACKChunkBody{
		CumulativeTSNAck:  binary.BigEndian.Uint32(b[0:4]),
		AdvReceiverWindow: binary.BigEndian.Uint32(b[4:8]),
		NumGapAckBlocks:   int(binary.BigEndian.Uint16(b[8:10])),
		NumDuplicateTSNs:  int(binary.BigEndian.Uint16(b[10:12])),
	}
	off := 12
	for i := 0; i < s.NumGapAckBlocks && off+4 <= len(b); i++ {
		s.GapAckBlocks = append(s.GapAckBlocks, GapAckBlock{
			Start: int(binary.BigEndian.Uint16(b[off : off+2])),
			End:   int(binary.BigEndian.Uint16(b[off+2 : off+4])),
		})
		off += 4
	}
	for i := 0; i < s.NumDuplicateTSNs && off+4 <= len(b); i++ {
		s.DuplicateTSNs = append(s.DuplicateTSNs,
			binary.BigEndian.Uint32(b[off:off+4]))
		off += 4
	}
	return s
}

func decodeHeartbeat(b []byte) *HeartbeatBody {
	if len(b) < 4 {
		return nil
	}
	h := &HeartbeatBody{
		InfoParameterType:   int(binary.BigEndian.Uint16(b[0:2])),
		InfoParameterLength: int(binary.BigEndian.Uint16(b[2:4])),
	}
	if h.InfoParameterLength >= 4 && h.InfoParameterLength <= len(b) {
		info := b[4:h.InfoParameterLength]
		h.InfoHex = strings.ToUpper(hex.EncodeToString(info))
	}
	return h
}

func decodeErrorCauses(b []byte) []ErrorCause {
	var out []ErrorCause
	off := 0
	for off+4 <= len(b) {
		code := int(binary.BigEndian.Uint16(b[off : off+2]))
		ln := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if ln < 4 || off+ln > len(b) {
			return out
		}
		body := b[off+4 : off+ln]
		out = append(out, ErrorCause{
			Code:     code,
			CodeName: errorCauseName(code),
			Length:   ln,
			BodyHex:  strings.ToUpper(hex.EncodeToString(body)),
		})
		padded := off + ln + ((4 - (ln % 4)) % 4)
		off = padded
	}
	return out
}

func chunkTypeName(t int) string {
	switch t {
	case 0:
		return "DATA"
	case 1:
		return "INIT"
	case 2:
		return "INIT_ACK"
	case 3:
		return "SACK"
	case 4:
		return "HEARTBEAT"
	case 5:
		return "HEARTBEAT_ACK"
	case 6:
		return "ABORT"
	case 7:
		return "SHUTDOWN"
	case 8:
		return "SHUTDOWN_ACK"
	case 9:
		return "ERROR"
	case 10:
		return "COOKIE_ECHO"
	case 11:
		return "COOKIE_ACK"
	case 12:
		return "ECNE"
	case 13:
		return "CWR"
	case 14:
		return "SHUTDOWN_COMPLETE"
	case 15:
		return "AUTH"
	case 128:
		return "ASCONF_ACK"
	case 129:
		return "RE-CONFIG"
	case 130:
		return "PAD"
	case 132:
		return "ASCONF"
	case 192:
		return "FORWARD-TSN"
	}
	return fmt.Sprintf("uncatalogued chunk type %d", t)
}

func ppidName(p uint32) string {
	switch p {
	case 0:
		return ""
	case 1:
		return "IUA (ISDN Q.921-User Adaptation)"
	case 2:
		return "M2UA (MTP2-User Adaptation)"
	case 3:
		return "M3UA (MTP3-User Adaptation)"
	case 4:
		return "SUA (SCCP-User Adaptation)"
	case 5:
		return "M2PA (MTP2 Peer Adaptation)"
	case 6:
		return "V5UA (V5.2-User Adaptation)"
	case 7:
		return "H.248 / Megaco"
	case 8:
		return "BICC (Bearer Independent Call Control)"
	case 9:
		return "TALI (Transport Adapter Layer Interface)"
	case 11:
		return "DUA (DPNSS/DASS2 User Adaptation)"
	case 13:
		return "Q.931 / H.323"
	case 18:
		return "S1AP (LTE eNodeB to MME)"
	case 19:
		return "RUA (3GPP HNB)"
	case 20:
		return "HNBAP (Home NodeB Application Part)"
	case 27:
		return "X2AP (LTE eNodeB-to-eNodeB)"
	case 33:
		return "PPP"
	case 43:
		return "M2AP"
	case 44:
		return "M3AP"
	case 46:
		return "Diameter (cleartext)"
	case 47:
		return "Diameter (over DTLS)"
	case 53:
		return "WebRTC Binary"
	case 54:
		return "WebRTC String"
	case 56:
		return "WebRTC String Empty"
	case 60:
		return "NGAP (5G NG Application Protocol)"
	case 61:
		return "XnAP (5G Xn Application Protocol)"
	}
	return fmt.Sprintf("uncatalogued PPID %d", p)
}

func parameterTypeName(t int) string {
	switch t {
	case 1:
		return "Heartbeat Info"
	case 5:
		return "IPv4 Address"
	case 6:
		return "IPv6 Address"
	case 7:
		return "State Cookie"
	case 8:
		return "Unrecognized Parameter"
	case 9:
		return "Cookie Preservative"
	case 11:
		return "Hostname"
	case 12:
		return "Supported Address Types"
	case 32768:
		return "ECN Capable"
	case 49152:
		return "Forward-TSN Supported"
	case 49158:
		return "Random (RFC 4895)"
	case 49160:
		return "Chunk List (RFC 4895)"
	case 49161:
		return "Requested HMAC Algorithm (RFC 4895)"
	}
	return fmt.Sprintf("uncatalogued parameter type %d", t)
}

func errorCauseName(c int) string {
	switch c {
	case 1:
		return "Invalid Stream Identifier"
	case 2:
		return "Missing Mandatory Parameter"
	case 3:
		return "Stale Cookie Error"
	case 4:
		return "Out of Resource"
	case 5:
		return "Unresolvable Address"
	case 6:
		return "Unrecognized Chunk Type"
	case 7:
		return "Invalid Mandatory Parameter"
	case 8:
		return "Unrecognized Parameters"
	case 9:
		return "No User Data"
	case 10:
		return "Cookie Received While Shutting Down"
	case 11:
		return "Restart of an Association with New Addresses"
	case 12:
		return "User Initiated Abort"
	case 13:
		return "Protocol Violation"
	}
	return fmt.Sprintf("uncatalogued cause %d", c)
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
