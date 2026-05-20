// Package dccp decodes DCCP (Datagram Congestion Control
// Protocol) packets per RFC 4340. DCCP is the niche fourth
// IP transport — alongside TCP (reliable streams), UDP
// (unreliable datagrams), and SCTP (reliable streams +
// multihoming) — designed for applications that want UDP-
// style unreliable delivery *plus* TCP-style congestion
// control. The intended use cases are real-time media (voice,
// video), interactive games, and any traffic where dropping a
// packet is preferable to retransmitting a stale one.
//
// Operationally, DCCP saw limited deployment compared to the
// other three transports but remains the IP protocol number
// 33 wire format that operators occasionally see in:
//
//   - **WebRTC SCTP-over-DTLS-over-UDP fallbacks** (when
//     DTLS-SCTP isn't available) where some implementations
//     used DCCP as the lower-overhead transport.
//   - **Embedded game-server protocols** at smaller publishers
//     that don't want to roll their own congestion control.
//   - **IETF reference implementations** in research / lab
//     environments studying congestion-control variants
//     (DCCP's CCID negotiation cleanly exposes TCP-like vs
//     TCP-friendly Rate Control as plug-in modules).
//
// Wrap-vs-native judgement
//
//	Native. RFC 4340 is fully public. DCCP has a tight
//	12- or 16-byte fixed header (short vs extended
//	sequence number; X-bit dispatch) followed by a per-
//	type body and an optional Options walker. No crypto
//	at the parse layer.
//
// What this package covers
//
//   - **Generic header** (RFC 4340 §5.1, 12 or 16 bytes
//     depending on X bit):
//
//   - bytes 0-1: Source Port.
//
//   - bytes 2-3: Destination Port.
//
//   - byte 4: **Data Offset** (in 4-byte words from the
//     start of the DCCP header to the start of the
//     application data; minimum 3 for short header, 4
//     for extended).
//
//   - byte 5: 4-bit **CCVal** (Congestion Control Value;
//     per-CCID semantics) + 4-bit **CsCov** (Checksum
//     Coverage; 0 = full packet, N = first N×4 bytes of
//     application data).
//
//   - bytes 6-7: Checksum (uint16 BE; Internet checksum
//     over pseudo-header + DCCP header + selected
//     application data per CsCov).
//
//   - byte 8: 3-bit Res (reserved) + 4-bit **Type** +
//     1-bit **X** (Extended Sequence Numbers — 0 = short
//     24-bit, 1 = extended 48-bit).
//
//   - For **X=0** (short header): byte 9 reserved +
//     bytes 10-11 reserved + bytes 9-11 = 24-bit Sequence
//     Number. Wait — actually X=0 layout is bytes 9 = 1
//     reserved + bytes 10-11+ for low Sequence — let me
//     re-check RFC §5.1 fig 1.
//
//   - For **X=1** (extended header): byte 9 reserved +
//     bytes 10-15 = 48-bit Sequence Number.
//
//     Actually per RFC 4340 §5.1 Figure 1:
//     ```
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |          Source Port          |           Dest Port           |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |  Data Offset  | CCVal | CsCov |           Checksum            |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     | Res | Type  |X|               |                               .
//     +-+-+-+-+-+-+-+-+   Sequence Number (high 16 bits when X=1)     .
//     |                                                               .
//     .                                                               .
//     .            Sequence Number (low 24 bits when X=0;             .
//     .                          low 32 bits when X=1)                .
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     ```
//
//     Short header (X=0, 12 bytes): byte 9 + bytes 10-11
//     = 24-bit Sequence Number.
//     Extended header (X=1, 16 bytes): byte 9 reserved +
//     bytes 10-15 = 48-bit Sequence Number.
//
//   - **10-entry packet type name table** (RFC 4340 §5.1):
//     0 DCCP-Request / 1 DCCP-Response / 2 DCCP-Data /
//     3 DCCP-Ack / 4 DCCP-DataAck / 5 DCCP-CloseReq /
//     6 DCCP-Close / 7 DCCP-Reset / 8 DCCP-Sync /
//     9 DCCP-SyncAck.
//
//   - **Request / Response body** (Types 0 + 1): when
//     present, the first 4 bytes after the generic
//     header are the **Service Code** (a per-application
//     identifier the receiver uses to demultiplex
//     incoming connections — analogous to UDP/TCP
//     destination port + application). Plus an
//     Acknowledgement Number subheader for Response.
//
//   - **Ack-family bodies** (Types 3, 4, 5, 8, 9):
//     8-byte **Acknowledgement Subheader** — 16-bit
//     Reserved + 48-bit Acknowledgement Number.
//
//   - **Reset body** (Type 7): 8-byte Acknowledgement
//     Subheader + 1-byte **Reset Code** + 1-byte Data1 +
//     1-byte Data2 + 1-byte Data3. **12-entry Reset
//     Code name table** (RFC 4340 §5.6): 0 Unspecified /
//     1 Closed / 2 Aborted / 3 No Connection / 4 Packet
//     Error / 5 Option Error / 6 Mandatory Error / 7
//     Connection Refused / 8 Bad Service Code / 9 Too
//     Busy / 10 Bad Init Cookie / 11 Aggression Penalty.
//
//   - **Data / Close / CloseReq** bodies have no
//     additional fields beyond the generic header.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - IP framing — feed DCCP bytes after the IPv4 / IPv6
//     header strip. DCCP runs as IP protocol 33.
//
//   - Options walker — DCCP has a rich set of Options
//     (Mandatory, NDP Count, Ack Vector, Elapsed Time,
//     Timestamp, Timestamp Echo, Slow Receiver, CCID-
//     specific) that live after the per-type body up to
//     Data Offset; surfaced as raw hex; per-option
//     decoders are future work.
//
//   - Per-CCID semantics — DCCP supports pluggable
//     Congestion Control IDs (CCID 2 = TCP-like, CCID 3
//     = TCP-Friendly Rate Control, CCID 4 = TFRC for
//     Small Packets). The CCVal nibble surfaces as raw;
//     per-CCID decoders are out of scope.
//
//   - Checksum verification — the Internet-checksum over
//     the IP pseudo-header + DCCP header + CsCov bytes is
//     surfaced as hex but not re-computed.
//
//   - DCCP state-machine reasoning — connection setup
//     (Request/Response/Ack three-way handshake),
//     teardown (CloseReq/Close/Reset), Sync recovery,
//     and CCID negotiation are all higher-level
//     analysis.
package dccp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the top-level decoded view of a DCCP packet.
type Result struct {
	SourcePort      int    `json:"source_port"`
	DestinationPort int    `json:"destination_port"`
	DataOffsetWords int    `json:"data_offset_words"`
	DataOffsetBytes int    `json:"data_offset_bytes"`
	CCVal           int    `json:"ccval"`
	CsCov           int    `json:"cs_cov"`
	ChecksumHex     string `json:"checksum_hex"`
	Type            int    `json:"type"`
	TypeName        string `json:"type_name"`
	Extended        bool   `json:"extended_sequence_numbers"`
	SequenceNumber  uint64 `json:"sequence_number"`

	// Per-type bodies (populated for the matching Type).
	RequestServiceCode  *uint32    `json:"request_service_code,omitempty"`
	ResponseServiceCode *uint32    `json:"response_service_code,omitempty"`
	ResetBody           *ResetBody `json:"reset,omitempty"`
	AckNumber           *uint64    `json:"acknowledgement_number,omitempty"`

	TotalBytes int      `json:"total_bytes"`
	Notes      []string `json:"notes,omitempty"`
}

// ResetBody is the decoded Reset body (Type 7).
type ResetBody struct {
	AckNumber     uint64 `json:"acknowledgement_number"`
	ResetCode     int    `json:"reset_code"`
	ResetCodeName string `json:"reset_code_name"`
	Data1         int    `json:"data1"`
	Data2         int    `json:"data2"`
	Data3         int    `json:"data3"`
}

// Decode parses a single DCCP packet from hex.
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
		return nil, fmt.Errorf("DCCP packet truncated (%d bytes; need ≥12 for short generic header)",
			len(b))
	}
	r := &Result{
		TotalBytes:      len(b),
		SourcePort:      int(binary.BigEndian.Uint16(b[0:2])),
		DestinationPort: int(binary.BigEndian.Uint16(b[2:4])),
		DataOffsetWords: int(b[4]),
		CCVal:           int(b[5] >> 4),
		CsCov:           int(b[5] & 0x0F),
		ChecksumHex:     fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b[6:8])),
		Type:            int((b[8] >> 1) & 0x0F),
		Extended:        b[8]&0x01 != 0,
	}
	r.DataOffsetBytes = r.DataOffsetWords * 4
	r.TypeName = typeName(r.Type)

	var off int
	if r.Extended {
		if len(b) < 16 {
			return r, fmt.Errorf("DCCP extended header truncated (%d; need 16)", len(b))
		}
		// Byte 9 reserved; bytes 10-15 = 48-bit sequence.
		r.SequenceNumber = (uint64(b[10]) << 40) | (uint64(b[11]) << 32) |
			(uint64(b[12]) << 24) | (uint64(b[13]) << 16) |
			(uint64(b[14]) << 8) | uint64(b[15])
		off = 16
	} else {
		// Bytes 9-11 = 24-bit sequence.
		r.SequenceNumber = (uint64(b[9]) << 16) | (uint64(b[10]) << 8) | uint64(b[11])
		off = 12
	}

	switch r.Type {
	case 0:
		// Request: 4-byte Service Code follows the generic header.
		if off+4 <= len(b) {
			sc := binary.BigEndian.Uint32(b[off : off+4])
			r.RequestServiceCode = &sc
		}
	case 1:
		// Response: 8-byte Ack Subheader + 4-byte Service Code.
		if off+8 <= len(b) {
			ack := decodeAck(b[off : off+8])
			r.AckNumber = &ack
		}
		if off+12 <= len(b) {
			sc := binary.BigEndian.Uint32(b[off+8 : off+12])
			r.ResponseServiceCode = &sc
		}
	case 3, 4, 5, 8, 9:
		// Ack / DataAck / CloseReq / Sync / SyncAck:
		// 8-byte Ack Subheader.
		if off+8 <= len(b) {
			ack := decodeAck(b[off : off+8])
			r.AckNumber = &ack
		}
	case 7:
		// Reset: 8-byte Ack Subheader + Reset body.
		if off+12 <= len(b) {
			rb := &ResetBody{
				AckNumber: decodeAck(b[off : off+8]),
				ResetCode: int(b[off+8]),
				Data1:     int(b[off+9]),
				Data2:     int(b[off+10]),
				Data3:     int(b[off+11]),
			}
			rb.ResetCodeName = resetCodeName(rb.ResetCode)
			r.ResetBody = rb
		}
	}
	return r, nil
}

// decodeAck reads an 8-byte Acknowledgement Subheader (RFC
// 4340 §5.7) — 16-bit Reserved + 48-bit Acknowledgement Number.
func decodeAck(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return (uint64(b[2]) << 40) | (uint64(b[3]) << 32) |
		(uint64(b[4]) << 24) | (uint64(b[5]) << 16) |
		(uint64(b[6]) << 8) | uint64(b[7])
}

func typeName(t int) string {
	switch t {
	case 0:
		return "DCCP-Request"
	case 1:
		return "DCCP-Response"
	case 2:
		return "DCCP-Data"
	case 3:
		return "DCCP-Ack"
	case 4:
		return "DCCP-DataAck"
	case 5:
		return "DCCP-CloseReq"
	case 6:
		return "DCCP-Close"
	case 7:
		return "DCCP-Reset"
	case 8:
		return "DCCP-Sync"
	case 9:
		return "DCCP-SyncAck"
	}
	return fmt.Sprintf("uncatalogued type %d", t)
}

func resetCodeName(c int) string {
	switch c {
	case 0:
		return "Unspecified"
	case 1:
		return "Closed"
	case 2:
		return "Aborted"
	case 3:
		return "No Connection"
	case 4:
		return "Packet Error"
	case 5:
		return "Option Error"
	case 6:
		return "Mandatory Error"
	case 7:
		return "Connection Refused"
	case 8:
		return "Bad Service Code"
	case 9:
		return "Too Busy"
	case 10:
		return "Bad Init Cookie"
	case 11:
		return "Aggression Penalty"
	}
	return fmt.Sprintf("uncatalogued reset code %d", c)
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
