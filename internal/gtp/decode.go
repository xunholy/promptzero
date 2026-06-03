// Package gtp decodes GPRS Tunneling Protocol User Plane
// (GTP-U) packets per 3GPP TS 29.281. The control plane
// (GTP-C, TS 29.274) and GTPv0/v1' (charging variant) are
// not decoded here; the user-plane is the high-volume case
// every cellular operator carries on its S1-U / N3 / N9
// interfaces.
//
// Wrap-vs-native judgement
//
//	Native. 3GPP TS 29.281 is fully public; the GTP-U
//	wire format is a tight 8-byte mandatory header with
//	flag-gated optional fields plus a typed extension header
//	chain. No crypto, no compression, no varints. Operators
//	paste UDP-payload bytes (standard UDP dest port 2152)
//	from a Wireshark Follow-UDP-Stream view, a `tcpdump -X
//	udp port 2152` line, an Open5GS / free5GC / Magma debug
//	capture, or any GTP-U-emitting tool and get the
//	documented header + extension chain + inner protocol
//	identification.
//
// What this package covers
//
//   - **8-byte mandatory header** (TS 29.281 §5.1):
//
//   - byte 0: Flags — Version (3 bits, GTP-U is version 1)
//
//   - Protocol Type (1 bit, 1 = GTP, 0 = GTP') + Spare
//     (1 bit) + E (1 bit, Extension Header present) + S
//     (1 bit, Sequence Number present) + PN (1 bit,
//     N-PDU Number present).
//
//   - byte 1: **Message Type** with **6-entry name table**:
//
//   - 0x01 Echo Request
//
//   - 0x02 Echo Response
//
//   - 0x1A Error Indication
//
//   - 0x1F Supported Extension Headers Notification
//
//   - 0xFE End Marker
//
//   - 0xFF G-PDU (user-plane data)
//
//   - bytes 2-3: Length (uint16 BE) — length of the
//     payload (i.e. everything after the 8-byte mandatory
//     header).
//
//   - bytes 4-7: TEID (uint32 BE) — Tunnel Endpoint
//     Identifier (the per-bearer / per-session demux ID
//     allocated by the receiver).
//
//   - **Optional 4-byte block** (present iff E|S|PN flag is
//     set):
//
//   - Sequence Number (uint16 BE)
//
//   - N-PDU Number (uint8)
//
//   - Next Extension Header Type (uint8)
//
//   - **Extension header chain** (when E flag set and Next
//     Extension Header Type != 0):
//
//   - byte 0: Extension Length (in 4-byte units, including
//     this byte and the trailing Next Extension Header
//     Type byte). Length 0 ends the chain.
//
//   - bytes 1..N: Extension content.
//
//   - last byte: Next Extension Header Type (0 = no more,
//     or one of the documented types below).
//
//   - **Extension Header Type name table** (TS 29.281 §5.2.1
//     — 8 entries): 0x00 No more / 0x01 MBMS support
//     indication / 0x02 MS Info Change Reporting / 0x40
//     Service Class Indicator / 0x81 RAN Container / 0x82
//     Long PDCP PDU Number / 0x83 Xw RAN Container / 0x84
//     NR RAN Container (5G NG-U) / 0x85 PDU Session
//     Container (5G N3 / N9).
//
//   - **Inner payload heuristic** — for G-PDU (0xFF), the
//     payload is a user IP packet. First-nibble version
//     detection: 4 → IPv4, 6 → IPv6, 0 → control word /
//     unknown. For a G-PDU (0xFF) the subscriber's IP packet is
//     decoded in place via internal/ipdecode (the version nibble
//     is self-describing — GTP-U has no protocol-type field), so
//     the tunnelled flow's addresses / protocol / ports surface
//     directly. A payload that does not parse as IP is reported
//     with an error and left as hex — no confidently-wrong output.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - GTP-C (control plane, TS 29.274) — different message
//     catalogue (Create Session Request / Modify Bearer /
//     etc.); a future Spec.
//
//   - GTPv0 / GTPv1' (charging variant) — older / charging-
//     specific protocols.
//
//   - PDU Session Container deep dissection (5G N3 / N9
//     QFI + RQI bits) — the extension is recognised by name
//     and surfaced as raw hex.
//
//   - UDP / IP framing — feed the UDP payload bytes (after
//     the outer IP + UDP headers; standard UDP dest port
//     2152).
package gtp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ipdecode"
)

// Result is the top-level decoded view.
type Result struct {
	Version             int    `json:"version"`
	ProtocolType        int    `json:"protocol_type"`
	ProtocolTypeName    string `json:"protocol_type_name"`
	ExtensionHeaderFlag bool   `json:"extension_header_flag"`
	SequenceNumberFlag  bool   `json:"sequence_number_flag"`
	NPDUNumberFlag      bool   `json:"npdu_number_flag"`
	FlagsHex            string `json:"flags_hex"`
	MessageType         int    `json:"message_type"`
	MessageTypeHex      string `json:"message_type_hex"`
	MessageTypeName     string `json:"message_type_name"`
	LengthDeclared      int    `json:"length_declared"`
	TEID                uint32 `json:"teid"`
	TEIDHex             string `json:"teid_hex"`

	// Optional 4-byte block fields (only set when at least
	// one of E/S/PN is true).
	SequenceNumber        *uint16 `json:"sequence_number,omitempty"`
	NPDUNumber            *uint8  `json:"npdu_number,omitempty"`
	NextExtensionType     *uint8  `json:"next_extension_header_type,omitempty"`
	NextExtensionTypeName string  `json:"next_extension_header_type_name,omitempty"`

	ExtensionHeaders []ExtensionHeader `json:"extension_headers,omitempty"`

	HeaderBytes      int              `json:"header_bytes"`
	PayloadLength    int              `json:"payload_length"`
	PayloadGuess     string           `json:"payload_guess,omitempty"`
	PayloadHex       string           `json:"payload_hex,omitempty"`
	InnerPacket      *ipdecode.Packet `json:"inner_packet,omitempty"`
	InnerDecodeError string           `json:"inner_decode_error,omitempty"`
	TotalBytes       int              `json:"total_bytes"`
	Notes            []string         `json:"notes,omitempty"`
}

// ExtensionHeader is one entry in the extension header chain.
type ExtensionHeader struct {
	Type        int    `json:"type"`
	TypeHex     string `json:"type_hex"`
	TypeName    string `json:"type_name"`
	LengthW     int    `json:"length_words"`
	LengthBytes int    `json:"length_bytes"`
	BodyHex     string `json:"body_hex,omitempty"`
	NextType    int    `json:"next_type"`
	NextTypeHex string `json:"next_type_hex"`
}

// Decode parses a GTP-U packet from hex.
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
	if len(b) < 8 {
		return nil, fmt.Errorf("GTP-U header truncated (%d bytes; need ≥8)", len(b))
	}

	flags := b[0]
	r := &Result{
		TotalBytes:          len(b),
		Version:             int(flags >> 5),
		ProtocolType:        int((flags >> 4) & 0x01),
		ExtensionHeaderFlag: flags&0x04 != 0,
		SequenceNumberFlag:  flags&0x02 != 0,
		NPDUNumberFlag:      flags&0x01 != 0,
		FlagsHex:            fmt.Sprintf("0x%02X", flags),
		MessageType:         int(b[1]),
		LengthDeclared:      int(binary.BigEndian.Uint16(b[2:4])),
		TEID:                binary.BigEndian.Uint32(b[4:8]),
	}
	r.MessageTypeHex = fmt.Sprintf("0x%02X", r.MessageType)
	r.MessageTypeName = messageTypeName(r.MessageType)
	r.TEIDHex = fmt.Sprintf("0x%08X", r.TEID)
	if r.ProtocolType == 1 {
		r.ProtocolTypeName = "GTP (TS 29.281)"
	} else {
		r.ProtocolTypeName = "GTP' (charging)"
	}

	if r.Version != 1 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"GTP version is %d; this decoder targets GTP-U (version 1, TS 29.281). "+
				"Version 0 is the legacy GTPv0 and version 2 is GTPv2-C / control plane.",
			r.Version))
	}

	off := 8
	hasOptional := r.ExtensionHeaderFlag || r.SequenceNumberFlag || r.NPDUNumberFlag
	if hasOptional {
		if off+4 > len(b) {
			return nil, fmt.Errorf("optional 4-byte block truncated")
		}
		seq := binary.BigEndian.Uint16(b[off : off+2])
		npn := b[off+2]
		initialNext := b[off+3]
		nextType := initialNext
		r.SequenceNumber = &seq
		r.NPDUNumber = &npn
		// Copy initialNext into a new heap value so the
		// pointer survives nextType mutation inside the
		// extension-header walker below.
		nextHeap := initialNext
		r.NextExtensionType = &nextHeap
		r.NextExtensionTypeName = extensionTypeName(int(initialNext))
		off += 4

		// Extension header chain.
		if r.ExtensionHeaderFlag {
			for nextType != 0 {
				if off+1 > len(b) {
					return nil, fmt.Errorf("extension header at offset %d truncated",
						off)
				}
				lengthW := int(b[off])
				if lengthW == 0 {
					return nil, fmt.Errorf("extension header at offset %d declares length 0 (invalid)",
						off)
				}
				totalBytes := lengthW * 4
				if off+totalBytes > len(b) {
					return nil, fmt.Errorf("extension header at offset %d declares %d bytes; %d left",
						off, totalBytes, len(b)-off)
				}
				body := b[off+1 : off+totalBytes-1]
				nt := b[off+totalBytes-1]
				eh := ExtensionHeader{
					Type:        int(nextType),
					TypeHex:     fmt.Sprintf("0x%02X", nextType),
					TypeName:    extensionTypeName(int(nextType)),
					LengthW:     lengthW,
					LengthBytes: totalBytes,
					NextType:    int(nt),
					NextTypeHex: fmt.Sprintf("0x%02X", nt),
				}
				if len(body) > 0 {
					eh.BodyHex = strings.ToUpper(hex.EncodeToString(body))
				}
				r.ExtensionHeaders = append(r.ExtensionHeaders, eh)
				nextType = nt
				off += totalBytes
			}
		}
	}

	r.HeaderBytes = off
	payload := b[off:]
	r.PayloadLength = len(payload)
	if len(payload) > 0 {
		if r.MessageType == 0xFF { // G-PDU — payload is the subscriber's IP packet
			r.PayloadGuess = guessInnerIP(payload)
			// Decode the tunnelled IP packet in place (its version nibble is
			// self-describing — no protocol-type field in GTP-U). A payload
			// that does not parse as IP is reported, not asserted.
			if pkt, err := ipdecode.DecodeBytes(payload); err == nil {
				r.InnerPacket = pkt
			} else {
				r.InnerDecodeError = err.Error()
			}
		}
		if len(payload) > 256 {
			r.PayloadHex = strings.ToUpper(hex.EncodeToString(payload[:256])) + "..."
		} else {
			r.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
		}
	}
	return r, nil
}

func messageTypeName(t int) string {
	switch t {
	case 0x01:
		return "Echo Request"
	case 0x02:
		return "Echo Response"
	case 0x1A:
		return "Error Indication"
	case 0x1F:
		return "Supported Extension Headers Notification"
	case 0xFE:
		return "End Marker"
	case 0xFF:
		return "G-PDU (user-plane data)"
	}
	return fmt.Sprintf("uncatalogued message type 0x%02X", t)
}

func extensionTypeName(t int) string {
	switch t {
	case 0x00:
		return "No more extension headers"
	case 0x01:
		return "MBMS support indication"
	case 0x02:
		return "MS Info Change Reporting"
	case 0x40:
		return "Service Class Indicator"
	case 0x81:
		return "RAN Container"
	case 0x82:
		return "Long PDCP PDU Number"
	case 0x83:
		return "Xw RAN Container"
	case 0x84:
		return "NR RAN Container (5G NG-U)"
	case 0x85:
		return "PDU Session Container (5G N3 / N9)"
	}
	return fmt.Sprintf("uncatalogued extension type 0x%02X", t)
}

func guessInnerIP(b []byte) string {
	if len(b) == 0 {
		return "empty payload"
	}
	switch b[0] >> 4 {
	case 4:
		return "IPv4 (first nibble 0x4)"
	case 6:
		return "IPv6 (first nibble 0x6)"
	case 0:
		return "padding / control word / unknown (first nibble 0x0)"
	}
	return fmt.Sprintf("unknown (first nibble 0x%X)", b[0]>>4)
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
