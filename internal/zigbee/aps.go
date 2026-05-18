package zigbee

// aps.go — Zigbee APS (Application Support sublayer) frame
// dissector. APS sits on top of the NWK layer in the Zigbee
// stack: MAC (IEEE 802.15.4) → NWK → APS → ZCL.
//
// Wrap-vs-native judgement: same as the rest of the Zigbee
// stack — public spec (Zigbee Pro 2015 R21+), bit-level
// walker, pure offline decode. Operators chain
// ieee802154_decode → zigbee_nwk_decode → zigbee_aps_decode
// for full Zigbee frame analysis.

import (
	"encoding/binary"
	"fmt"
)

// APSFrameType is the 2-bit frame type field.
type APSFrameType int

const (
	APSFrameTypeData        APSFrameType = 0
	APSFrameTypeCommand     APSFrameType = 1
	APSFrameTypeAcknowledge APSFrameType = 2
	APSFrameTypeInterPAN    APSFrameType = 3
)

func (t APSFrameType) String() string {
	switch t {
	case APSFrameTypeData:
		return "Data"
	case APSFrameTypeCommand:
		return "APS Command"
	case APSFrameTypeAcknowledge:
		return "Acknowledge"
	case APSFrameTypeInterPAN:
		return "Inter-PAN APS"
	}
	return "Unknown"
}

// DeliveryMode is the 2-bit delivery-mode field.
type DeliveryMode int

const (
	DeliveryModeUnicast   DeliveryMode = 0
	DeliveryModeIndirect  DeliveryMode = 1
	DeliveryModeBroadcast DeliveryMode = 2
	DeliveryModeGroup     DeliveryMode = 3
)

func (d DeliveryMode) String() string {
	switch d {
	case DeliveryModeUnicast:
		return "Unicast"
	case DeliveryModeIndirect:
		return "Indirect (deprecated)"
	case DeliveryModeBroadcast:
		return "Broadcast"
	case DeliveryModeGroup:
		return "Group"
	}
	return "Reserved"
}

// APSFrameControl is the decoded 8-bit APS Frame Control byte.
type APSFrameControl struct {
	Raw int `json:"raw"`
	// FrameType (bits 1..0).
	FrameType     int    `json:"frame_type"`
	FrameTypeName string `json:"frame_type_name"`
	// DeliveryMode (bits 3..2).
	DeliveryMode     int    `json:"delivery_mode"`
	DeliveryModeName string `json:"delivery_mode_name"`
	// AckFormat (bit 4) — only meaningful for Acknowledge frames
	// (0 = APS data ACK, 1 = APS command ACK).
	AckFormat bool `json:"ack_format"`
	// Security (bit 5) — APS auxiliary security header present.
	Security bool `json:"security"`
	// AckRequest (bit 6) — sender wants an APS-level ACK.
	AckRequest bool `json:"ack_request"`
	// ExtendedHeader (bit 7) — APS extended header present.
	ExtendedHeader bool `json:"extended_header_present"`
}

// APSFrame is the top-level decoded APS frame.
type APSFrame struct {
	FrameControl APSFrameControl `json:"frame_control"`
	// DestinationEndpoint is the 1-byte destination endpoint
	// (Data / Ack frames only; absent for Group delivery mode
	// where the group address replaces it).
	DestinationEndpoint *int `json:"destination_endpoint,omitempty"`
	// GroupAddress is the 2-byte group address (present only
	// when DeliveryMode = Group on Data/Ack frames).
	GroupAddress    string `json:"group_address,omitempty"`
	GroupAddressRaw int    `json:"group_address_raw,omitempty"`
	// ClusterID is the 2-byte cluster identifier (Data/Ack only).
	ClusterID    string `json:"cluster_id,omitempty"`
	ClusterIDRaw int    `json:"cluster_id_raw,omitempty"`
	// ProfileID is the 2-byte profile identifier (Data/Ack only).
	ProfileID    string `json:"profile_id,omitempty"`
	ProfileIDRaw int    `json:"profile_id_raw,omitempty"`
	// SourceEndpoint is the 1-byte source endpoint (Data/Ack
	// only).
	SourceEndpoint *int `json:"source_endpoint,omitempty"`
	// APSCounter is the 1-byte APS sequence counter.
	APSCounter int `json:"aps_counter"`
	// ExtendedHeaderHex is the raw extended header bytes when
	// the flag is set. Walking it (fragmentation control / block
	// number / ack bitfield) is deferred to a follow-on Spec.
	ExtendedHeaderHex string `json:"extended_header_hex,omitempty"`
	// AuxSecurityHeaderHex is the raw APS aux security header
	// when the Security flag is set. Same shape as the NWK
	// security header (1-byte security control + 4-byte frame
	// counter + optional 8-byte source IEEE + optional 1-byte
	// key sequence number).
	AuxSecurityHeaderHex string `json:"aux_security_header_hex,omitempty"`
	// PayloadHex is the APS payload after all headers.
	PayloadHex string `json:"payload_hex,omitempty"`
	// ProfileName is the recognised Zigbee profile (HA, ZLL,
	// SE, ZDP, Green Power, etc.) when ProfileID is in the
	// well-known set.
	ProfileName string `json:"profile_name,omitempty"`
}

// DecodeAPS parses a hex-encoded Zigbee APS frame. Tolerates
// ':' / '-' / '_' / whitespace separators.
func DecodeAPS(hexBlob string) (APSFrame, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return APSFrame{}, fmt.Errorf("zigbee: empty APS input")
	}
	b, err := hexDecode(cleaned)
	if err != nil {
		return APSFrame{}, fmt.Errorf("zigbee: invalid hex: %w", err)
	}
	return DecodeAPSBytes(b)
}

// DecodeAPSBytes is the byte-slice variant of DecodeAPS.
func DecodeAPSBytes(b []byte) (APSFrame, error) {
	if len(b) < 1 {
		return APSFrame{}, fmt.Errorf("zigbee: APS frame empty")
	}
	fc := decodeAPSFrameControl(b[0])
	out := APSFrame{FrameControl: fc}
	off := 1
	dm := DeliveryMode(fc.DeliveryMode)
	ft := APSFrameType(fc.FrameType)
	// Data + Ack frames carry addressing fields. Command and
	// Inter-PAN frames skip directly to the APS counter.
	hasAddressing := ft == APSFrameTypeData ||
		(ft == APSFrameTypeAcknowledge && !fc.AckFormat)
	if hasAddressing {
		if dm == DeliveryModeGroup {
			// Group address (2 bytes) replaces destination endpoint.
			if off+2 > len(b) {
				return out, fmt.Errorf("zigbee: APS group address truncated")
			}
			ga := binary.LittleEndian.Uint16(b[off : off+2])
			out.GroupAddress = fmt.Sprintf("%04X", ga)
			out.GroupAddressRaw = int(ga)
			off += 2
		} else {
			// Destination endpoint (1 byte).
			if off >= len(b) {
				return out, fmt.Errorf("zigbee: APS dest endpoint truncated")
			}
			de := int(b[off])
			out.DestinationEndpoint = &de
			off++
		}
		// Cluster ID (2 bytes)
		if off+2 > len(b) {
			return out, fmt.Errorf("zigbee: APS cluster ID truncated")
		}
		cid := binary.LittleEndian.Uint16(b[off : off+2])
		out.ClusterID = fmt.Sprintf("%04X", cid)
		out.ClusterIDRaw = int(cid)
		off += 2
		// Profile ID (2 bytes)
		if off+2 > len(b) {
			return out, fmt.Errorf("zigbee: APS profile ID truncated")
		}
		pid := binary.LittleEndian.Uint16(b[off : off+2])
		out.ProfileID = fmt.Sprintf("%04X", pid)
		out.ProfileIDRaw = int(pid)
		if name, ok := zigbeeProfiles[pid]; ok {
			out.ProfileName = name
		}
		off += 2
		// Source endpoint (1 byte)
		if off >= len(b) {
			return out, fmt.Errorf("zigbee: APS source endpoint truncated")
		}
		se := int(b[off])
		out.SourceEndpoint = &se
		off++
	}
	// APS counter (1 byte) — present on all APS frames.
	if off >= len(b) {
		return out, fmt.Errorf("zigbee: APS counter truncated")
	}
	out.APSCounter = int(b[off])
	off++
	// Optional extended header
	if fc.ExtendedHeader {
		// Extended header has variable length; the first byte
		// encodes the type. For the common Fragmentation
		// extended header: type=0x00, then block number (1
		// byte) and ack bitfield (1 byte, only on ACKs). We
		// surface the full 3 bytes when present.
		if off >= len(b) {
			return out, fmt.Errorf("zigbee: APS extended header truncated")
		}
		// Assume 3-byte extended header for fragmentation; this
		// covers most real-world cases. Operators with novel
		// extended-header types can read the raw bytes from the
		// hex field.
		extLen := 3
		if off+extLen > len(b) {
			extLen = len(b) - off
		}
		out.ExtendedHeaderHex = hexString(b[off : off+extLen])
		off += extLen
	}
	// Optional aux security header
	if fc.Security {
		if off >= len(b) {
			return out, fmt.Errorf("zigbee: APS aux security header missing")
		}
		secCtrl := b[off]
		secHdrLen := securityHeaderLen(secCtrl)
		if off+secHdrLen > len(b) {
			return out, fmt.Errorf("zigbee: APS aux security header truncated: want %d bytes, have %d",
				secHdrLen, len(b)-off)
		}
		out.AuxSecurityHeaderHex = hexString(b[off : off+secHdrLen])
		off += secHdrLen
	}
	// Remaining bytes = payload
	if off < len(b) {
		out.PayloadHex = hexString(b[off:])
	}
	return out, nil
}

// decodeAPSFrameControl unpacks the 8-bit APS Frame Control byte.
func decodeAPSFrameControl(b byte) APSFrameControl {
	ft := int(b & 0x03)
	dm := int((b >> 2) & 0x03)
	return APSFrameControl{
		Raw:              int(b),
		FrameType:        ft,
		FrameTypeName:    APSFrameType(ft).String(),
		DeliveryMode:     dm,
		DeliveryModeName: DeliveryMode(dm).String(),
		AckFormat:        b&0x10 != 0,
		Security:         b&0x20 != 0,
		AckRequest:       b&0x40 != 0,
		ExtendedHeader:   b&0x80 != 0,
	}
}

// zigbeeProfiles maps the well-known Zigbee Application Profile
// IDs to their canonical names. Source: Zigbee Alliance Profile
// Identifiers document.
var zigbeeProfiles = map[uint16]string{
	0x0000: "Zigbee Device Profile (ZDP)",
	0x0101: "Industrial Plant Monitoring (IPM)",
	0x0104: "Home Automation (HA)",
	0x0105: "Commercial Building Automation (CBA)",
	0x0107: "Telecom Applications (TA)",
	0x0108: "Personal Home + Hospital Care (PHHC)",
	0x0109: "Advanced Metering Initiative (AMI)",
	0x010A: "Smart Energy (SE)",
	0x010B: "Health Care",
	0x010C: "Retail Services",
	0x0260: "Light Link (ZLL)",
	0xA1E0: "Smart Energy Plus",
	0xC05E: "Light Link (legacy)",
	0x7F01: "Test Profile #1",
	0xA10E: "Green Power Profile",
}

// hexDecode is a small wrapper around encoding/hex's DecodeString
// that returns nil on empty input rather than an empty []byte —
// keeps the call sites tidier.
func hexDecode(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty hex")
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex length %d", len(s))
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, ok := hexNibble(s[2*i])
		if !ok {
			return nil, fmt.Errorf("invalid hex digit at offset %d: %q", 2*i, s[2*i])
		}
		lo, ok := hexNibble(s[2*i+1])
		if !ok {
			return nil, fmt.Errorf("invalid hex digit at offset %d: %q", 2*i+1, s[2*i+1])
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

// hexNibble converts a single hex character to its 4-bit value.
func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
