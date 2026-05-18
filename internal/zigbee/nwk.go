// Package zigbee decodes Zigbee Network Layer (NWK) frames —
// the layer that sits on top of IEEE 802.15.4 MAC frames in the
// Zigbee stack. Pure offline parser; no transport, no hardware.
//
// Wrap-vs-native judgement: Zigbee NWK is a public Zigbee
// Alliance specification (Zigbee Pro 2015 R21+). The walker is
// bit-level decoding over a documented Frame Control + address
// + optional fields layout. Wrapping a FAP for this would add
// an SD-card install step + a firmware-fork dependency for a
// pure parser. Native delivers offline analysis — operators
// decode the IEEE 802.15.4 MAC frame with ieee802154_decode,
// then dispatch the MAC payload here for NWK-layer fields.
//
// Pairs with the existing ieee802154_decode — chain the two for
// full Zigbee frame analysis.
//
// What this package covers:
//   - NWK Frame Control (16 bits): frame type (Data / NWK
//     Command / Reserved / Inter-PAN), protocol version (R22 =
//     0x2), discover route (0/1/2), multicast / security /
//     source route / destination IEEE / source IEEE flags
//   - 16-bit destination + source NWK addresses
//   - Radius (hop limit) + sequence number
//   - Optional 64-bit destination + source IEEE addresses (when
//     the corresponding presence flag is set)
//   - Multicast control byte (when multicast flag is set)
//   - Source route subframe (when source-route flag is set):
//     relay count + relay index + relay list
//   - Auxiliary Security Header (when security flag is set):
//     security control + frame counter + source address +
//     key sequence number — surfaced as hex; decryption needs
//     the network key out-of-band
//   - NWK payload — surfaced as hex; APS (Application Support
//     Sublayer) and ZCL (Zigbee Cluster Library) dissection is
//     deferred to follow-on Specs
//
// What this package does NOT cover (deliberately out of scope):
//   - NWK Command frame body decoding (Route Request / Response
//     / Leave / Rejoin / Link Status / Network Status / End
//     Device Timeout) — separate Spec when a caller materialises
//   - APS / ZDO / ZCL — higher-layer protocols
//   - Decryption (needs the network key)
//   - MIC validation (needs key + frame-counter context)
package zigbee

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// NWKFrameType is the 2-bit frame type field.
type NWKFrameType int

const (
	NWKFrameTypeData     NWKFrameType = 0
	NWKFrameTypeCommand  NWKFrameType = 1
	NWKFrameTypeReserved NWKFrameType = 2
	NWKFrameTypeInterPAN NWKFrameType = 3
)

func (t NWKFrameType) String() string {
	switch t {
	case NWKFrameTypeData:
		return "Data"
	case NWKFrameTypeCommand:
		return "NWK Command"
	case NWKFrameTypeInterPAN:
		return "Inter-PAN"
	}
	return "Reserved"
}

// DiscoverRoute is the 2-bit discover-route field.
type DiscoverRoute int

const (
	DiscoverRouteSuppress DiscoverRoute = 0
	DiscoverRouteEnable   DiscoverRoute = 1
	DiscoverRouteReserved DiscoverRoute = 2
)

func (d DiscoverRoute) String() string {
	switch d {
	case DiscoverRouteSuppress:
		return "Suppress"
	case DiscoverRouteEnable:
		return "Enable"
	}
	return "Reserved"
}

// FrameControl is the decoded 16-bit NWK Frame Control field.
type FrameControl struct {
	Raw int `json:"raw"`
	// Frame Type (bits 1..0).
	FrameType     int    `json:"frame_type"`
	FrameTypeName string `json:"frame_type_name"`
	// Protocol Version (bits 5..2) — Zigbee Pro R22 uses 2.
	ProtocolVersion int `json:"protocol_version"`
	// Discover Route (bits 7..6).
	DiscoverRoute     int    `json:"discover_route"`
	DiscoverRouteName string `json:"discover_route_name"`
	// Bit 8: Multicast (when set, multicast control byte follows
	// the addressing fields).
	Multicast bool `json:"multicast"`
	// Bit 9: Security (auxiliary security header present).
	Security bool `json:"security"`
	// Bit 10: Source Route (source route subframe present).
	SourceRoute bool `json:"source_route"`
	// Bit 11: Destination IEEE Address present (8 bytes after
	// source NWK address).
	DestinationIEEE bool `json:"destination_ieee_present"`
	// Bit 12: Source IEEE Address present.
	SourceIEEE bool `json:"source_ieee_present"`
}

// Frame is the top-level decoded NWK frame.
type Frame struct {
	FrameControl FrameControl `json:"frame_control"`
	// DestinationAddress is the 16-bit short address of the
	// destination node (or broadcast 0xFFFF / 0xFFFD / 0xFFFC /
	// 0xFFFB for documented broadcast classes).
	DestinationAddress    string `json:"destination_address"`
	DestinationAddressRaw int    `json:"destination_address_raw"`
	// SourceAddress is the 16-bit short address of the source.
	SourceAddress    string `json:"source_address"`
	SourceAddressRaw int    `json:"source_address_raw"`
	// Radius is the hop limit (decremented at each forwarding hop).
	Radius int `json:"radius"`
	// SequenceNumber is the NWK-layer sequence number.
	SequenceNumber int `json:"sequence_number"`
	// DestinationIEEEHex / SourceIEEEHex are populated when the
	// respective presence flag is set. Stored little-endian on
	// wire, rendered big-endian to match the form printed on
	// device labels.
	DestinationIEEEHex string `json:"destination_ieee,omitempty"`
	SourceIEEEHex      string `json:"source_ieee,omitempty"`
	// MulticastControl is populated when the multicast flag is
	// set. The byte encodes mode + non-member radius + max
	// non-member radius.
	MulticastControl *MulticastControl `json:"multicast_control,omitempty"`
	// SourceRouteHex is the raw source-route subframe when the
	// flag is set (relay count + relay index + relay list).
	SourceRouteHex string `json:"source_route_hex,omitempty"`
	// AuxSecurityHeaderHex is the raw security header when the
	// flag is set. Walking it (security level / key identifier /
	// frame counter) is deferred to a follow-on Spec.
	AuxSecurityHeaderHex string `json:"aux_security_header_hex,omitempty"`
	// PayloadHex is the NWK payload after all headers.
	PayloadHex string `json:"payload_hex,omitempty"`
	// BroadcastClass names the well-known broadcast destination
	// when applicable.
	BroadcastClass string `json:"broadcast_class,omitempty"`
}

// MulticastControl is the decoded multicast control byte
// (present when the Multicast flag is set in Frame Control).
//
//	bits 0..1: Multicast Mode (0 = non-member, 1 = member)
//	bits 2..4: Non-Member Radius (3 bits)
//	bits 5..7: Max Non-Member Radius (3 bits)
type MulticastControl struct {
	Raw                int    `json:"raw"`
	Mode               int    `json:"mode"`
	ModeName           string `json:"mode_name"`
	NonMemberRadius    int    `json:"non_member_radius"`
	MaxNonMemberRadius int    `json:"max_non_member_radius"`
}

// Decode parses a hex-encoded Zigbee NWK frame. Tolerates ':' /
// '-' / '_' / whitespace separators.
func Decode(hexBlob string) (Frame, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return Frame{}, fmt.Errorf("zigbee: empty NWK input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return Frame{}, fmt.Errorf("zigbee: invalid hex: %w", err)
	}
	return DecodeBytes(b)
}

// DecodeBytes is the byte-slice variant of Decode.
func DecodeBytes(b []byte) (Frame, error) {
	const minHeader = 8 // FC(2) + DstAddr(2) + SrcAddr(2) + Radius(1) + Seq(1)
	if len(b) < minHeader {
		return Frame{}, fmt.Errorf("zigbee: NWK frame %d bytes < %d-byte minimum",
			len(b), minHeader)
	}
	fc := decodeFrameControl(binary.LittleEndian.Uint16(b[0:2]))
	dst := binary.LittleEndian.Uint16(b[2:4])
	src := binary.LittleEndian.Uint16(b[4:6])
	radius := int(b[6])
	seq := int(b[7])
	out := Frame{
		FrameControl:          fc,
		DestinationAddress:    fmt.Sprintf("%04X", dst),
		DestinationAddressRaw: int(dst),
		SourceAddress:         fmt.Sprintf("%04X", src),
		SourceAddressRaw:      int(src),
		Radius:                radius,
		SequenceNumber:        seq,
		BroadcastClass:        broadcastClassName(dst),
	}
	off := 8
	// Optional destination IEEE address
	if fc.DestinationIEEE {
		if off+8 > len(b) {
			return out, fmt.Errorf("zigbee: dest IEEE flag set but only %d bytes remain", len(b)-off)
		}
		out.DestinationIEEEHex = hexString(reverseBytes(b[off : off+8]))
		off += 8
	}
	// Optional source IEEE address
	if fc.SourceIEEE {
		if off+8 > len(b) {
			return out, fmt.Errorf("zigbee: source IEEE flag set but only %d bytes remain", len(b)-off)
		}
		out.SourceIEEEHex = hexString(reverseBytes(b[off : off+8]))
		off += 8
	}
	// Optional multicast control byte
	if fc.Multicast {
		if off >= len(b) {
			return out, fmt.Errorf("zigbee: multicast flag set but no control byte present")
		}
		mc := decodeMulticastControl(b[off])
		out.MulticastControl = &mc
		off++
	}
	// Optional source route subframe (variable length, surfaced
	// as hex)
	if fc.SourceRoute {
		if off+2 > len(b) {
			return out, fmt.Errorf("zigbee: source route flag set but <2 bytes remain")
		}
		relayCount := int(b[off])
		// Relay count + relay index + (relayCount × 2 bytes for
		// each 16-bit relay address)
		srLen := 2 + relayCount*2
		if off+srLen > len(b) {
			return out, fmt.Errorf("zigbee: source route declares %d relays (%d bytes) but only %d remain",
				relayCount, srLen, len(b)-off)
		}
		out.SourceRouteHex = hexString(b[off : off+srLen])
		off += srLen
	}
	// Optional auxiliary security header. The walker doesn't
	// dissect it in detail (just the 1-byte security control to
	// size the header); the rest is surfaced as hex.
	if fc.Security {
		if off >= len(b) {
			return out, fmt.Errorf("zigbee: security flag set but no header bytes present")
		}
		secCtrl := b[off]
		secHdrLen := securityHeaderLen(secCtrl)
		if off+secHdrLen > len(b) {
			return out, fmt.Errorf("zigbee: security header length %d exceeds remaining %d",
				secHdrLen, len(b)-off)
		}
		out.AuxSecurityHeaderHex = hexString(b[off : off+secHdrLen])
		off += secHdrLen
	}
	if off < len(b) {
		out.PayloadHex = hexString(b[off:])
	}
	return out, nil
}

// decodeFrameControl unpacks the 16-bit NWK Frame Control field.
func decodeFrameControl(fc uint16) FrameControl {
	ft := int(fc & 0x03)
	dr := int((fc >> 6) & 0x03)
	return FrameControl{
		Raw:               int(fc),
		FrameType:         ft,
		FrameTypeName:     NWKFrameType(ft).String(),
		ProtocolVersion:   int((fc >> 2) & 0x0F),
		DiscoverRoute:     dr,
		DiscoverRouteName: DiscoverRoute(dr).String(),
		Multicast:         fc&0x0100 != 0,
		Security:          fc&0x0200 != 0,
		SourceRoute:       fc&0x0400 != 0,
		DestinationIEEE:   fc&0x0800 != 0,
		SourceIEEE:        fc&0x1000 != 0,
	}
}

// decodeMulticastControl unpacks the multicast control byte.
func decodeMulticastControl(b byte) MulticastControl {
	mode := int(b & 0x03)
	out := MulticastControl{
		Raw:                int(b),
		Mode:               mode,
		NonMemberRadius:    int((b >> 2) & 0x07),
		MaxNonMemberRadius: int((b >> 5) & 0x07),
	}
	switch mode {
	case 0:
		out.ModeName = "Non-member"
	case 1:
		out.ModeName = "Member"
	default:
		out.ModeName = "Reserved"
	}
	return out
}

// broadcastClassName maps the well-known Zigbee NWK broadcast
// destination addresses to their classes per Zigbee Pro §3.6.5.
func broadcastClassName(addr uint16) string {
	switch addr {
	case 0xFFFF:
		return "All nodes"
	case 0xFFFD:
		return "All non-sleepy nodes"
	case 0xFFFC:
		return "All routers + coordinator"
	case 0xFFFB:
		return "Low-power routers"
	}
	return ""
}

// securityHeaderLen returns the Zigbee NWK Auxiliary Security
// Header length based on the 1-byte Security Control field.
// Layout per Zigbee Pro §4.5.1:
//
//	bits 0..2: Security Level (we ignore — same length)
//	bits 3..4: Key Identifier (0 = data key, 1 = network key,
//	             2 = key-transport key, 3 = key-load key)
//	bit  5:   Extended Nonce flag (when set, source 64-bit IEEE
//	             present; 8 extra bytes)
//	bits 6..7: Reserved
//
// Header layout: SecCtrl(1) + Frame Counter(4) + optional
// Source Address(8) + Key Sequence Number(1 — when KeyID = 1
// for network key).
func securityHeaderLen(secCtrl byte) int {
	l := 1 + 4 // SecCtrl + Frame Counter
	if secCtrl&0x20 != 0 {
		// Extended Nonce — Source IEEE address (8 bytes) present
		l += 8
	}
	keyID := (secCtrl >> 3) & 0x03
	if keyID == 1 {
		// Network key — Key Sequence Number byte present
		l++
	}
	return l
}

// reverseBytes returns a fresh slice with bytes reversed (LE→BE).
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[len(b)-1-i] = c
	}
	return out
}

// hexString renders bytes as uppercase no-separator hex.
func hexString(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

// stripSeparators mirrors the convention across our pure-decoder
// packages.
func stripSeparators(s string) string {
	repl := strings.NewReplacer(
		" ", "",
		"\t", "",
		"\n", "",
		"\r", "",
		":", "",
		"-", "",
		"_", "",
	)
	return repl.Replace(strings.TrimSpace(s))
}
