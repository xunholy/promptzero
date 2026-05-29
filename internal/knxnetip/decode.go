// SPDX-License-Identifier: AGPL-3.0-or-later

// Package knxnetip decodes KNXnet/IP frames — the IP-transport
// dialect of KNX, the dominant European building-automation bus
// (lighting, HVAC, blinds/shutters, access control, energy
// metering, room controllers). KNXnet/IP tunnels or routes KNX
// telegrams over UDP/3671 (multicast 224.0.23.12 for routing),
// which is exactly the traffic a pentester captures on a building's
// management VLAN.
//
// # Wrap-vs-native judgement
//
// Native. KNXnet/IP is defined by the public KNX Standard (v2.1,
// chapters 3/8/x). Every frame is a fixed 6-byte header
// (header length, protocol version, 16-bit service type, 16-bit
// total length) followed by a service-specific body. Service-type
// dispatch is a lookup table; the connection-oriented bodies
// (CONNECT_REQUEST, TUNNELLING_REQUEST, ...) are fixed-format byte
// streams; and the carried cEMI telegram (the actual KNX bus
// command) is a documented TLV-ish layout. Pasting a hex blob from
// Wireshark / a UDP/3671 capture is enough — no ETS, no vendor SDK.
//
// # What this package covers
//
//   - KNXnet/IP header: header length (0x06), protocol version
//     (0x10 = v1.0), 16-bit service type identifier with a full
//     service catalog (Core / Device-Management / Tunnelling /
//     Routing / KNXnet-IP-Secure families), and total-length
//     validation against the actual buffer.
//   - HPAI (Host Protocol Address Information) blocks for the
//     discovery / connection services: host protocol code
//     (IPv4 UDP / IPv4 TCP), IPv4 endpoint, and port.
//   - Connection header (4 bytes) for the connection-oriented
//     services: communication channel ID + sequence counter +
//     status — the fields an attacker spoofs to hijack or reset
//     an established tunnel.
//   - cEMI telegram decode for TUNNELLING_REQUEST /
//     ROUTING_INDICATION: message code (L_Data.req / .ind / .con
//     and the M_Prop management codes), additional-info skip,
//     control fields, KNX source individual address
//     (area.line.device), destination group/individual address,
//     and the TPCI/APCI application command — most importantly
//     GroupValueRead / GroupValueResponse / GroupValueWrite plus
//     the (possibly 6-bit-packed) payload. A decoded
//     "GroupValueWrite 1/2/3 = 01" is "switch lighting group
//     1/2/3 on" in plain terms.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - KNXnet/IP Secure (service family 0x09xx): the SECURE_WRAPPER
//     and session services are named in the catalog but their
//     AES-CCM-encrypted payloads are not decrypted.
//   - cEMI additional-information field interpretation (it is
//     skipped by its length so the L_Data fields line up).
//   - Datapoint-type (DPT) interpretation of the GroupValue
//     payload: the raw value bytes are surfaced; mapping them to
//     an engineering value (e.g. DPT 9.001 temperature) needs the
//     project ETS group-address export and is a separate concern.
//   - The KNX TP1 / PL110 / RF physical-layer framings — only the
//     IP transport is in scope here.
package knxnetip

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Frame is the decoded view of a KNXnet/IP frame.
type Frame struct {
	HexInput   string      `json:"hex_input"`
	Header     *Header     `json:"header"`
	HPAIs      []*HPAI     `json:"hpai,omitempty"`
	ConnHeader *ConnHeader `json:"connection_header,omitempty"`
	CEMI       *CEMI       `json:"cemi,omitempty"`
	BodyHex    string      `json:"body_hex,omitempty"`
	Notes      []string    `json:"notes,omitempty"`
}

// Header is the fixed 6-byte KNXnet/IP header.
type Header struct {
	HeaderLength    int    `json:"header_length"`
	ProtocolVersion int    `json:"protocol_version"`
	ServiceType     int    `json:"service_type"`
	ServiceTypeName string `json:"service_type_name"`
	ServiceFamily   string `json:"service_family"`
	TotalLength     int    `json:"total_length"`
}

// HPAI is a Host Protocol Address Information block (8 bytes for
// IPv4): structure length, host protocol code, IPv4 address, port.
type HPAI struct {
	Role             string `json:"role,omitempty"`
	StructureLength  int    `json:"structure_length"`
	HostProtocol     int    `json:"host_protocol_code"`
	HostProtocolName string `json:"host_protocol_name"`
	Address          string `json:"address"`
	Port             int    `json:"port"`
}

// ConnHeader is the 4-byte connection header carried by the
// connection-oriented services (tunnelling, device management).
type ConnHeader struct {
	StructureLength  int `json:"structure_length"`
	ChannelID        int `json:"communication_channel_id"`
	SequenceCounter  int `json:"sequence_counter"`
	StatusOrReserved int `json:"status_or_reserved"`
}

// CEMI is a decoded cEMI (common External Message Interface)
// telegram — the actual KNX bus command carried over IP.
type CEMI struct {
	MessageCode     int    `json:"message_code"`
	MessageCodeName string `json:"message_code_name"`
	AddInfoLength   int    `json:"additional_info_length"`
	ControlField1   *int   `json:"control_field_1,omitempty"`
	ControlField2   *int   `json:"control_field_2,omitempty"`
	SourceAddress   string `json:"source_address,omitempty"`
	DestAddress     string `json:"destination_address,omitempty"`
	DestIsGroup     bool   `json:"destination_is_group_address,omitempty"`
	NPDULength      *int   `json:"npdu_length,omitempty"`
	APCI            *int   `json:"apci,omitempty"`
	APCIName        string `json:"apci_name,omitempty"`
	PayloadHex      string `json:"payload_hex,omitempty"`
}

// Decode parses a hex-encoded KNXnet/IP frame.
func Decode(hexBlob string) (*Frame, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a raw KNXnet/IP frame.
func DecodeBytes(b []byte) (*Frame, error) {
	if len(b) < 6 {
		return nil, fmt.Errorf("knxnetip: frame too short (%d bytes) — the header alone is 6 bytes", len(b))
	}
	hdr, err := decodeHeader(b)
	if err != nil {
		return nil, err
	}
	f := &Frame{
		HexInput: strings.ToUpper(hex.EncodeToString(b)),
		Header:   hdr,
	}

	body := b[hdr.HeaderLength:]
	switch hdr.ServiceType {
	case stSearchRequest, stDescriptionRequest, stConnectionStateRequest, stDisconnectRequest:
		// These lead with a single (control) HPAI.
		f.consumeHPAIs(body, "control")
	case stConnectRequest:
		// CONNECT_REQUEST: control HPAI + data HPAI + CRI.
		f.consumeHPAIs(body, "control", "data")
	case stConnectResponse:
		// channel id (1) + status (1) + data HPAI + CRD.
		if len(body) >= 2 {
			f.Notes = append(f.Notes,
				fmt.Sprintf("communication_channel_id=%d status=0x%02X", body[0], body[1]))
			f.consumeHPAIs(body[2:], "data")
		}
	case stTunnellingRequest, stDeviceConfigurationRequest:
		// 4-byte connection header, then a cEMI telegram.
		ch, rest, ok := decodeConnHeader(body)
		if ok {
			f.ConnHeader = ch
			if cemi := decodeCEMI(rest); cemi != nil {
				f.CEMI = cemi
			} else if len(rest) > 0 {
				f.BodyHex = strings.ToUpper(hex.EncodeToString(rest))
			}
		} else {
			f.BodyHex = strings.ToUpper(hex.EncodeToString(body))
		}
	case stTunnellingAck, stDeviceConfigurationAck:
		// 4-byte connection header only.
		if ch, _, ok := decodeConnHeader(body); ok {
			f.ConnHeader = ch
		}
	case stRoutingIndication:
		// cEMI telegram directly in the body.
		if cemi := decodeCEMI(body); cemi != nil {
			f.CEMI = cemi
		} else if len(body) > 0 {
			f.BodyHex = strings.ToUpper(hex.EncodeToString(body))
		}
	default:
		if len(body) > 0 {
			f.BodyHex = strings.ToUpper(hex.EncodeToString(body))
		}
	}

	if hdr.ServiceFamily == "KNXnet/IP Secure" {
		f.Notes = append(f.Notes,
			"KNXnet/IP Secure frame — encrypted payload not decoded (AES-CCM session)")
	}
	return f, nil
}

func decodeHeader(b []byte) (*Header, error) {
	hl := int(b[0])
	if hl < 6 || hl > len(b) {
		return nil, fmt.Errorf("knxnetip: header length byte = %d; want 6 within a %d-byte buffer", hl, len(b))
	}
	st := int(b[2])<<8 | int(b[3])
	total := int(b[4])<<8 | int(b[5])
	if total != len(b) {
		return nil, fmt.Errorf(
			"knxnetip: total-length field (%d) does not match buffer length (%d)", total, len(b))
	}
	// A protocol version other than 0x10 (v1.0) is surfaced rather
	// than rejected — minor variants exist and the rest of the frame
	// still decodes.
	return &Header{
		HeaderLength:    hl,
		ProtocolVersion: int(b[1]),
		ServiceType:     st,
		ServiceTypeName: serviceTypeName(st),
		ServiceFamily:   serviceFamily(st),
		TotalLength:     total,
	}, nil
}

// consumeHPAIs walks the leading roles' worth of HPAI blocks off the
// front of body. Each HPAI declares its own structure length, so a
// short/garbage block simply stops the walk.
func (f *Frame) consumeHPAIs(body []byte, roles ...string) {
	off := 0
	for _, role := range roles {
		h, used := decodeHPAI(body[off:])
		if h == nil {
			return
		}
		h.Role = role
		f.HPAIs = append(f.HPAIs, h)
		off += used
		if off >= len(body) {
			return
		}
	}
}

// decodeHPAI decodes one IPv4 HPAI (8 bytes) and returns it plus the
// number of bytes consumed, or (nil, 0) if the block is malformed.
func decodeHPAI(b []byte) (*HPAI, int) {
	if len(b) < 1 {
		return nil, 0
	}
	sl := int(b[0])
	// Standard IPv4 HPAI is exactly 8 bytes. Reject a length that
	// can't fit or that under-runs the 8-byte minimum.
	if sl < 8 || sl > len(b) {
		return nil, 0
	}
	addr := fmt.Sprintf("%d.%d.%d.%d", b[2], b[3], b[4], b[5])
	port := int(b[6])<<8 | int(b[7])
	return &HPAI{
		StructureLength:  sl,
		HostProtocol:     int(b[1]),
		HostProtocolName: hostProtocolName(int(b[1])),
		Address:          addr,
		Port:             port,
	}, sl
}

// decodeConnHeader decodes the 4-byte connection header and returns
// it, the remaining bytes after it, and whether decoding succeeded.
func decodeConnHeader(b []byte) (*ConnHeader, []byte, bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	sl := int(b[0])
	// The connection header structure length is fixed at 4; reject
	// anything that would over-run the buffer.
	if sl < 4 || sl > len(b) {
		return nil, nil, false
	}
	ch := &ConnHeader{
		StructureLength:  sl,
		ChannelID:        int(b[1]),
		SequenceCounter:  int(b[2]),
		StatusOrReserved: int(b[3]),
	}
	return ch, b[sl:], true
}

// decodeCEMI decodes a cEMI telegram. It returns nil when the buffer
// is too short to hold even a message code, so the caller can fall
// back to surfacing the raw body.
func decodeCEMI(b []byte) *CEMI {
	if len(b) < 2 {
		return nil
	}
	mc := int(b[0])
	c := &CEMI{
		MessageCode:     mc,
		MessageCodeName: cemiMessageCodeName(mc),
	}
	addInfoLen := int(b[1])
	c.AddInfoLength = addInfoLen
	// L_Data layout follows only for the L_Data message codes; other
	// codes (M_Prop*, etc.) carry a different body we don't dissect.
	if mc != cemiLDataReq && mc != cemiLDataInd && mc != cemiLDataCon {
		return c
	}
	// Skip the additional-info field: 2 (mc + ail) + addInfoLen.
	off := 2 + addInfoLen
	// Need ctrl1(1) ctrl2(1) src(2) dst(2) len(1) = 7 bytes.
	if off+7 > len(b) {
		return c
	}
	ctrl1 := int(b[off])
	ctrl2 := int(b[off+1])
	c.ControlField1 = &ctrl1
	c.ControlField2 = &ctrl2
	src := int(b[off+2])<<8 | int(b[off+3])
	dst := int(b[off+4])<<8 | int(b[off+5])
	c.SourceAddress = formatIndividualAddr(src)
	// Control field 2 bit 7 set => destination is a group address.
	c.DestIsGroup = ctrl2&0x80 != 0
	if c.DestIsGroup {
		c.DestAddress = formatGroupAddr(dst)
	} else {
		c.DestAddress = formatIndividualAddr(dst)
	}
	npduLen := int(b[off+6])
	c.NPDULength = &npduLen
	// TPCI/APCI occupy the two octets after the length byte. The
	// APCI is a 10-bit field: low 2 bits of the first octet + all 8
	// bits of the second.
	tpciOff := off + 7
	if tpciOff+1 >= len(b) {
		return c
	}
	apci := (int(b[tpciOff])&0x03)<<8 | int(b[tpciOff+1])
	c.APCI = &apci
	c.APCIName = apciName(apci)
	// Payload. For a 1-octet NPDU the 6-bit data is packed into the
	// low bits of the second APCI octet; for longer NPDUs the data
	// follows in subsequent octets.
	if npduLen <= 1 {
		c.PayloadHex = fmt.Sprintf("%02X", b[tpciOff+1]&0x3F)
	} else {
		dataStart := tpciOff + 2
		dataEnd := dataStart + (npduLen - 1)
		if dataEnd > len(b) {
			dataEnd = len(b)
		}
		if dataStart < dataEnd {
			c.PayloadHex = strings.ToUpper(hex.EncodeToString(b[dataStart:dataEnd]))
		}
	}
	return c
}

// formatIndividualAddr renders a 16-bit KNX individual (physical)
// address as area.line.device (4/4/8 bits).
func formatIndividualAddr(a int) string {
	return fmt.Sprintf("%d.%d.%d", (a>>12)&0x0F, (a>>8)&0x0F, a&0xFF)
}

// formatGroupAddr renders a 16-bit KNX group address in the common
// 3-level main/middle/sub notation (5/3/8 bits).
func formatGroupAddr(a int) string {
	return fmt.Sprintf("%d/%d/%d", (a>>11)&0x1F, (a>>8)&0x07, a&0xFF)
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("knxnetip: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("knxnetip: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
