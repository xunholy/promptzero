// SPDX-License-Identifier: AGPL-3.0-or-later

// Package stun decodes STUN packets per RFC 5389 / 8489 +
// TURN extensions per RFC 5766 / 8656. STUN (Session
// Traversal Utilities for NAT) is the NAT-discovery and
// candidate-exchange protocol behind WebRTC, every browser
// peer-to-peer connection, video conferencing systems
// (Zoom/Teams/Meet/Webex), VoIP softphones, and SIP
// User-Agent NAT traversal. TURN extends STUN with relay
// allocation for symmetric-NAT cases.
//
// # Wrap-vs-native judgement
//
// Native. STUN has a fixed 20-byte header (Message Type +
// Length + Magic Cookie 0x2112A442 + 12-byte Transaction
// ID) followed by a TLV list of attributes. The Magic
// Cookie is the unambiguous way to tell STUN from any
// other UDP payload on port 3478. The XOR-MAPPED-ADDRESS
// trick (and TURN's XOR-PEER-ADDRESS / XOR-RELAYED-ADDRESS)
// XOR the IP / port with the magic cookie + transaction ID
// to defeat NAT-rewriting middleware that helpfully
// scans for IPv4 addresses in payloads. Pasting a hex blob
// from Wireshark / tshark / a tcpdump-of-3478 capture is
// enough — no STUN server, no live network attach.
//
// # What this package covers
//
//   - **20-byte header**: Message Type broken out into 12-bit
//     method + 2-bit class per RFC 5389 §6 (the top 2 bits
//     of the type field must be 0; the remaining 14 bits
//     encode class C0+C1 interleaved with the 12-bit method
//     M0..M11). Length, Magic Cookie validation (must be
//     0x2112A442 — anything else is rejected as not-STUN),
//     12-byte Transaction ID.
//   - **Method + class dispatch**:
//   - Methods: Binding (0x001), Allocate (0x003, TURN),
//     Refresh (0x004, TURN), Send (0x006, TURN indication),
//     Data (0x007, TURN indication), CreatePermission
//     (0x008, TURN), ChannelBind (0x009, TURN).
//   - Classes: Request (0x00), Indication (0x01),
//     Success Response (0x02), Error Response (0x03).
//   - **Attribute TLV walker** with 4-byte boundary padding
//     (attributes are aligned to 4-byte boundaries; the
//     length field excludes padding).
//   - **~30-entry attribute name table** covering STUN
//     (RFC 5389 §15) + TURN (RFC 5766/8656 §14) attributes:
//     MAPPED-ADDRESS (0x0001), RESPONSE-ADDRESS (0x0002),
//     CHANGE-REQUEST (0x0003), SOURCE-ADDRESS (0x0004),
//     CHANGED-ADDRESS (0x0005), USERNAME (0x0006), PASSWORD
//     (0x0007), MESSAGE-INTEGRITY (0x0008), ERROR-CODE
//     (0x0009), UNKNOWN-ATTRIBUTES (0x000A), REFLECTED-FROM
//     (0x000B), CHANNEL-NUMBER (0x000C, TURN), LIFETIME
//     (0x000D, TURN), XOR-PEER-ADDRESS (0x0012, TURN), DATA
//     (0x0013, TURN), REALM (0x0014), NONCE (0x0015),
//     XOR-RELAYED-ADDRESS (0x0016, TURN), REQUESTED-
//     ADDRESS-FAMILY (0x0017, TURN), EVEN-PORT (0x0018,
//     TURN), REQUESTED-TRANSPORT (0x0019, TURN), DONT-
//     FRAGMENT (0x001A, TURN), XOR-MAPPED-ADDRESS (0x0020),
//     RESERVATION-TOKEN (0x0022, TURN), PRIORITY (0x0024,
//     ICE), USE-CANDIDATE (0x0025, ICE), PADDING (0x0026),
//     RESPONSE-PORT (0x0027), SOFTWARE (0x8022), ALTERNATE-
//     SERVER (0x8023), FINGERPRINT (0x8028), ICE-CONTROLLED
//     (0x8029), ICE-CONTROLLING (0x802A), RESPONSE-ORIGIN
//     (0x802B), OTHER-ADDRESS (0x802C).
//   - **XOR address un-masking**: XOR-MAPPED-ADDRESS,
//     XOR-PEER-ADDRESS, and XOR-RELAYED-ADDRESS values are
//     un-XOR'd with the magic cookie + transaction ID and
//     decoded as IPv4 or IPv6 + port.
//   - **ERROR-CODE decode**: class (1 byte: hundreds digit)
//   - number (1 byte: units digit) + reason string, with
//     a documented-codes lookup (300 Try Alternate / 400
//     Bad Request / 401 Unauthorized / 403 Forbidden / 420
//     Unknown Attribute / 437 Allocation Mismatch / 438
//     Stale Nonce / 440 Address Family not Supported / 441
//     Wrong Credentials / 442 Unsupported Transport / 486
//     Allocation Quota / 487 Role Conflict / 500 Server
//     Error / 508 Insufficient Capacity).
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - MESSAGE-INTEGRITY / FINGERPRINT validation — the
//     HMAC-SHA1 / CRC-32 values are surfaced as hex but
//     not validated (HMAC-SHA1 requires the shared key
//     from the auth flow; FINGERPRINT is straightforward
//     CRC-32 but deferred since it's rarely the point of
//     interest).
//   - TURN ChannelData messages — these are non-STUN
//     framed (4-byte header [channel#][length]); detection
//     by leading byte ≥ 0x40 is supported, but the payload
//     is surfaced as raw hex.
//   - Long-lived TURN session bookkeeping — this is a
//     packet decoder, not a session tracker.
package stun

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Packet is the decoded STUN packet view.
type Packet struct {
	HexInput         string       `json:"hex_input"`
	MessageType      int          `json:"message_type"`
	MessageTypeHex   string       `json:"message_type_hex"`
	MessageClass     int          `json:"message_class"`
	MessageClassName string       `json:"message_class_name"`
	Method           int          `json:"method"`
	MethodName       string       `json:"method_name"`
	Length           int          `json:"length"`
	MagicCookieHex   string       `json:"magic_cookie_hex"`
	TransactionIDHex string       `json:"transaction_id_hex"`
	Attributes       []*Attribute `json:"attributes,omitempty"`
}

// Attribute is one decoded STUN attribute.
type Attribute struct {
	Type    int    `json:"type"`
	TypeHex string `json:"type_hex"`
	Name    string `json:"name"`
	Length  int    `json:"length"`
	DataHex string `json:"data_hex,omitempty"`

	// Type-aware decoded value.
	String        string         `json:"string,omitempty"`
	XORAddress    *XORAddress    `json:"xor_address,omitempty"`
	MappedAddress *MappedAddress `json:"mapped_address,omitempty"`
	ErrorCode     *ErrorCode     `json:"error_code,omitempty"`
	UInt32        *uint32        `json:"uint32,omitempty"`
	UInt32Name    string         `json:"uint32_name,omitempty"`
}

// XORAddress is an XOR-MAPPED / XOR-PEER / XOR-RELAYED
// address — un-XOR'd against the magic cookie + transaction
// ID for the operator's convenience.
type XORAddress struct {
	Family int    `json:"family"`
	Port   int    `json:"port"`
	IP     string `json:"ip"`
}

// MappedAddress is a plain (non-XOR) MAPPED-ADDRESS value.
type MappedAddress struct {
	Family int    `json:"family"`
	Port   int    `json:"port"`
	IP     string `json:"ip"`
}

// ErrorCode is the ERROR-CODE attribute body.
type ErrorCode struct {
	Class  int    `json:"class"`
	Number int    `json:"number"`
	Code   int    `json:"code"`
	Name   string `json:"name,omitempty"`
	Reason string `json:"reason"`
}

// magicCookie is the fixed 32-bit value that distinguishes
// STUN from any other UDP payload.
const magicCookie uint32 = 0x2112A442

// Decode parses a hex-encoded STUN packet.
func Decode(hexBlob string) (*Packet, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a raw STUN packet.
func DecodeBytes(b []byte) (*Packet, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("stun: packet too short (%d bytes); header is 20 bytes", len(b))
	}
	// Top 2 bits of message type must be zero — that's how
	// STUN multiplexes against ChannelData on the same port.
	if b[0]&0xC0 != 0 {
		return nil, fmt.Errorf("stun: top 2 bits of message type non-zero (0x%02X); possible TURN ChannelData", b[0])
	}
	mt := int(binary.BigEndian.Uint16(b[0:2]))
	length := int(binary.BigEndian.Uint16(b[2:4]))
	cookie := binary.BigEndian.Uint32(b[4:8])
	if cookie != magicCookie {
		return nil, fmt.Errorf("stun: magic cookie 0x%08X != 0x2112A442; not a STUN packet", cookie)
	}
	if 20+length > len(b) {
		return nil, fmt.Errorf("stun: declared body length %d exceeds buffer (%d bytes)", length, len(b)-20)
	}
	txID := b[8:20]
	method, class := splitMessageType(mt)
	p := &Packet{
		HexInput:         strings.ToUpper(hex.EncodeToString(b[:20+length])),
		MessageType:      mt,
		MessageTypeHex:   fmt.Sprintf("0x%04X", mt),
		MessageClass:     class,
		MessageClassName: classNameLookup(class),
		Method:           method,
		MethodName:       methodNameLookup(method),
		Length:           length,
		MagicCookieHex:   fmt.Sprintf("0x%08X", cookie),
		TransactionIDHex: strings.ToUpper(hex.EncodeToString(txID)),
	}
	// Walk attributes.
	body := b[20 : 20+length]
	off := 0
	for off < len(body) {
		if off+4 > len(body) {
			return nil, fmt.Errorf("stun: attribute header truncated at offset %d", off)
		}
		attrType := int(binary.BigEndian.Uint16(body[off : off+2]))
		attrLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+attrLen > len(body) {
			return nil, fmt.Errorf("stun: attribute %d length %d exceeds remaining body", attrType, attrLen)
		}
		val := body[off : off+attrLen]
		a := decodeAttribute(attrType, val, txID)
		a.Length = attrLen
		p.Attributes = append(p.Attributes, a)
		// Round up to 4-byte boundary.
		off += attrLen
		if pad := attrLen % 4; pad != 0 {
			off += 4 - pad
		}
	}
	return p, nil
}

// splitMessageType extracts the 12-bit method and 2-bit
// class from the 14-bit STUN message type field per RFC 5389
// §6:
//
//	0                 1
//	2  3  4  5  6  7  8  9  0  1  2  3  4  5
//	M11 M10 M9 M8 M7 C1 M6 M5 M4 C0 M3 M2 M1 M0
func splitMessageType(mt int) (method, class int) {
	m0to3 := mt & 0x0F
	c0 := (mt >> 4) & 0x01
	m4to6 := (mt >> 5) & 0x07
	c1 := (mt >> 8) & 0x01
	m7to11 := (mt >> 9) & 0x1F
	method = m0to3 | (m4to6 << 4) | (m7to11 << 7)
	class = c0 | (c1 << 1)
	return method, class
}

func decodeAttribute(typ int, val, txID []byte) *Attribute {
	a := &Attribute{
		Type:    typ,
		TypeHex: fmt.Sprintf("0x%04X", typ),
		Name:    attributeName(typ),
		DataHex: strings.ToUpper(hex.EncodeToString(val)),
	}
	switch typ {
	case 0x0006, 0x0014, 0x0015, 0x8022: // USERNAME, REALM, NONCE, SOFTWARE
		a.String = string(val)
	case 0x0001, 0x0002, 0x0004, 0x0005, 0x000B, 0x8023, 0x802B, 0x802C:
		// MAPPED-ADDRESS / RESPONSE-ADDRESS / SOURCE / CHANGED /
		// REFLECTED-FROM / ALTERNATE-SERVER / RESPONSE-ORIGIN /
		// OTHER-ADDRESS — all plain (non-XOR) addresses.
		a.MappedAddress = decodeMappedAddress(val)
	case 0x0020, 0x0012, 0x0016:
		// XOR-MAPPED-ADDRESS / XOR-PEER-ADDRESS / XOR-RELAYED-ADDRESS
		a.XORAddress = decodeXORAddress(val, txID)
	case 0x0009:
		a.ErrorCode = decodeErrorCode(val)
	case 0x000D, 0x0024, 0x000C, 0x0019, 0x0017, 0x0027:
		// LIFETIME / PRIORITY / CHANNEL-NUMBER / REQUESTED-
		// TRANSPORT / REQUESTED-ADDRESS-FAMILY / RESPONSE-PORT
		if len(val) == 4 {
			v := binary.BigEndian.Uint32(val)
			a.UInt32 = &v
			a.UInt32Name = uint32AttrName(typ, v)
		} else if len(val) == 2 {
			v := uint32(binary.BigEndian.Uint16(val))
			a.UInt32 = &v
			a.UInt32Name = uint32AttrName(typ, v)
		}
	}
	return a
}

func decodeMappedAddress(b []byte) *MappedAddress {
	if len(b) < 4 {
		return nil
	}
	family := int(b[1])
	port := int(binary.BigEndian.Uint16(b[2:4]))
	switch family {
	case 1: // IPv4
		if len(b) < 8 {
			return nil
		}
		return &MappedAddress{Family: family, Port: port, IP: net.IP(b[4:8]).String()}
	case 2: // IPv6
		if len(b) < 20 {
			return nil
		}
		return &MappedAddress{Family: family, Port: port, IP: net.IP(b[4:20]).String()}
	}
	return &MappedAddress{Family: family, Port: port}
}

// decodeXORAddress un-XORs an XOR-MAPPED-ADDRESS family
// against the magic cookie + transaction ID per RFC 5389
// §15.2. The port is XOR'd with the most-significant 16
// bits of the magic cookie; the IPv4 address is XOR'd with
// the full magic cookie; the IPv6 address is XOR'd with the
// magic cookie + transaction ID.
func decodeXORAddress(b, txID []byte) *XORAddress {
	if len(b) < 4 {
		return nil
	}
	family := int(b[1])
	xorPort := binary.BigEndian.Uint16(b[2:4])
	cookie := uint32(magicCookie)
	port := int(xorPort ^ uint16(cookie>>16))
	a := &XORAddress{Family: family, Port: port}
	switch family {
	case 1:
		if len(b) < 8 {
			return a
		}
		cookieBytes := cookieToBytes()
		ipBytes := make([]byte, 4)
		for i := 0; i < 4; i++ {
			ipBytes[i] = b[4+i] ^ cookieBytes[i]
		}
		a.IP = net.IP(ipBytes).String()
	case 2:
		if len(b) < 20 || len(txID) < 12 {
			return a
		}
		cookieBytes := cookieToBytes()
		ipBytes := make([]byte, 16)
		for i := 0; i < 4; i++ {
			ipBytes[i] = b[4+i] ^ cookieBytes[i]
		}
		for i := 0; i < 12; i++ {
			ipBytes[4+i] = b[8+i] ^ txID[i]
		}
		a.IP = net.IP(ipBytes).String()
	}
	return a
}

// cookieToBytes returns the magic cookie as a 4-byte
// big-endian slice. Wrapping the constant in a function avoids
// Go's compile-time check that rejects `byte(magicCookie>>16)`
// (8466 doesn't fit in a byte as an untyped constant).
func cookieToBytes() []byte {
	c := uint32(magicCookie)
	return []byte{byte(c >> 24), byte(c >> 16), byte(c >> 8), byte(c)}
}

func decodeErrorCode(b []byte) *ErrorCode {
	if len(b) < 4 {
		return nil
	}
	// First 2 bytes reserved + class (3 bits) + number (8 bits)
	class := int(b[2] & 0x07)
	number := int(b[3])
	code := class*100 + number
	return &ErrorCode{
		Class:  class,
		Number: number,
		Code:   code,
		Name:   errorCodeName(code),
		Reason: string(b[4:]),
	}
}

func classNameLookup(c int) string {
	switch c {
	case 0:
		return "Request"
	case 1:
		return "Indication"
	case 2:
		return "Success Response"
	case 3:
		return "Error Response"
	}
	return ""
}

func methodNameLookup(m int) string {
	switch m {
	case 0x001:
		return "Binding"
	case 0x002:
		return "Shared Secret (RFC 3489, obsolete)"
	case 0x003:
		return "Allocate (TURN)"
	case 0x004:
		return "Refresh (TURN)"
	case 0x006:
		return "Send (TURN)"
	case 0x007:
		return "Data (TURN)"
	case 0x008:
		return "CreatePermission (TURN)"
	case 0x009:
		return "ChannelBind (TURN)"
	case 0x00A:
		return "Connect (TURN-TCP, RFC 6062)"
	case 0x00B:
		return "ConnectionBind (TURN-TCP)"
	case 0x00C:
		return "ConnectionAttempt (TURN-TCP indication)"
	}
	return fmt.Sprintf("Method 0x%03X", m)
}

func attributeName(t int) string {
	switch t {
	case 0x0001:
		return "MAPPED-ADDRESS"
	case 0x0002:
		return "RESPONSE-ADDRESS (RFC 3489, obsolete)"
	case 0x0003:
		return "CHANGE-REQUEST (RFC 3489)"
	case 0x0004:
		return "SOURCE-ADDRESS (RFC 3489, obsolete)"
	case 0x0005:
		return "CHANGED-ADDRESS (RFC 3489, obsolete)"
	case 0x0006:
		return "USERNAME"
	case 0x0007:
		return "PASSWORD (RFC 3489, deprecated)"
	case 0x0008:
		return "MESSAGE-INTEGRITY (HMAC-SHA1)"
	case 0x0009:
		return "ERROR-CODE"
	case 0x000A:
		return "UNKNOWN-ATTRIBUTES"
	case 0x000B:
		return "REFLECTED-FROM (RFC 3489, obsolete)"
	case 0x000C:
		return "CHANNEL-NUMBER (TURN)"
	case 0x000D:
		return "LIFETIME (TURN)"
	case 0x0012:
		return "XOR-PEER-ADDRESS (TURN)"
	case 0x0013:
		return "DATA (TURN)"
	case 0x0014:
		return "REALM"
	case 0x0015:
		return "NONCE"
	case 0x0016:
		return "XOR-RELAYED-ADDRESS (TURN)"
	case 0x0017:
		return "REQUESTED-ADDRESS-FAMILY (TURN)"
	case 0x0018:
		return "EVEN-PORT (TURN)"
	case 0x0019:
		return "REQUESTED-TRANSPORT (TURN)"
	case 0x001A:
		return "DONT-FRAGMENT (TURN)"
	case 0x001C:
		return "MESSAGE-INTEGRITY-SHA256 (RFC 8489)"
	case 0x001D:
		return "PASSWORD-ALGORITHM (RFC 8489)"
	case 0x001E:
		return "USERHASH (RFC 8489)"
	case 0x0020:
		return "XOR-MAPPED-ADDRESS"
	case 0x0022:
		return "RESERVATION-TOKEN (TURN)"
	case 0x0024:
		return "PRIORITY (ICE, RFC 8445)"
	case 0x0025:
		return "USE-CANDIDATE (ICE)"
	case 0x0026:
		return "PADDING"
	case 0x0027:
		return "RESPONSE-PORT"
	case 0x002A:
		return "CONNECTION-ID (TURN-TCP, RFC 6062)"
	case 0x8022:
		return "SOFTWARE"
	case 0x8023:
		return "ALTERNATE-SERVER"
	case 0x8025:
		return "TRANSACTION-TRANSMIT-COUNTER (RFC 7982)"
	case 0x8027:
		return "CACHE-TIMEOUT"
	case 0x8028:
		return "FINGERPRINT (CRC-32)"
	case 0x8029:
		return "ICE-CONTROLLED (ICE)"
	case 0x802A:
		return "ICE-CONTROLLING (ICE)"
	case 0x802B:
		return "RESPONSE-ORIGIN"
	case 0x802C:
		return "OTHER-ADDRESS"
	case 0x802D:
		return "ECN-CHECK (RFC 6679)"
	case 0x802E:
		return "THIRD-PARTY-AUTHORIZATION (RFC 7635)"
	case 0x8030:
		return "MOBILITY-TICKET (RFC 8016)"
	}
	return fmt.Sprintf("Unknown attribute 0x%04X", t)
}

func uint32AttrName(typ int, v uint32) string {
	switch typ {
	case 0x0019: // REQUESTED-TRANSPORT
		switch v >> 24 {
		case 17:
			return "UDP"
		case 6:
			return "TCP"
		}
	case 0x0017: // REQUESTED-ADDRESS-FAMILY
		switch (v >> 24) & 0xFF {
		case 1:
			return "IPv4"
		case 2:
			return "IPv6"
		}
	}
	return ""
}

func errorCodeName(c int) string {
	switch c {
	case 300:
		return "Try Alternate"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthenticated"
	case 403:
		return "Forbidden"
	case 405:
		return "Mobility Forbidden"
	case 420:
		return "Unknown Attribute"
	case 437:
		return "Allocation Mismatch (TURN)"
	case 438:
		return "Stale Nonce"
	case 440:
		return "Address Family not Supported (TURN)"
	case 441:
		return "Wrong Credentials (TURN)"
	case 442:
		return "Unsupported Transport Protocol (TURN)"
	case 443:
		return "Peer Address Family Mismatch (TURN)"
	case 486:
		return "Allocation Quota Reached (TURN)"
	case 487:
		return "Role Conflict (ICE)"
	case 500:
		return "Server Error"
	case 508:
		return "Insufficient Capacity (TURN)"
	}
	return fmt.Sprintf("Error %d", c)
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("stun: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("stun: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
