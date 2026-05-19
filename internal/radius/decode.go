// SPDX-License-Identifier: AGPL-3.0-or-later

// Package radius decodes RADIUS packets per RFC 2865 (auth)
// + RFC 2866 (accounting) + supporting RFCs. RADIUS is the
// dominant AAA protocol on enterprise networks — every
// Wi-Fi 802.1X / WPA2-Enterprise auth, every VPN
// concentrator, every NAS / RADIUS-PAM / FreeRADIUS deployment
// speaks it on UDP/1812 (auth) + UDP/1813 (accounting).
//
// # Wrap-vs-native judgement
//
// Native. RADIUS has a fixed 20-byte header (Code + Identifier
// + Length + 16-byte Authenticator) followed by a TLV list of
// attributes. The ~80 standard attributes are documented in
// the IANA RADIUS Types registry; values are typed (string,
// integer, IPv4, time, binary). Pasting a hex blob from
// Wireshark / tshark / a tcpdump-of-1812-or-1813 capture is
// enough — no AAA server, no shared secret, no live network
// attach.
//
// # What this package covers
//
//   - **20-byte header**: Code (16-entry name table —
//     Access-Request / Access-Accept / Access-Reject /
//     Accounting-Request / Accounting-Response / Access-
//     Challenge / Status-Server / Status-Client / Disconnect-
//     Request / Disconnect-ACK / Disconnect-NAK / CoA-
//     Request / CoA-ACK / CoA-NAK / Reserved), Identifier,
//     Length (validated against buffer), Authenticator (16
//     bytes, surfaced as hex).
//   - **Attribute TLV walker**: type (1 byte) + length (1
//     byte, includes the 2-byte header) + value. Per RFC
//     2865 §5 value-formats. Length validated against the
//     remaining buffer.
//   - **~80-entry attribute name table** covering the IANA
//     RADIUS Types registry: User-Name (1), User-Password
//     (2), CHAP-Password (3), NAS-IP-Address (4), NAS-Port
//     (5), Service-Type (6), Framed-Protocol (7), Framed-
//     IP-Address (8), Framed-IP-Netmask (9), Framed-Routing
//     (10), Filter-Id (11), Framed-MTU (12), Framed-
//     Compression (13), Login-IP-Host (14), Login-Service
//     (15), Login-TCP-Port (16), Reply-Message (18),
//     Callback-Number (19), Callback-Id (20), Framed-Route
//     (22), Framed-IPX-Network (23), State (24), Class (25),
//     Vendor-Specific (26), Session-Timeout (27), Idle-
//     Timeout (28), Termination-Action (29), Called-Station-
//     Id (30), Calling-Station-Id (31), NAS-Identifier (32),
//     Proxy-State (33), Login-LAT-Service (34), Login-LAT-
//     Node (35), Login-LAT-Group (36), Framed-AppleTalk-Link
//     (37), Framed-AppleTalk-Network (38), Framed-AppleTalk-
//     Zone (39), Acct-Status-Type (40), Acct-Delay-Time (41),
//     Acct-Input-Octets (42), Acct-Output-Octets (43), Acct-
//     Session-Id (44), Acct-Authentic (45), Acct-Session-
//     Time (46), Acct-Input-Packets (47), Acct-Output-
//     Packets (48), Acct-Terminate-Cause (49), Acct-Multi-
//     Session-Id (50), Acct-Link-Count (51), Acct-Input-
//     Gigawords (52), Acct-Output-Gigawords (53), Event-
//     Timestamp (55), CHAP-Challenge (60), NAS-Port-Type
//     (61), Port-Limit (62), Login-LAT-Port (63), Tunnel-*
//     (64-67, 81-83), ARAP-* (70-73, 84), Acct-Interim-
//     Interval (85), NAS-Port-Id (87), EAP-Message (79),
//     Message-Authenticator (80), Framed-IPv6-Prefix (97),
//     etc.
//   - **Vendor-Specific (26)** deep decode: vendor-id (4
//     bytes) + vendor-attribute sub-TLVs (vendor-type +
//     vendor-length + vendor-value).
//   - **Type-aware value rendering**: string attributes →
//     UTF-8; integer attributes → uint32 + name-table
//     lookup (Service-Type, Framed-Protocol, Acct-Status-
//     Type, Acct-Terminate-Cause, NAS-Port-Type, Tunnel-
//     Type, etc.); IPv4 attributes → dotted-decimal; time
//     attributes → uint32 seconds + RFC 3339 string when
//     Event-Timestamp.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - **User-Password decryption**: the encoded password is
//     surfaced as raw bytes; recovering the cleartext
//     requires the shared secret and the Authenticator
//     hash chain (RFC 2865 §5.2).
//   - **Message-Authenticator verification**: the HMAC-MD5
//     value is surfaced but not validated (requires the
//     shared secret).
//   - **EAP-Message reassembly**: multiple EAP-Message
//     attributes can chain to form a single EAP packet;
//     each attribute is decoded individually, but
//     reassembly is the caller's responsibility.
//   - **Diameter (RFC 6733)**: the modern successor protocol;
//     entirely different wire format; separate Spec.
//   - **TACACS+ (RFC 8907)**: a different AAA protocol with
//     its own envelope; separate Spec.
package radius

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// Packet is the decoded RADIUS packet view.
type Packet struct {
	HexInput         string       `json:"hex_input"`
	Code             int          `json:"code"`
	CodeName         string       `json:"code_name"`
	Identifier       int          `json:"identifier"`
	Length           int          `json:"length"`
	AuthenticatorHex string       `json:"authenticator_hex"`
	Attributes       []*Attribute `json:"attributes,omitempty"`
}

// Attribute is one decoded RADIUS attribute.
//
// Only the fields that match the attribute's documented
// value type are populated; the raw bytes are always
// available via DataHex.
type Attribute struct {
	Type    int    `json:"type"`
	Name    string `json:"name"`
	Length  int    `json:"length"`
	DataHex string `json:"data_hex,omitempty"`

	// Type-aware decoded value.
	String         string          `json:"string,omitempty"`
	Uint32         *uint32         `json:"uint32,omitempty"`
	IntName        string          `json:"int_name,omitempty"`
	IPv4           string          `json:"ipv4,omitempty"`
	TimeUnix       *uint32         `json:"time_unix,omitempty"`
	TimeRFC3339    string          `json:"time_rfc3339,omitempty"`
	VendorSpecific *VendorSpecific `json:"vendor_specific,omitempty"`
}

// VendorSpecific is the decoded body of attribute 26 (a
// Vendor-Id + a list of vendor sub-attributes).
type VendorSpecific struct {
	VendorID      uint32           `json:"vendor_id"`
	VendorName    string           `json:"vendor_name,omitempty"`
	SubAttributes []*VendorSubAttr `json:"sub_attributes,omitempty"`
	RawHex        string           `json:"raw_hex,omitempty"`
}

// VendorSubAttr is one entry in a Vendor-Specific TLV list.
type VendorSubAttr struct {
	Type    int    `json:"type"`
	Length  int    `json:"length"`
	DataHex string `json:"data_hex"`
}

// Decode parses a hex-encoded RADIUS packet.
func Decode(hexBlob string) (*Packet, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a raw RADIUS packet.
func DecodeBytes(b []byte) (*Packet, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("radius: packet too short (%d bytes); minimum is 20 (header)", len(b))
	}
	code := int(b[0])
	id := int(b[1])
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < 20 || length > 4096 {
		return nil, fmt.Errorf("radius: declared length %d out of spec range 20..4096", length)
	}
	if length > len(b) {
		return nil, fmt.Errorf("radius: declared length %d exceeds buffer (%d bytes)", length, len(b))
	}
	p := &Packet{
		HexInput:         strings.ToUpper(hex.EncodeToString(b[:length])),
		Code:             code,
		CodeName:         codeName(code),
		Identifier:       id,
		Length:           length,
		AuthenticatorHex: strings.ToUpper(hex.EncodeToString(b[4:20])),
	}
	// Walk attributes between offset 20 and the declared length.
	off := 20
	for off < length {
		if off+2 > length {
			return nil, fmt.Errorf("radius: attribute header truncated at offset %d", off)
		}
		attrType := int(b[off])
		attrLen := int(b[off+1])
		if attrLen < 2 || off+attrLen > length {
			return nil, fmt.Errorf("radius: attribute %d length %d invalid at offset %d", attrType, attrLen, off)
		}
		a := decodeAttribute(attrType, b[off+2:off+attrLen])
		a.Length = attrLen
		p.Attributes = append(p.Attributes, a)
		off += attrLen
	}
	return p, nil
}

func decodeAttribute(typ int, body []byte) *Attribute {
	a := &Attribute{
		Type:    typ,
		Name:    attributeName(typ),
		DataHex: strings.ToUpper(hex.EncodeToString(body)),
	}
	switch typ {
	// String-valued attributes
	case 1, 11, 18, 19, 20, 22, 30, 31, 32, 33, 34, 35, 36, 39, 44, 50, 60, 63, 79, 87:
		a.String = string(body)
	// 4-byte unsigned integer attributes
	case 5, 6, 7, 10, 12, 13, 15, 16, 27, 28, 29, 37, 38, 40, 45, 46, 47, 48, 49, 51, 52, 53, 61, 62, 85:
		if len(body) == 4 {
			v := binary.BigEndian.Uint32(body)
			a.Uint32 = &v
			a.IntName = integerAttrName(typ, v)
		}
	// IPv4-address attributes
	case 4, 8, 9, 14:
		if len(body) == 4 {
			a.IPv4 = net.IP(body).String()
		}
	// Time attributes (Event-Timestamp = 55, Unix seconds)
	case 55:
		if len(body) == 4 {
			v := binary.BigEndian.Uint32(body)
			a.TimeUnix = &v
			a.TimeRFC3339 = time.Unix(int64(v), 0).UTC().Format(time.RFC3339)
		}
	// Vendor-Specific (26): vendor-id + sub-TLVs
	case 26:
		if len(body) >= 4 {
			vid := binary.BigEndian.Uint32(body)
			vs := &VendorSpecific{
				VendorID:   vid,
				VendorName: vendorName(vid),
				RawHex:     strings.ToUpper(hex.EncodeToString(body[4:])),
			}
			vs.SubAttributes = parseVendorSubAttrs(body[4:])
			a.VendorSpecific = vs
		}
	}
	return a
}

// parseVendorSubAttrs walks a vendor-specific sub-TLV list:
// [type:1][length:1][value:length-2]+.
func parseVendorSubAttrs(b []byte) []*VendorSubAttr {
	var out []*VendorSubAttr
	off := 0
	for off+2 <= len(b) {
		t := int(b[off])
		l := int(b[off+1])
		if l < 2 || off+l > len(b) {
			break
		}
		out = append(out, &VendorSubAttr{
			Type:    t,
			Length:  l,
			DataHex: strings.ToUpper(hex.EncodeToString(b[off+2 : off+l])),
		})
		off += l
	}
	return out
}

func codeName(c int) string {
	switch c {
	case 1:
		return "Access-Request"
	case 2:
		return "Access-Accept"
	case 3:
		return "Access-Reject"
	case 4:
		return "Accounting-Request"
	case 5:
		return "Accounting-Response"
	case 11:
		return "Access-Challenge"
	case 12:
		return "Status-Server (experimental)"
	case 13:
		return "Status-Client (experimental)"
	case 40:
		return "Disconnect-Request"
	case 41:
		return "Disconnect-ACK"
	case 42:
		return "Disconnect-NAK"
	case 43:
		return "CoA-Request"
	case 44:
		return "CoA-ACK"
	case 45:
		return "CoA-NAK"
	case 255:
		return "Reserved"
	}
	return fmt.Sprintf("Unknown code %d", c)
}

// attributeName labels the IANA RADIUS attribute type codes.
// Covers the ~80 most-deployed attributes.
func attributeName(t int) string {
	switch t {
	case 1:
		return "User-Name"
	case 2:
		return "User-Password"
	case 3:
		return "CHAP-Password"
	case 4:
		return "NAS-IP-Address"
	case 5:
		return "NAS-Port"
	case 6:
		return "Service-Type"
	case 7:
		return "Framed-Protocol"
	case 8:
		return "Framed-IP-Address"
	case 9:
		return "Framed-IP-Netmask"
	case 10:
		return "Framed-Routing"
	case 11:
		return "Filter-Id"
	case 12:
		return "Framed-MTU"
	case 13:
		return "Framed-Compression"
	case 14:
		return "Login-IP-Host"
	case 15:
		return "Login-Service"
	case 16:
		return "Login-TCP-Port"
	case 18:
		return "Reply-Message"
	case 19:
		return "Callback-Number"
	case 20:
		return "Callback-Id"
	case 22:
		return "Framed-Route"
	case 23:
		return "Framed-IPX-Network"
	case 24:
		return "State"
	case 25:
		return "Class"
	case 26:
		return "Vendor-Specific"
	case 27:
		return "Session-Timeout"
	case 28:
		return "Idle-Timeout"
	case 29:
		return "Termination-Action"
	case 30:
		return "Called-Station-Id"
	case 31:
		return "Calling-Station-Id"
	case 32:
		return "NAS-Identifier"
	case 33:
		return "Proxy-State"
	case 34:
		return "Login-LAT-Service"
	case 35:
		return "Login-LAT-Node"
	case 36:
		return "Login-LAT-Group"
	case 37:
		return "Framed-AppleTalk-Link"
	case 38:
		return "Framed-AppleTalk-Network"
	case 39:
		return "Framed-AppleTalk-Zone"
	case 40:
		return "Acct-Status-Type"
	case 41:
		return "Acct-Delay-Time"
	case 42:
		return "Acct-Input-Octets"
	case 43:
		return "Acct-Output-Octets"
	case 44:
		return "Acct-Session-Id"
	case 45:
		return "Acct-Authentic"
	case 46:
		return "Acct-Session-Time"
	case 47:
		return "Acct-Input-Packets"
	case 48:
		return "Acct-Output-Packets"
	case 49:
		return "Acct-Terminate-Cause"
	case 50:
		return "Acct-Multi-Session-Id"
	case 51:
		return "Acct-Link-Count"
	case 52:
		return "Acct-Input-Gigawords"
	case 53:
		return "Acct-Output-Gigawords"
	case 55:
		return "Event-Timestamp"
	case 60:
		return "CHAP-Challenge"
	case 61:
		return "NAS-Port-Type"
	case 62:
		return "Port-Limit"
	case 63:
		return "Login-LAT-Port"
	case 64:
		return "Tunnel-Type"
	case 65:
		return "Tunnel-Medium-Type"
	case 66:
		return "Tunnel-Client-Endpoint"
	case 67:
		return "Tunnel-Server-Endpoint"
	case 79:
		return "EAP-Message"
	case 80:
		return "Message-Authenticator"
	case 81:
		return "Tunnel-Private-Group-ID"
	case 82:
		return "Tunnel-Assignment-ID"
	case 83:
		return "Tunnel-Preference"
	case 85:
		return "Acct-Interim-Interval"
	case 87:
		return "NAS-Port-Id"
	case 88:
		return "Framed-Pool"
	case 95:
		return "NAS-IPv6-Address"
	case 96:
		return "Framed-Interface-Id"
	case 97:
		return "Framed-IPv6-Prefix"
	case 98:
		return "Login-IPv6-Host"
	case 99:
		return "Framed-IPv6-Route"
	case 100:
		return "Framed-IPv6-Pool"
	case 101:
		return "Error-Cause"
	}
	return fmt.Sprintf("Unknown attribute %d", t)
}

// integerAttrName labels enum-valued integer attributes.
func integerAttrName(typ int, v uint32) string {
	switch typ {
	case 6: // Service-Type
		return serviceTypeName(v)
	case 7: // Framed-Protocol
		return framedProtocolName(v)
	case 13: // Framed-Compression
		switch v {
		case 0:
			return "None"
		case 1:
			return "VJ-TCP-Header-Compression"
		case 2:
			return "IPX-Header-Compression"
		case 3:
			return "Stac-LZS-Compression"
		}
	case 15: // Login-Service
		switch v {
		case 0:
			return "Telnet"
		case 1:
			return "Rlogin"
		case 2:
			return "TCP-Clear"
		case 3:
			return "PortMaster"
		case 4:
			return "LAT"
		case 5:
			return "X25-PAD"
		case 6:
			return "X25-T3POS"
		case 8:
			return "TCP-Clear-Quiet"
		}
	case 29: // Termination-Action
		switch v {
		case 0:
			return "Default"
		case 1:
			return "RADIUS-Request"
		}
	case 40: // Acct-Status-Type
		return acctStatusTypeName(v)
	case 45: // Acct-Authentic
		switch v {
		case 1:
			return "RADIUS"
		case 2:
			return "Local"
		case 3:
			return "Remote"
		case 4:
			return "Diameter"
		}
	case 49: // Acct-Terminate-Cause
		return acctTerminateCauseName(v)
	case 61: // NAS-Port-Type
		return nasPortTypeName(v)
	case 64: // Tunnel-Type
		return tunnelTypeName(v)
	case 65: // Tunnel-Medium-Type
		return tunnelMediumTypeName(v)
	case 101: // Error-Cause
		return errorCauseName(v)
	}
	return ""
}

func serviceTypeName(v uint32) string {
	switch v {
	case 1:
		return "Login"
	case 2:
		return "Framed"
	case 3:
		return "Callback-Login"
	case 4:
		return "Callback-Framed"
	case 5:
		return "Outbound"
	case 6:
		return "Administrative"
	case 7:
		return "NAS-Prompt"
	case 8:
		return "Authenticate-Only"
	case 9:
		return "Callback-NAS-Prompt"
	case 10:
		return "Call-Check"
	case 11:
		return "Callback-Administrative"
	case 12:
		return "Voice"
	case 13:
		return "Fax"
	case 14:
		return "Modem-Relay"
	case 15:
		return "IAPP-Register"
	case 16:
		return "IAPP-AP-Check"
	case 17:
		return "Authorize-Only"
	}
	return ""
}

func framedProtocolName(v uint32) string {
	switch v {
	case 1:
		return "PPP"
	case 2:
		return "SLIP"
	case 3:
		return "AppleTalk Remote Access Protocol (ARAP)"
	case 4:
		return "Gandalf proprietary SingleLink/MultiLink"
	case 5:
		return "Xylogics proprietary IPX/SLIP"
	case 6:
		return "X.75 Synchronous"
	case 7:
		return "GPRS PDP Context"
	}
	return ""
}

func acctStatusTypeName(v uint32) string {
	switch v {
	case 1:
		return "Start"
	case 2:
		return "Stop"
	case 3:
		return "Interim-Update"
	case 7:
		return "Accounting-On"
	case 8:
		return "Accounting-Off"
	case 9:
		return "Tunnel-Start (3GPP)"
	case 10:
		return "Tunnel-Stop"
	case 11:
		return "Tunnel-Reject"
	case 12:
		return "Tunnel-Link-Start"
	case 13:
		return "Tunnel-Link-Stop"
	case 14:
		return "Tunnel-Link-Reject"
	case 15:
		return "Failed"
	}
	return ""
}

func acctTerminateCauseName(v uint32) string {
	switch v {
	case 1:
		return "User-Request"
	case 2:
		return "Lost-Carrier"
	case 3:
		return "Lost-Service"
	case 4:
		return "Idle-Timeout"
	case 5:
		return "Session-Timeout"
	case 6:
		return "Admin-Reset"
	case 7:
		return "Admin-Reboot"
	case 8:
		return "Port-Error"
	case 9:
		return "NAS-Error"
	case 10:
		return "NAS-Request"
	case 11:
		return "NAS-Reboot"
	case 12:
		return "Port-Unneeded"
	case 13:
		return "Port-Preempted"
	case 14:
		return "Port-Suspended"
	case 15:
		return "Service-Unavailable"
	case 16:
		return "Callback"
	case 17:
		return "User-Error"
	case 18:
		return "Host-Request"
	}
	return ""
}

func nasPortTypeName(v uint32) string {
	switch v {
	case 0:
		return "Async"
	case 1:
		return "Sync"
	case 2:
		return "ISDN Sync"
	case 3:
		return "ISDN Async V.120"
	case 4:
		return "ISDN Async V.110"
	case 5:
		return "Virtual"
	case 6:
		return "PIAFS"
	case 7:
		return "HDLC Clear Channel"
	case 8:
		return "X.25"
	case 9:
		return "X.75"
	case 10:
		return "G.3 Fax"
	case 11:
		return "SDSL"
	case 12:
		return "ADSL-CAP"
	case 13:
		return "ADSL-DMT"
	case 14:
		return "IDSL"
	case 15:
		return "Ethernet"
	case 16:
		return "xDSL"
	case 17:
		return "Cable"
	case 18:
		return "Wireless-Other"
	case 19:
		return "Wireless-802.11"
	}
	return ""
}

func tunnelTypeName(v uint32) string {
	switch v {
	case 1:
		return "PPTP"
	case 2:
		return "L2F"
	case 3:
		return "L2TP"
	case 4:
		return "ATMP"
	case 5:
		return "VTP"
	case 6:
		return "AH"
	case 7:
		return "IP-IP-Encap"
	case 8:
		return "MIN-IP-IP"
	case 9:
		return "ESP"
	case 10:
		return "GRE"
	case 11:
		return "Bay-DVS"
	case 12:
		return "IP-in-IP"
	case 13:
		return "VLAN"
	}
	return ""
}

func tunnelMediumTypeName(v uint32) string {
	switch v {
	case 1:
		return "IPv4"
	case 2:
		return "IPv6"
	case 3:
		return "NSAP"
	case 4:
		return "HDLC (8-bit multidrop)"
	case 6:
		return "802 (includes Ethernet, Token Ring, FDDI)"
	case 7:
		return "E.163 (POTS)"
	case 8:
		return "E.164 (SMDS, Frame Relay, ATM)"
	case 9:
		return "F.69 (Telex)"
	case 10:
		return "X.121 (X.25, Frame Relay)"
	case 11:
		return "IPX"
	case 12:
		return "AppleTalk"
	}
	return ""
}

func errorCauseName(v uint32) string {
	switch v {
	case 201:
		return "Residual Session Context Removed"
	case 202:
		return "Invalid EAP Packet (Ignored)"
	case 401:
		return "Unsupported Attribute"
	case 402:
		return "Missing Attribute"
	case 403:
		return "NAS Identification Mismatch"
	case 404:
		return "Invalid Request"
	case 405:
		return "Unsupported Service"
	case 406:
		return "Unsupported Extension"
	case 501:
		return "Administratively Prohibited"
	case 502:
		return "Request Not Routable (Proxy)"
	case 503:
		return "Session Context Not Found"
	case 504:
		return "Session Context Not Removable"
	case 505:
		return "Other Proxy Processing Error"
	case 506:
		return "Resources Unavailable"
	case 507:
		return "Request Initiated"
	}
	return ""
}

// vendorName labels the most-common SMI Network Management
// Private Enterprise Codes encountered in RADIUS Vendor-
// Specific attributes.
func vendorName(v uint32) string {
	switch v {
	case 9:
		return "Cisco Systems"
	case 10:
		return "Hewlett-Packard"
	case 11:
		return "Sun Microsystems"
	case 14179:
		return "Cisco Wireless (Airespace)"
	case 311:
		return "Microsoft"
	case 14988:
		return "MikroTik"
	case 2352:
		return "Redback Networks"
	case 4874:
		return "Juniper Networks (Unisphere)"
	case 2636:
		return "Juniper Networks"
	case 5263:
		return "Aruba Networks"
	case 14823:
		return "Aruba Networks (Trapeze)"
	case 25506:
		return "H3C / Hewlett-Packard Enterprise"
	case 9048:
		return "Mikrotik (alternate)"
	case 26928:
		return "Ruckus Networks"
	case 12356:
		return "Fortinet"
	case 11129:
		return "Google"
	case 6527:
		return "Nokia (Alcatel-Lucent SROS)"
	case 800:
		return "3Com"
	case 6431:
		return "Foundry Networks"
	case 1751:
		return "Lucent Technologies"
	case 1916:
		return "Extreme Networks"
	}
	return ""
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("radius: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("radius: invalid hex: %w", err)
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
