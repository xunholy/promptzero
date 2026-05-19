// Package lldp decodes Link Layer Discovery Protocol payloads
// per IEEE 802.1AB-2009.
//
// Wrap-vs-native judgement
//
//	Native. IEEE 802.1AB is fully public; LLDP wire format
//	is a tight 7-bit-type + 9-bit-length TLV walker over a
//	small (~10) documented type catalogue plus an
//	Organizationally Specific escape hatch keyed by OUI.
//	No crypto, no compression, no varints. Operators paste
//	the LLDP payload bytes (after the Ethernet header strip,
//	typically EtherType 0x88CC) from a `tcpdump -i ethX -X
//	ether proto 0x88CC` line, a Wireshark Follow-Frame
//	view, or any LLDP-emitting tool and get every documented
//	field plus per-TLV body decoding for the operationally-
//	useful types (Chassis ID / Port ID / TTL / System Name /
//	System Description / Capabilities / Management Address).
//
// What this package covers
//
//   - **TLV walker** — each TLV is 16 bits of header (7 bits
//     type + 9 bits length, big-endian) followed by `length`
//     bytes of body. The walker stops at End of LLDPDU
//     (type 0) or at the buffer end.
//
//   - **Mandatory TLVs** (must appear in this order at the
//     start of every LLDPDU per §8.1.1):
//
//   - Type 1 Chassis ID
//
//   - Type 2 Port ID
//
//   - Type 3 Time-To-Live (uint16 BE seconds)
//
//   - **Optional standardised TLVs**:
//
//   - Type 0 End of LLDPDU
//
//   - Type 4 Port Description (UTF-8)
//
//   - Type 5 System Name (UTF-8)
//
//   - Type 6 System Description (UTF-8)
//
//   - Type 7 System Capabilities (2 capability flags + 2
//     enabled flags, total 4 bytes — 11 documented
//     capability bits: Other / Repeater / MAC Bridge /
//     WLAN AP / Router / Telephone / DOCSIS Cable Device /
//     Station Only / C-VLAN Component / S-VLAN Component
//     / Two-port MAC Relay)
//
//   - Type 8 Management Address
//
//   - **Chassis ID subtypes** (RFC IANA): 1 Chassis component
//     / 2 Interface alias / 3 Port component / 4 MAC
//     address (6 bytes, formatted as XX:XX:XX:XX:XX:XX) /
//     5 Network address (1-byte AFI + addr) / 6 Interface
//     name / 7 Locally assigned.
//
//   - **Port ID subtypes**: 1 Interface alias / 2 Port
//     component / 3 MAC address / 4 Network address / 5
//     Interface name / 6 Agent circuit ID / 7 Locally
//     assigned.
//
//   - **Management Address** body: address string length +
//     address subtype (IANA Address Family Number) + address
//     bytes + interface numbering subtype (1 unknown / 2
//     ifIndex / 3 systemPortNumber) + interface number
//     (uint32 BE) + OID string length + OID bytes (BER-
//     encoded; surfaced as hex).
//
//   - **Organizationally Specific TLV** (type 127): 3-byte
//     OUI + 1-byte subtype + organisation-defined body.
//     Common OUIs surfaced with their canonical name:
//
//   - 00-12-0F: IEEE 802.3
//
//   - 00-80-C2: IEEE 802.1
//
//   - 00-12-BB: LLDP-MED (TIA TR-41)
//
//   - 00-13-1F: PROFIBUS (PROFINET)
//
//   - **Mandatory-TLV ordering check** — surfaces a note if
//     the first three TLVs are not Chassis ID + Port ID +
//     TTL in that order.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - Ethernet framing — feed the payload bytes after the
//     Ethernet header (dst MAC + src MAC + EtherType 0x88CC).
//
//   - LLDP-MED extension TLV-by-TLV decoding — the LLDP-MED
//     OUI (00-12-BB) subtypes are surfaced with raw body hex;
//     deep dissection of capabilities, network policy, location
//     identification, and inventory belongs in a sibling Spec.
//
//   - IEEE 802.1 / 802.3 OUI subtypes (VLAN ID / link
//     aggregation / max frame size / power-via-MDI) — also
//     surfaced as raw body hex; deep dissection deferred.
//
//   - CDP (Cisco Discovery Protocol, proprietary EtherType
//     0x2000) — a sibling Spec; LLDP is the open multi-vendor
//     standard.
package lldp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"
)

// Result is the top-level decoded view.
type Result struct {
	TLVs       []TLV    `json:"tlvs"`
	TLVCount   int      `json:"tlv_count"`
	TotalBytes int      `json:"total_bytes"`
	Summary    string   `json:"summary"`
	Notes      []string `json:"notes,omitempty"`
}

// TLV is one decoded LLDP TLV.
type TLV struct {
	Type     int    `json:"type"`
	TypeName string `json:"type_name"`
	Length   int    `json:"length"`
	BodyHex  string `json:"body_hex,omitempty"`

	ChassisID         *IDWithSubtype      `json:"chassis_id,omitempty"`
	PortID            *IDWithSubtype      `json:"port_id,omitempty"`
	TTLSeconds        *uint16             `json:"ttl_seconds,omitempty"`
	PortDescription   string              `json:"port_description,omitempty"`
	SystemName        string              `json:"system_name,omitempty"`
	SystemDescription string              `json:"system_description,omitempty"`
	Capabilities      *SystemCapabilities `json:"system_capabilities,omitempty"`
	ManagementAddress *ManagementAddress  `json:"management_address,omitempty"`
	OrgSpecific       *OrgSpecific        `json:"organizationally_specific,omitempty"`
}

// IDWithSubtype is the Chassis ID and Port ID body shape — a
// 1-byte subtype followed by the variable-length ID.
type IDWithSubtype struct {
	Subtype     int    `json:"subtype"`
	SubtypeName string `json:"subtype_name"`
	IDHex       string `json:"id_hex,omitempty"`
	IDText      string `json:"id_text,omitempty"`
	MAC         string `json:"mac,omitempty"`
	IPAddress   string `json:"ip_address,omitempty"`
}

// SystemCapabilities is the body of type 7.
type SystemCapabilities struct {
	CapabilityFlags string `json:"capability_flags_decoded"`
	EnabledFlags    string `json:"enabled_flags_decoded"`
	CapabilityRaw   uint16 `json:"capability_raw"`
	EnabledRaw      uint16 `json:"enabled_raw"`
}

// ManagementAddress is the body of type 8.
type ManagementAddress struct {
	AddressSubtype       int    `json:"address_subtype"`
	AddressSubtypeName   string `json:"address_subtype_name"`
	Address              string `json:"address"`
	InterfaceSubtype     int    `json:"interface_subtype"`
	InterfaceSubtypeName string `json:"interface_subtype_name"`
	InterfaceNumber      uint32 `json:"interface_number"`
	OIDHex               string `json:"oid_hex,omitempty"`
}

// OrgSpecific is the body of type 127.
type OrgSpecific struct {
	OUI     string `json:"oui"`
	OUIName string `json:"oui_name"`
	Subtype int    `json:"subtype"`
	BodyHex string `json:"body_hex,omitempty"`
}

// Decode parses an LLDP payload from hex.
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
	if len(b) < 2 {
		return nil, fmt.Errorf("buffer too short (%d bytes; need ≥2 for first TLV header)",
			len(b))
	}

	r := &Result{TotalBytes: len(b)}
	off := 0
	for off+2 <= len(b) {
		hdr := binary.BigEndian.Uint16(b[off : off+2])
		typ := int(hdr >> 9)
		length := int(hdr & 0x1FF)
		if off+2+length > len(b) {
			return nil, fmt.Errorf("TLV at offset %d type %d declares %d bytes; %d left",
				off, typ, length, len(b)-off-2)
		}
		body := b[off+2 : off+2+length]
		t := TLV{
			Type:     typ,
			TypeName: typeName(typ),
			Length:   length,
		}
		if length > 0 {
			t.BodyHex = strings.ToUpper(hex.EncodeToString(body))
		}
		decorate(&t, typ, body)
		r.TLVs = append(r.TLVs, t)

		off += 2 + length
		if typ == 0 {
			break // End of LLDPDU
		}
	}

	r.TLVCount = len(r.TLVs)
	names := make([]string, 0, len(r.TLVs))
	for _, t := range r.TLVs {
		names = append(names, t.TypeName)
	}
	r.Summary = strings.Join(names, " + ")

	// Mandatory-order check (RFC IEEE 802.1AB §8.1.1).
	if len(r.TLVs) >= 3 {
		if r.TLVs[0].Type != 1 || r.TLVs[1].Type != 2 || r.TLVs[2].Type != 3 {
			r.Notes = append(r.Notes,
				"non-conformant TLV ordering: first three TLVs should be Chassis ID, "+
					"Port ID, Time-To-Live per IEEE 802.1AB §8.1.1")
		}
	}
	return r, nil
}

func decorate(t *TLV, typ int, body []byte) {
	switch typ {
	case 1:
		t.ChassisID = decodeIDWithSubtype(body, chassisIDSubtypeName)
	case 2:
		t.PortID = decodeIDWithSubtype(body, portIDSubtypeName)
	case 3:
		if len(body) == 2 {
			v := binary.BigEndian.Uint16(body)
			t.TTLSeconds = &v
		}
	case 4:
		t.PortDescription = safeText(body)
	case 5:
		t.SystemName = safeText(body)
	case 6:
		t.SystemDescription = safeText(body)
	case 7:
		if len(body) == 4 {
			t.Capabilities = &SystemCapabilities{
				CapabilityRaw: binary.BigEndian.Uint16(body[0:2]),
				EnabledRaw:    binary.BigEndian.Uint16(body[2:4]),
			}
			t.Capabilities.CapabilityFlags =
				capabilityFlagsName(t.Capabilities.CapabilityRaw)
			t.Capabilities.EnabledFlags =
				capabilityFlagsName(t.Capabilities.EnabledRaw)
		}
	case 8:
		t.ManagementAddress = decodeManagementAddress(body)
	case 127:
		t.OrgSpecific = decodeOrgSpecific(body)
	}
}

func decodeIDWithSubtype(body []byte, subtypeNamer func(int) string) *IDWithSubtype {
	if len(body) < 1 {
		return nil
	}
	id := &IDWithSubtype{
		Subtype:     int(body[0]),
		SubtypeName: subtypeNamer(int(body[0])),
	}
	val := body[1:]
	id.IDHex = strings.ToUpper(hex.EncodeToString(val))
	// Dispatch by subtype name rather than raw number, since
	// chassis-ID subtype 5 (Network address) and port-ID
	// subtype 5 (Interface name) are different semantics.
	switch id.SubtypeName {
	case "MAC address":
		if len(val) == 6 {
			id.MAC = formatMAC(val)
		}
	case "Network address":
		if len(val) >= 1 {
			afi := int(val[0])
			addr := val[1:]
			id.IPAddress = formatNetworkAddress(afi, addr)
		}
	default:
		// All other documented subtypes (Interface alias / name
		// / Port component / Chassis component / Agent circuit
		// ID / Locally assigned) carry text.
		id.IDText = safeText(val)
	}
	return id
}

func decodeManagementAddress(body []byte) *ManagementAddress {
	if len(body) < 1 {
		return nil
	}
	addrStrLen := int(body[0])
	if 1+addrStrLen+5 > len(body) {
		return nil
	}
	addrSubtype := int(body[1])
	addr := body[2 : 1+addrStrLen]
	ifSubtype := int(body[1+addrStrLen])
	ifNumber := binary.BigEndian.Uint32(body[1+addrStrLen+1 : 1+addrStrLen+5])
	oidStrLen := 0
	if 1+addrStrLen+5 < len(body) {
		oidStrLen = int(body[1+addrStrLen+5])
	}
	m := &ManagementAddress{
		AddressSubtype:       addrSubtype,
		AddressSubtypeName:   ianaAFNName(addrSubtype),
		Address:              formatNetworkAddress(addrSubtype, addr),
		InterfaceSubtype:     ifSubtype,
		InterfaceSubtypeName: ifSubtypeName(ifSubtype),
		InterfaceNumber:      ifNumber,
	}
	if oidStrLen > 0 && 1+addrStrLen+5+1+oidStrLen <= len(body) {
		oid := body[1+addrStrLen+5+1 : 1+addrStrLen+5+1+oidStrLen]
		m.OIDHex = strings.ToUpper(hex.EncodeToString(oid))
	}
	return m
}

func decodeOrgSpecific(body []byte) *OrgSpecific {
	if len(body) < 4 {
		return nil
	}
	oui := body[:3]
	subtype := int(body[3])
	o := &OrgSpecific{
		OUI:     fmt.Sprintf("%02X-%02X-%02X", oui[0], oui[1], oui[2]),
		OUIName: ouiName(oui),
		Subtype: subtype,
	}
	if len(body) > 4 {
		o.BodyHex = strings.ToUpper(hex.EncodeToString(body[4:]))
	}
	return o
}

func typeName(t int) string {
	switch t {
	case 0:
		return "End of LLDPDU"
	case 1:
		return "Chassis ID"
	case 2:
		return "Port ID"
	case 3:
		return "Time-To-Live"
	case 4:
		return "Port Description"
	case 5:
		return "System Name"
	case 6:
		return "System Description"
	case 7:
		return "System Capabilities"
	case 8:
		return "Management Address"
	case 127:
		return "Organizationally Specific"
	}
	return fmt.Sprintf("Reserved type %d", t)
}

func chassisIDSubtypeName(s int) string {
	switch s {
	case 1:
		return "Chassis component"
	case 2:
		return "Interface alias"
	case 3:
		return "Port component"
	case 4:
		return "MAC address"
	case 5:
		return "Network address"
	case 6:
		return "Interface name"
	case 7:
		return "Locally assigned"
	}
	return fmt.Sprintf("subtype %d (reserved)", s)
}

func portIDSubtypeName(s int) string {
	switch s {
	case 1:
		return "Interface alias"
	case 2:
		return "Port component"
	case 3:
		return "MAC address"
	case 4:
		return "Network address"
	case 5:
		return "Interface name"
	case 6:
		return "Agent circuit ID"
	case 7:
		return "Locally assigned"
	}
	return fmt.Sprintf("subtype %d (reserved)", s)
}

func capabilityFlagsName(flags uint16) string {
	parts := []string{}
	if flags&0x0001 != 0 {
		parts = append(parts, "Other")
	}
	if flags&0x0002 != 0 {
		parts = append(parts, "Repeater")
	}
	if flags&0x0004 != 0 {
		parts = append(parts, "MAC Bridge")
	}
	if flags&0x0008 != 0 {
		parts = append(parts, "WLAN Access Point")
	}
	if flags&0x0010 != 0 {
		parts = append(parts, "Router")
	}
	if flags&0x0020 != 0 {
		parts = append(parts, "Telephone")
	}
	if flags&0x0040 != 0 {
		parts = append(parts, "DOCSIS Cable Device")
	}
	if flags&0x0080 != 0 {
		parts = append(parts, "Station Only")
	}
	if flags&0x0100 != 0 {
		parts = append(parts, "C-VLAN Component")
	}
	if flags&0x0200 != 0 {
		parts = append(parts, "S-VLAN Component")
	}
	if flags&0x0400 != 0 {
		parts = append(parts, "Two-port MAC Relay")
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, " | ")
}

func ianaAFNName(afi int) string {
	switch afi {
	case 1:
		return "IPv4"
	case 2:
		return "IPv6"
	case 6:
		return "MAC (802)"
	case 16:
		return "DNS name"
	}
	return fmt.Sprintf("AFI %d", afi)
}

func ifSubtypeName(s int) string {
	switch s {
	case 1:
		return "Unknown"
	case 2:
		return "ifIndex"
	case 3:
		return "systemPortNumber"
	}
	return fmt.Sprintf("subtype %d", s)
}

func ouiName(oui []byte) string {
	if len(oui) != 3 {
		return ""
	}
	key := (uint32(oui[0]) << 16) | (uint32(oui[1]) << 8) | uint32(oui[2])
	switch key {
	case 0x00120F:
		return "IEEE 802.3"
	case 0x0080C2:
		return "IEEE 802.1"
	case 0x0012BB:
		return "LLDP-MED (TIA TR-41)"
	case 0x00131F:
		return "PROFIBUS (PROFINET)"
	case 0x000142:
		return "Cisco Systems"
	}
	return "unknown OUI"
}

func formatMAC(b []byte) string {
	if len(b) != 6 {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		b[0], b[1], b[2], b[3], b[4], b[5])
}

func formatNetworkAddress(afi int, addr []byte) string {
	switch afi {
	case 1:
		if len(addr) == 4 {
			return net.IP(addr).String()
		}
	case 2:
		if len(addr) == 16 {
			return net.IP(addr).String()
		}
	case 6:
		if len(addr) == 6 {
			return formatMAC(addr)
		}
	}
	return strings.ToUpper(hex.EncodeToString(addr))
}

func safeText(b []byte) string {
	if !utf8.Valid(b) {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return strings.ToUpper(hex.EncodeToString(b))
		}
	}
	return string(b)
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
