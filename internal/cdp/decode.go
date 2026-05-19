// Package cdp decodes Cisco Discovery Protocol packets per
// the publicly-documented wire format (reverse-engineered and
// documented in Wireshark dissectors, tcpdump output, and the
// CDP protocol whitepapers Cisco has historically published).
//
// Wrap-vs-native judgement
//
//	Native. CDP is a proprietary Cisco protocol but the wire
//	format has been openly documented for decades — every
//	Wireshark dissector, every `tcpdump -X ether proto 0x2000`
//	parser, and every Linux `cdpr`/`cdptools` utility agrees
//	on the layout. Four bytes of fixed header (version + TTL
//	+ checksum) followed by a TLV walker over ~17 documented
//	TLV types. No crypto, no compression, no varints.
//	Operators paste CDP payload bytes (after the SNAP/LLC
//	header strip, EtherType 0x2000 with OUI 00-00-0C and
//	PID 0x2000) from a Wireshark Follow-Frame view, a
//	`tcpdump -i ethX -X ether proto 0x2000` line, or any
//	CDP-emitting tool and get every documented field.
//
// What this package covers
//
//   - **4-byte header**: Version (1 byte; usually 2) + TTL
//     (1 byte seconds, default 180) + Checksum (2 bytes BE).
//     Checksum verification is out of scope (requires the
//     standard one's-complement Internet checksum over the
//     whole CDPDU); the value is surfaced as hex.
//
//   - **TLV walker** — each TLV is Type (2 bytes BE) + Length
//     (2 bytes BE, includes the 4 header bytes) + Value
//     (Length-4 bytes). The walker iterates until the buffer
//     is consumed.
//
//   - **~17 documented TLV types** with per-type body decoding:
//
//   - 0x0001 Device ID (UTF-8 string)
//
//   - 0x0002 Addresses (list of protocol-typed addresses)
//
//   - 0x0003 Port ID (UTF-8 string)
//
//   - 0x0004 Capabilities (uint32 BE bitfield — 10
//     documented bits: Router / Transparent Bridge /
//     Source Route Bridge / Switch / Host / IGMP /
//     Repeater / VoIP Phone / Remotely Managed Device /
//     CVTA)
//
//   - 0x0005 Software Version (UTF-8 string — typically
//     multi-line Cisco IOS version banner)
//
//   - 0x0006 Platform (UTF-8 string — e.g. "cisco WS-C2960")
//
//   - 0x000A Native VLAN (uint16 BE)
//
//   - 0x000B Duplex (1 byte: 0 half-duplex / 1 full-duplex)
//
//   - 0x000E VoIP VLAN Reply
//
//   - 0x000F VoIP VLAN Query
//
//   - 0x0010 Power Consumption (uint16 BE milliwatts)
//
//   - 0x0011 MTU (uint32 BE bytes)
//
//   - 0x0012 Trust Bitmap (1 byte)
//
//   - 0x0013 Untrusted Port CoS (1 byte)
//
//   - 0x0014 System Name (UTF-8 string)
//
//   - 0x0015 System Object ID (ASN.1 OID bytes)
//
//   - 0x0016 Management Address (list, same shape as 0x0002)
//
//   - **Addresses TLV body** (used by both Addresses and
//     Management Address):
//
//   - Number of addresses (uint32 BE)
//
//   - For each: Protocol Type (1 byte, typically 1=NLPID) +
//     Protocol Length (1 byte) + Protocol bytes (e.g. 0xCC
//     for IPv4 NLPID) + Address Length (uint16 BE) +
//     Address bytes (4 for IPv4, 16 for IPv6).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - SNAP/LLC framing — feed the CDP payload bytes after the
//     802.2 LLC SNAP header (DSAP/SSAP 0xAA / Control 0x03 /
//     OUI 00-00-0C / PID 0x2000). The dissector starts at the
//     CDP version byte.
//
//   - Checksum verification — the value is surfaced as hex;
//     operators can compute the standard one's-complement
//     checksum over the whole CDPDU if they need to verify.
//
//   - CDP version 1 (deprecated; the protocol is essentially
//     a subset of v2). The walker handles v1 TLVs that
//     overlap; v1-only behaviours are not flagged.
//
//   - LLDP (the open IEEE 802.1AB-2009 equivalent) — handled
//     by `lldp_decode`. CDP and LLDP often coexist on the
//     same wire because Cisco switches typically run both.
package cdp

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
	Version     int    `json:"version"`
	TTLSeconds  int    `json:"ttl_seconds"`
	ChecksumHex string `json:"checksum_hex"`
	TotalBytes  int    `json:"total_bytes"`
	TLVs        []TLV  `json:"tlvs"`
	TLVCount    int    `json:"tlv_count"`
	Summary     string `json:"summary"`
}

// TLV is one decoded CDP TLV.
type TLV struct {
	Type     int    `json:"type"`
	TypeHex  string `json:"type_hex"`
	TypeName string `json:"type_name"`
	Length   int    `json:"length"`
	BodyHex  string `json:"body_hex,omitempty"`

	DeviceID            string        `json:"device_id,omitempty"`
	PortID              string        `json:"port_id,omitempty"`
	SoftwareVersion     string        `json:"software_version,omitempty"`
	Platform            string        `json:"platform,omitempty"`
	SystemName          string        `json:"system_name,omitempty"`
	SystemObjectID      string        `json:"system_object_id_hex,omitempty"`
	Capabilities        *Capabilities `json:"capabilities,omitempty"`
	Addresses           *AddressList  `json:"addresses,omitempty"`
	ManagementAddresses *AddressList  `json:"management_addresses,omitempty"`
	NativeVLAN          *uint16       `json:"native_vlan,omitempty"`
	Duplex              string        `json:"duplex,omitempty"`
	PowerMW             *uint16       `json:"power_consumption_mw,omitempty"`
	MTU                 *uint32       `json:"mtu_bytes,omitempty"`
	TrustBitmap         *uint8        `json:"trust_bitmap,omitempty"`
	UntrustedCoS        *uint8        `json:"untrusted_port_cos,omitempty"`
}

// Capabilities is the body of TLV 0x0004.
type Capabilities struct {
	Raw    uint32 `json:"raw"`
	RawHex string `json:"raw_hex"`
	Flags  string `json:"flags_decoded"`
}

// AddressList is the body of TLVs 0x0002 and 0x0016.
type AddressList struct {
	Count     int       `json:"count"`
	Addresses []Address `json:"entries,omitempty"`
}

// Address is one entry in an AddressList.
type Address struct {
	ProtocolType int    `json:"protocol_type"`
	ProtocolHex  string `json:"protocol_hex"`
	ProtocolName string `json:"protocol_name"`
	Address      string `json:"address"`
	AddressHex   string `json:"address_hex,omitempty"`
}

// Decode parses a CDP packet from hex.
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
	if len(b) < 4 {
		return nil, fmt.Errorf("CDP header truncated (%d bytes; need ≥4)", len(b))
	}

	r := &Result{
		Version:     int(b[0]),
		TTLSeconds:  int(b[1]),
		ChecksumHex: fmt.Sprintf("%04X", binary.BigEndian.Uint16(b[2:4])),
		TotalBytes:  len(b),
	}

	off := 4
	for off+4 <= len(b) {
		typ := int(binary.BigEndian.Uint16(b[off : off+2]))
		length := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if length < 4 {
			return nil, fmt.Errorf("TLV at offset %d declares length %d (must be ≥4 to include header)",
				off, length)
		}
		if off+length > len(b) {
			return nil, fmt.Errorf("TLV at offset %d type 0x%04X declares %d bytes; %d left",
				off, typ, length, len(b)-off)
		}
		body := b[off+4 : off+length]
		t := TLV{
			Type:     typ,
			TypeHex:  fmt.Sprintf("0x%04X", typ),
			TypeName: tlvTypeName(typ),
			Length:   length,
		}
		if len(body) > 0 {
			t.BodyHex = strings.ToUpper(hex.EncodeToString(body))
		}
		decorate(&t, typ, body)
		r.TLVs = append(r.TLVs, t)
		off += length
	}

	r.TLVCount = len(r.TLVs)
	names := make([]string, 0, len(r.TLVs))
	for _, t := range r.TLVs {
		names = append(names, t.TypeName)
	}
	r.Summary = strings.Join(names, " + ")
	return r, nil
}

func decorate(t *TLV, typ int, body []byte) {
	switch typ {
	case 0x0001:
		t.DeviceID = safeText(body)
	case 0x0002:
		t.Addresses = decodeAddressList(body)
	case 0x0003:
		t.PortID = safeText(body)
	case 0x0004:
		if len(body) == 4 {
			raw := binary.BigEndian.Uint32(body)
			t.Capabilities = &Capabilities{
				Raw:    raw,
				RawHex: fmt.Sprintf("0x%08X", raw),
				Flags:  capabilityFlagsName(raw),
			}
		}
	case 0x0005:
		t.SoftwareVersion = safeText(body)
	case 0x0006:
		t.Platform = safeText(body)
	case 0x000A:
		if len(body) == 2 {
			v := binary.BigEndian.Uint16(body)
			t.NativeVLAN = &v
		}
	case 0x000B:
		if len(body) == 1 {
			if body[0] == 0 {
				t.Duplex = "half-duplex"
			} else {
				t.Duplex = "full-duplex"
			}
		}
	case 0x0010:
		if len(body) == 2 {
			v := binary.BigEndian.Uint16(body)
			t.PowerMW = &v
		}
	case 0x0011:
		if len(body) == 4 {
			v := binary.BigEndian.Uint32(body)
			t.MTU = &v
		}
	case 0x0012:
		if len(body) == 1 {
			v := body[0]
			t.TrustBitmap = &v
		}
	case 0x0013:
		if len(body) == 1 {
			v := body[0]
			t.UntrustedCoS = &v
		}
	case 0x0014:
		t.SystemName = safeText(body)
	case 0x0015:
		t.SystemObjectID = strings.ToUpper(hex.EncodeToString(body))
	case 0x0016:
		t.ManagementAddresses = decodeAddressList(body)
	}
}

func decodeAddressList(b []byte) *AddressList {
	if len(b) < 4 {
		return nil
	}
	count := binary.BigEndian.Uint32(b[0:4])
	al := &AddressList{Count: int(count)}
	off := 4
	for i := uint32(0); i < count; i++ {
		if off+2 > len(b) {
			return al
		}
		protoType := int(b[off])
		protoLen := int(b[off+1])
		off += 2
		if off+protoLen+2 > len(b) {
			return al
		}
		protoBytes := b[off : off+protoLen]
		off += protoLen
		addrLen := int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
		if off+addrLen > len(b) {
			return al
		}
		addrBytes := b[off : off+addrLen]
		off += addrLen
		al.Addresses = append(al.Addresses, Address{
			ProtocolType: protoType,
			ProtocolHex:  strings.ToUpper(hex.EncodeToString(protoBytes)),
			ProtocolName: protocolName(protoType, protoBytes),
			Address:      formatAddress(protoType, protoBytes, addrBytes),
			AddressHex:   strings.ToUpper(hex.EncodeToString(addrBytes)),
		})
	}
	return al
}

func tlvTypeName(t int) string {
	switch t {
	case 0x0001:
		return "Device ID"
	case 0x0002:
		return "Addresses"
	case 0x0003:
		return "Port ID"
	case 0x0004:
		return "Capabilities"
	case 0x0005:
		return "Software Version"
	case 0x0006:
		return "Platform"
	case 0x0007:
		return "IP Network Prefix"
	case 0x0008:
		return "Protocol Hello"
	case 0x0009:
		return "VTP Management Domain"
	case 0x000A:
		return "Native VLAN"
	case 0x000B:
		return "Duplex"
	case 0x000E:
		return "VoIP VLAN Reply"
	case 0x000F:
		return "VoIP VLAN Query"
	case 0x0010:
		return "Power Consumption"
	case 0x0011:
		return "MTU"
	case 0x0012:
		return "Trust Bitmap"
	case 0x0013:
		return "Untrusted Port CoS"
	case 0x0014:
		return "System Name"
	case 0x0015:
		return "System Object ID"
	case 0x0016:
		return "Management Address"
	case 0x0017:
		return "Location"
	}
	return fmt.Sprintf("TLV 0x%04X (uncatalogued)", t)
}

func capabilityFlagsName(flags uint32) string {
	parts := []string{}
	if flags&0x01 != 0 {
		parts = append(parts, "Router")
	}
	if flags&0x02 != 0 {
		parts = append(parts, "Transparent Bridge")
	}
	if flags&0x04 != 0 {
		parts = append(parts, "Source Route Bridge")
	}
	if flags&0x08 != 0 {
		parts = append(parts, "Switch (Layer 2)")
	}
	if flags&0x10 != 0 {
		parts = append(parts, "Host")
	}
	if flags&0x20 != 0 {
		parts = append(parts, "IGMP-capable")
	}
	if flags&0x40 != 0 {
		parts = append(parts, "Repeater")
	}
	if flags&0x80 != 0 {
		parts = append(parts, "VoIP Phone")
	}
	if flags&0x100 != 0 {
		parts = append(parts, "Remotely Managed Device")
	}
	if flags&0x200 != 0 {
		parts = append(parts, "CVTA (Cast VLAN Trunking Aware)")
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, " | ")
}

func protocolName(typ int, proto []byte) string {
	if typ == 1 && len(proto) == 1 && proto[0] == 0xCC {
		return "IPv4 (NLPID 0xCC)"
	}
	if typ == 2 && len(proto) == 8 {
		// 802.2 LLC SNAP with OUI + PID; IPv6 is OUI 00-00-00 PID 0x86DD.
		if proto[5] == 0x00 && proto[6] == 0x86 && proto[7] == 0xDD {
			return "IPv6 (802.2 SNAP)"
		}
		return "802.2 SNAP"
	}
	return fmt.Sprintf("protocol type %d", typ)
}

func formatAddress(protoType int, proto, addr []byte) string {
	// IPv4: NLPID 0xCC + 4 byte address.
	if protoType == 1 && len(proto) == 1 && proto[0] == 0xCC && len(addr) == 4 {
		return net.IP(addr).String()
	}
	// IPv6: 802.2 SNAP, address is 16 bytes.
	if protoType == 2 && len(addr) == 16 {
		return net.IP(addr).String()
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
