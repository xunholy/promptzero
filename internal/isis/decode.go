// Package isis decodes IS-IS (Intermediate System to Intermediate System)
// packets per ISO 10589 and RFC 1195. IS-IS runs directly over L2 (OSI
// CLNS) — it has no IP header. On Ethernet it uses LLC/SNAP encapsulation
// or is carried directly; on point-to-point links it rides HDLC or PPP.
// IS-IS is the backbone IGP for large ISP and enterprise networks.
//
// IS-IS is a **high-value ISP/enterprise routing target**. Unlike IP-based
// routing protocols, IS-IS runs at L2, making it accessible to any device
// on the same segment. Default IS-IS has NO authentication — any L2-adjacent
// device can inject LSPs, redirect traffic through an attacker's device (MITM
// at ISP scale), or black-hole arbitrary prefixes.
//
// The wire format leaks:
//
//   - **System IDs + area addresses** — the complete L2 network topology is
//     encoded in every Hello and LSP. Area addresses reveal the IS-IS area
//     structure; system IDs identify every router. Together they enable
//     offline topology reconstruction.
//
//   - **Dynamic Hostname (TLV 137)** — most operators configure hostnames
//     in IS-IS for operator convenience. These hostnames map system IDs to
//     human-readable router names (e.g., "core-router-nyc-01"), directly
//     disclosing network topology and naming conventions.
//
//   - **Authentication (TLV 10)** — IS-IS auth is optional and commonly
//     absent. Cleartext password (auth_type 1) transmits the password in
//     plain text. HMAC-MD5 (auth_type 54) is offline-crackable via hashcat.
//     Absent TLV 10 means NO AUTHENTICATION — LSP injection is trivial.
//
//   - **IP interface addresses (TLV 132)** — every IS-IS Hello contains the
//     IP addresses of the originating interface, directly mapping system IDs
//     to IP addresses for targeting.
//
//   - **LSP sequence numbers + overload bit** — the sequence number reveals
//     router uptime and convergence history. The overload bit signals a
//     router in maintenance or under load, making it a MITM candidate.
//
//   - **IS type (L1/L2/L1L2)** — reveals the IS-IS level structure, enabling
//     targeted attack on L1-only devices that trust L2 LSPs by default in
//     some configurations.
//
// Wrap-vs-native judgement:
//
//	Native. ISO 10589 is a public standard; RFC 1195 adds IP support.
//	The IS-IS wire format is an 8-byte common header followed by per-PDU
//	fixed fields and TLV chains. No crypto at the parse layer (auth data
//	is opaque — auth_type is decoded, not the key material).
//
// What this package covers:
//
//   - **8-byte IS-IS common header**: irpd, length_indicator, version,
//     id_length, pdu_type (5-bit field with 9-entry name table), version2,
//     reserved, max_area_addresses.
//
//   - **LAN Hello (IIH) additional fields** (PDU types 15 + 16):
//     circuit_type, source_id (6 bytes, dotted-hex), holding_time, pdu_length,
//     priority, lan_id (7 bytes).
//
//   - **Point-to-Point Hello additional fields** (PDU type 17):
//     circuit_type, source_id, holding_time, pdu_length, local_circuit_id.
//
//   - **LSP additional fields** (PDU types 18 + 20):
//     pdu_length, remaining_lifetime, lsp_id (8 bytes, hex), sequence_number,
//     checksum, overload_bit, is_type.
//
//   - **CSNP / PSNP additional fields** (PDU types 24–27): pdu_length,
//     source_id surfaced.
//
//   - **TLV walker**: type (1 byte) + length (1 byte) + value[length];
//     surfaces tlv_count and tlv_types list.
//
//   - **Key TLV decoders**:
//     TLV 1 (Area Addresses): area_addresses[] in hex.
//     TLV 10 (Authentication): has_auth, auth_type, auth_type_name,
//     is_cleartext_auth.
//     TLV 132 (IP Interface Address): ip_addresses[] in dotted-quad.
//     TLV 137 (Dynamic Hostname): hostname string.
//
//   - **Classification flags**: is_hello, is_lsp, is_csnp, is_psnp, level
//     (1 or 2).
//
// What this package does NOT cover (deliberately out of scope):
//
//   - TLV 6 (IS Neighbors): neighbor system ID list not decoded.
//   - TLV 128/130 (IP Internal/External Reachability): old-style IP routes
//     not decoded.
//   - TLV 135 (Extended IP Reachability): wide-metric IP routes not decoded.
//   - TLV 232 (IPv6 Reachability): IPv6 routes not decoded.
//   - TLV 240 (Router Capability): capability sub-TLVs not decoded.
//   - TLV 242 (Multi-Topology): MT-ID list not decoded.
//   - **Checksum verification**: the IS-IS checksum is not validated.
//   - **Authentication verification**: auth_data bytes are never surfaced;
//     only auth_type is decoded (privacy-preserving).
//   - **CSNP/PSNP LSP Entry TLVs**: LSP range and partial entry lists
//     not decoded.
//   - **LLC/SNAP framing**: feed bytes after any L2 framing has been stripped.
package isis

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the structured decode of an IS-IS PDU.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Common IS-IS header (8 bytes)
	IRPD             int    `json:"irpd"`
	LengthIndicator  int    `json:"length_indicator"`
	Version          int    `json:"version"`
	IDLength         int    `json:"id_length"`
	PDUType          int    `json:"pdu_type"`
	PDUTypeName      string `json:"pdu_type_name"`
	Version2         int    `json:"version2"`
	Reserved         int    `json:"reserved"`
	MaxAreaAddresses int    `json:"max_area_addresses"`

	// Classification
	IsHello bool `json:"is_hello"`
	IsLSP   bool `json:"is_lsp"`
	IsCSNP  bool `json:"is_csnp"`
	IsPSNP  bool `json:"is_psnp"`
	Level   int  `json:"level"`

	// Hello fields (LAN + P2P)
	CircuitType    int    `json:"circuit_type,omitempty"`
	SourceID       string `json:"source_id,omitempty"`
	HoldingTime    int    `json:"holding_time,omitempty"`
	PDULength      int    `json:"pdu_length,omitempty"`
	Priority       int    `json:"priority,omitempty"`
	LANID          string `json:"lan_id,omitempty"`
	LocalCircuitID int    `json:"local_circuit_id,omitempty"`

	// LSP fields
	LSPID             string `json:"lsp_id,omitempty"`
	RemainingLifetime int    `json:"remaining_lifetime,omitempty"`
	SequenceNumber    uint32 `json:"sequence_number,omitempty"`
	Checksum          string `json:"checksum,omitempty"`
	OverloadBit       bool   `json:"overload_bit,omitempty"`
	ISType            int    `json:"is_type,omitempty"`

	// TLV summary
	TLVCount int   `json:"tlv_count"`
	TLVTypes []int `json:"tlv_types"`

	// TLV 1 — Area Addresses
	AreaAddresses []string `json:"area_addresses,omitempty"`

	// TLV 10 — Authentication
	HasAuth         bool   `json:"has_auth"`
	AuthType        int    `json:"auth_type,omitempty"`
	AuthTypeName    string `json:"auth_type_name,omitempty"`
	IsCleartextAuth bool   `json:"is_cleartext_auth"`

	// TLV 132 — IP Interface Address
	IPAddresses []string `json:"ip_addresses,omitempty"`

	// TLV 137 — Dynamic Hostname
	Hostname string `json:"hostname,omitempty"`
}

// isisCommonHeaderSize is the size of the IS-IS common header.
const isisCommonHeaderSize = 8

// Decode parses an IS-IS PDU from a hex string. The input should be the
// raw IS-IS PDU bytes (after any LLC/SNAP or HDLC framing has been stripped).
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < isisCommonHeaderSize {
		return nil, fmt.Errorf("is-is header truncated (%d bytes; need %d)", len(b), isisCommonHeaderSize)
	}

	r := &Result{TotalBytes: len(b)}

	// Parse 8-byte IS-IS common header.
	r.IRPD = int(b[0])
	r.LengthIndicator = int(b[1])
	r.Version = int(b[2])
	r.IDLength = int(b[3])
	// PDU type is the lower 5 bits of byte 4.
	r.PDUType = int(b[4] & 0x1F)
	r.PDUTypeName = pduTypeName(r.PDUType)
	r.Version2 = int(b[5])
	r.Reserved = int(b[6])
	r.MaxAreaAddresses = int(b[7])

	// Classify PDU.
	switch r.PDUType {
	case 15, 16, 17:
		r.IsHello = true
	case 18, 20:
		r.IsLSP = true
	case 24, 25:
		r.IsCSNP = true
	case 26, 27:
		r.IsPSNP = true
	}

	// Derive level from PDU type.
	switch r.PDUType {
	case 15, 18, 24, 26:
		r.Level = 1
	case 16, 20, 25, 27:
		r.Level = 2
	case 17:
		// Point-to-Point Hello can operate at either level; use circuit_type
		// to disambiguate — but set 0 here and let it be overridden below.
		r.Level = 0
	}

	// Effective system ID length: id_length=0 means 6 (ISO default).
	sysIDLen := r.IDLength
	switch sysIDLen {
	case 0:
		sysIDLen = 6
	case 255:
		sysIDLen = 0
	}

	// The length_indicator tells us where the per-PDU variable header ends
	// and TLVs begin. Per ISO 10589 the length_indicator field is the number
	// of bytes in the fixed header (including the common header).
	hdrLen := r.LengthIndicator
	if hdrLen < isisCommonHeaderSize || hdrLen > len(b) {
		// Malformed: treat entire buffer as just common header, no TLVs.
		hdrLen = len(b)
	}

	// Parse per-PDU-type fixed fields.
	off := isisCommonHeaderSize
	switch r.PDUType {
	case 15, 16: // LAN IIH (L1 or L2)
		off = decodeLANHello(r, b, off, sysIDLen)
	case 17: // Point-to-Point IIH
		off = decodePTPHello(r, b, off, sysIDLen)
	case 18, 20: // L1/L2 LSP
		off = decodeLSP(r, b, off, sysIDLen)
	case 24, 25, 26, 27: // CSNP / PSNP
		off = decodeCSNPPSNP(r, b, off, sysIDLen)
	}

	// Walk TLVs starting after the fixed per-PDU header.
	r.TLVTypes = []int{}
	r.IPAddresses = []string{}
	r.AreaAddresses = []string{}

	tlvStart := hdrLen
	if tlvStart < off {
		tlvStart = off
	}
	walkTLVs(r, b[tlvStart:])

	return r, nil
}

// decodeLANHello parses LAN IIH fixed fields (after common header).
// Layout: circuit_type(1) + source_id(sysIDLen) + holding_time(2BE) +
// pdu_length(2BE) + priority(1) + lan_id(sysIDLen+1)
func decodeLANHello(r *Result, b []byte, off, sysIDLen int) int {
	need := off + 1 + sysIDLen + 2 + 2 + 1 + sysIDLen + 1
	if len(b) < need {
		return len(b)
	}
	r.CircuitType = int(b[off] & 0x03)
	off++
	r.SourceID = formatSystemID(b[off : off+sysIDLen])
	off += sysIDLen
	r.HoldingTime = int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	r.PDULength = int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	r.Priority = int(b[off] & 0x7F)
	off++
	// LAN ID = designated IS system-ID (sysIDLen) + pseudonode ID (1)
	r.LANID = hex.EncodeToString(b[off : off+sysIDLen+1])
	off += sysIDLen + 1
	return off
}

// decodePTPHello parses Point-to-Point IIH fixed fields (after common header).
// Layout: circuit_type(1) + source_id(sysIDLen) + holding_time(2BE) +
// pdu_length(2BE) + local_circuit_id(1)
func decodePTPHello(r *Result, b []byte, off, sysIDLen int) int {
	need := off + 1 + sysIDLen + 2 + 2 + 1
	if len(b) < need {
		return len(b)
	}
	r.CircuitType = int(b[off] & 0x03)
	// For P2P hello, level comes from circuit_type.
	switch r.CircuitType {
	case 1:
		r.Level = 1
	case 2:
		r.Level = 2
	case 3:
		r.Level = 0 // L1+L2
	}
	off++
	r.SourceID = formatSystemID(b[off : off+sysIDLen])
	off += sysIDLen
	r.HoldingTime = int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	r.PDULength = int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	r.LocalCircuitID = int(b[off])
	off++
	return off
}

// decodeLSP parses LSP fixed fields (after common header).
// Layout: pdu_length(2BE) + remaining_lifetime(2BE) + lsp_id(sysIDLen+2) +
// sequence_number(4BE) + checksum(2BE) + p_att_oload_istype(1)
func decodeLSP(r *Result, b []byte, off, sysIDLen int) int {
	lspIDLen := sysIDLen + 2 // system_id + pseudonode_id + fragment
	need := off + 2 + 2 + lspIDLen + 4 + 2 + 1
	if len(b) < need {
		return len(b)
	}
	r.PDULength = int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	r.RemainingLifetime = int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	r.LSPID = hex.EncodeToString(b[off : off+lspIDLen])
	off += lspIDLen
	r.SequenceNumber = binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	r.Checksum = fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(b[off:off+2]))
	off += 2
	flags := b[off]
	r.OverloadBit = (flags & 0x04) != 0
	r.ISType = int(flags & 0x03)
	off++
	return off
}

// decodeCSNPPSNP parses CSNP/PSNP fixed fields (after common header).
// Layout: pdu_length(2BE) + source_id(sysIDLen+1)
func decodeCSNPPSNP(r *Result, b []byte, off, sysIDLen int) int {
	sourceIDLen := sysIDLen + 1 // system_id + circuit_id
	need := off + 2 + sourceIDLen
	if len(b) < need {
		return len(b)
	}
	r.PDULength = int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	r.SourceID = formatSystemID(b[off : off+sysIDLen])
	off += sourceIDLen
	return off
}

// walkTLVs iterates over the TLV section of an IS-IS PDU.
// IS-IS TLVs use 1-byte type + 1-byte length (unlike EIGRP's 2+2).
func walkTLVs(r *Result, tlvs []byte) {
	off := 0
	for off+2 <= len(tlvs) {
		tlvType := int(tlvs[off])
		tlvLen := int(tlvs[off+1])
		if off+2+tlvLen > len(tlvs) {
			// Truncated TLV value; stop walking.
			break
		}
		r.TLVCount++
		r.TLVTypes = append(r.TLVTypes, tlvType)

		value := tlvs[off+2 : off+2+tlvLen]
		decodeTLV(r, tlvType, value)

		off += 2 + tlvLen
	}
}

func decodeTLV(r *Result, tlvType int, value []byte) {
	switch tlvType {
	case 1: // Area Addresses
		decodeAreaAddressesTLV(r, value)
	case 10: // Authentication
		decodeAuthTLV(r, value)
	case 132: // IP Interface Address
		decodeIPInterfaceAddressTLV(r, value)
	case 137: // Dynamic Hostname
		r.Hostname = string(value)
	}
}

// decodeAreaAddressesTLV parses TLV type 1 (Area Addresses).
// Value format: repeated { address_length(1) + address(address_length) }
func decodeAreaAddressesTLV(r *Result, value []byte) {
	off := 0
	for off < len(value) {
		if off+1 > len(value) {
			break
		}
		addrLen := int(value[off])
		off++
		if off+addrLen > len(value) {
			break
		}
		r.AreaAddresses = append(r.AreaAddresses, hex.EncodeToString(value[off:off+addrLen]))
		off += addrLen
	}
}

// decodeAuthTLV parses TLV type 10 (Authentication).
// Value format: auth_type(1) + auth_data(variable)
func decodeAuthTLV(r *Result, value []byte) {
	if len(value) < 1 {
		return
	}
	r.HasAuth = true
	r.AuthType = int(value[0])
	r.AuthTypeName = authTypeName(r.AuthType)
	r.IsCleartextAuth = r.AuthType == 1
}

// decodeIPInterfaceAddressTLV parses TLV type 132 (IP Interface Address).
// Value format: repeated IPv4 addresses (4 bytes each)
func decodeIPInterfaceAddressTLV(r *Result, value []byte) {
	for i := 0; i+4 <= len(value); i += 4 {
		addr := net.IP(value[i : i+4]).String()
		r.IPAddresses = append(r.IPAddresses, addr)
	}
}

// formatSystemID formats a system ID byte slice as dotted-hex "XXXX.XXXX.XXXX".
// The IS-IS standard uses 6-byte system IDs by default. For other lengths,
// the bytes are grouped in pairs separated by dots.
func formatSystemID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	raw := hex.EncodeToString(b)
	// Group into 4-character (2-byte) chunks separated by dots.
	var parts []string
	for i := 0; i < len(raw); i += 4 {
		end := i + 4
		if end > len(raw) {
			end = len(raw)
		}
		parts = append(parts, raw[i:end])
	}
	return strings.Join(parts, ".")
}

func pduTypeName(t int) string {
	switch t {
	case 15:
		return "L1_LAN_Hello"
	case 16:
		return "L2_LAN_Hello"
	case 17:
		return "P2P_Hello"
	case 18:
		return "L1_LSP"
	case 20:
		return "L2_LSP"
	case 24:
		return "L1_CSNP"
	case 25:
		return "L2_CSNP"
	case 26:
		return "L1_PSNP"
	case 27:
		return "L2_PSNP"
	}
	return fmt.Sprintf("pdu_type_%d", t)
}

func authTypeName(t int) string {
	switch t {
	case 1:
		return "Cleartext"
	case 3:
		return "CryptoAuth"
	case 54:
		return "HMAC-MD5"
	}
	return fmt.Sprintf("auth_type_%d", t)
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
