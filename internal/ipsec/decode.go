// Package ipsec decodes the two IPsec data-plane protocols:
// ESP (Encapsulating Security Payload) per RFC 4303 and AH
// (Authentication Header) per RFC 4302. ESP is the dominant
// IPsec protocol — every site-to-site VPN (between branch
// offices, between cloud VPCs, between on-prem and cloud) and
// every IPsec-based remote-access VPN (StrongSwan, OpenSwan,
// Cisco AnyConnect IPsec mode, Windows IPsec) wraps its
// payload in ESP. AH provides authentication without
// confidentiality and is less common today, but remains in use
// for specific compliance + lawful-intercept scenarios where
// payload encryption is forbidden but integrity is required.
//
// Wrap-vs-native judgement
//
//	Native. RFCs 4302 + 4303 are fully public. Both
//	protocols have tight fixed-position headers — ESP is
//	an 8-byte preamble (SPI + Sequence) followed by an
//	opaque encrypted payload + trailer + ICV; AH is a
//	12-byte fixed header (Next Header + Payload Length +
//	Reserved + SPI + Sequence) followed by a variable-
//	length ICV whose size is derived from Payload Length.
//	No crypto at the parse layer — the encrypted payload
//	and ICV bytes are surfaced as hex for traceability;
//	verification requires the SA's key + algorithm
//	negotiated via IKE.
//
// What this package covers
//
//   - **ESP header** (RFC 4303 §2): 4-byte **SPI** (Security
//     Parameters Index — identifies the Security Association)
//
//   - 4-byte **Sequence Number** (per-SA monotonic anti-
//     replay counter) + remainder is opaque encrypted
//     payload that includes Padding + Pad Length + Next
//     Header (concealed) + ICV (Integrity Check Value).
//
//   - **AH header** (RFC 4302 §2): 1-byte **Next Header**
//     (IP protocol number of the next header — uses the same
//     IANA name table as IP protocol numbers) + 1-byte
//     **Payload Length** (AH header length in 32-bit words
//     minus 2, so the total header bytes = (PL + 2) × 4) +
//     2-byte Reserved + 4-byte **SPI** + 4-byte **Sequence
//     Number** + variable-length **ICV** (size = (PL - 1) × 4
//     bytes; for HMAC-SHA1-96 ICV is 12 bytes / PL=4, for
//     HMAC-SHA-256-128 ICV is 16 bytes / PL=5 with 2-byte
//     padding, etc.).
//
//   - **SPI semantic notes**: SPI 0 is reserved for local
//     use, 1-255 are IANA-reserved for future allocation,
//     and ≥ 256 are negotiated by peer IKE agents.
//
//   - **Next Header name table** (AH only): 13-entry table
//     covering the most common IP protocol numbers:
//     6 TCP / 17 UDP / 1 ICMP / 41 IPv6 (tunnel mode inner
//     header) / 47 GRE / 50 ESP (chained IPsec) / 51 AH
//     (chained IPsec) / 58 ICMPv6 / 89 OSPF / 132 SCTP /
//     112 VRRP / 4 IPv4 (tunnel mode inner header) / 59
//     IPv6 No Next Header.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - IP framing — feed ESP / AH bytes after the IPv4 /
//     IPv6 header strip. ESP runs as IP protocol 50; AH
//     runs as IP protocol 51.
//
//   - Cryptographic verification — without the SA's
//     negotiated key + algorithm (IKE-negotiated), the
//     ESP payload is opaque ciphertext and AH ICV cannot
//     be verified. Both are surfaced as hex; full
//     decryption + integrity check is a future
//     IKE-state-aware iteration.
//
//   - IKE (Internet Key Exchange, RFC 7296) — the
//     control-plane protocol that negotiates IPsec SAs.
//     IKE has its own complex envelope with payloads;
//     would warrant its own Spec.
//
//   - ESP-in-UDP / NAT-T encapsulation (RFC 3948) — UDP
//     port 4500 with a 4-byte all-zeros marker
//     distinguishes ESP-NAT-T from IKE-NAT-T. Feed the
//     ESP bytes after stripping the UDP + marker.
//
//   - Tunnel-mode inner-IP-header dissection — once
//     decrypted (out of scope), the inner header would
//     feed into `ip_packet_decode` or similar.
package ipsec

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// ESPResult is the top-level decoded view of an ESP packet.
type ESPResult struct {
	SPI                 uint32   `json:"spi"`
	SPIHex              string   `json:"spi_hex"`
	SPINote             string   `json:"spi_note,omitempty"`
	SequenceNumber      uint32   `json:"sequence_number"`
	EncryptedBytes      int      `json:"encrypted_payload_bytes"`
	EncryptedHex        string   `json:"encrypted_payload_hex,omitempty"`
	EncryptedBytesShown int      `json:"encrypted_payload_bytes_shown,omitempty"`
	TotalBytes          int      `json:"total_bytes"`
	Notes               []string `json:"notes,omitempty"`
}

// AHResult is the top-level decoded view of an AH packet.
type AHResult struct {
	NextHeader         int      `json:"next_header"`
	NextHeaderName     string   `json:"next_header_name"`
	PayloadLengthField int      `json:"payload_length_field"`
	HeaderTotalBytes   int      `json:"header_total_bytes"`
	ICVBytes           int      `json:"icv_bytes"`
	Reserved           int      `json:"reserved"`
	SPI                uint32   `json:"spi"`
	SPIHex             string   `json:"spi_hex"`
	SPINote            string   `json:"spi_note,omitempty"`
	SequenceNumber     uint32   `json:"sequence_number"`
	ICVHex             string   `json:"icv_hex"`
	TotalBytes         int      `json:"total_bytes"`
	Notes              []string `json:"notes,omitempty"`
}

// DecodeOpts tunes the ESP payload preview cap.
type DecodeOpts struct {
	// MaxPayloadBytes caps the ESP encrypted payload hex
	// preview. Zero surfaces the full payload (typically
	// up to MTU-relative length).
	MaxPayloadBytes int
}

// DefaultDecodeOpts returns a 256-byte payload preview cap.
func DefaultDecodeOpts() DecodeOpts {
	return DecodeOpts{MaxPayloadBytes: 256}
}

// DecodeESP parses a single ESP packet from hex per RFC 4303.
// The decoder surfaces the 8-byte plaintext header (SPI +
// Sequence) and the encrypted payload + trailer + ICV as a
// single opaque hex blob.
func DecodeESP(hexStr string, opts DecodeOpts) (*ESPResult, error) {
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
		return nil, fmt.Errorf("ESP packet truncated (%d bytes; need ≥8 for SPI + Sequence)",
			len(b))
	}
	r := &ESPResult{
		TotalBytes:     len(b),
		SPI:            binary.BigEndian.Uint32(b[0:4]),
		SequenceNumber: binary.BigEndian.Uint32(b[4:8]),
	}
	r.SPIHex = fmt.Sprintf("0x%08X", r.SPI)
	r.SPINote = spiNote(r.SPI)
	encrypted := b[8:]
	r.EncryptedBytes = len(encrypted)
	if len(encrypted) > 0 {
		show := len(encrypted)
		if opts.MaxPayloadBytes > 0 && show > opts.MaxPayloadBytes {
			show = opts.MaxPayloadBytes
		}
		r.EncryptedHex = strings.ToUpper(hex.EncodeToString(encrypted[:show]))
		r.EncryptedBytesShown = show
	}
	return r, nil
}

// DecodeAH parses a single AH packet from hex per RFC 4302.
func DecodeAH(hexStr string) (*AHResult, error) {
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
		return nil, fmt.Errorf("AH packet truncated (%d bytes; need ≥12 for fixed header)",
			len(b))
	}
	r := &AHResult{
		TotalBytes:         len(b),
		NextHeader:         int(b[0]),
		PayloadLengthField: int(b[1]),
		Reserved:           int(binary.BigEndian.Uint16(b[2:4])),
		SPI:                binary.BigEndian.Uint32(b[4:8]),
		SequenceNumber:     binary.BigEndian.Uint32(b[8:12]),
	}
	r.NextHeaderName = nextHeaderName(r.NextHeader)
	r.SPIHex = fmt.Sprintf("0x%08X", r.SPI)
	r.SPINote = spiNote(r.SPI)
	r.HeaderTotalBytes = (r.PayloadLengthField + 2) * 4
	r.ICVBytes = r.HeaderTotalBytes - 12
	if r.HeaderTotalBytes > len(b) {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"AH header declares %d bytes (PayloadLength=%d) but only %d bytes provided",
			r.HeaderTotalBytes, r.PayloadLengthField, len(b)))
		r.ICVBytes = len(b) - 12
		if r.ICVBytes < 0 {
			r.ICVBytes = 0
		}
	}
	icvEnd := 12 + r.ICVBytes
	if icvEnd > len(b) {
		icvEnd = len(b)
	}
	r.ICVHex = strings.ToUpper(hex.EncodeToString(b[12:icvEnd]))
	if r.Reserved != 0 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"Reserved field is 0x%04X (RFC 4302 §2.2 requires 0)", r.Reserved))
	}
	return r, nil
}

func spiNote(spi uint32) string {
	switch {
	case spi == 0:
		return "0 — reserved for local use (RFC 4303 §2.1)"
	case spi >= 1 && spi <= 255:
		return fmt.Sprintf("%d — IANA-reserved for future allocation (RFC 4303 §2.1)", spi)
	}
	return ""
}

func nextHeaderName(n int) string {
	switch n {
	case 0:
		return "HOPOPT (IPv6 Hop-by-Hop Option)"
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 4:
		return "IPv4 (tunnel mode inner header)"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6 (tunnel mode inner header)"
	case 47:
		return "GRE"
	case 50:
		return "ESP (chained IPsec)"
	case 51:
		return "AH (chained IPsec)"
	case 58:
		return "ICMPv6"
	case 59:
		return "IPv6 No Next Header"
	case 89:
		return "OSPF"
	case 103:
		return "PIM"
	case 112:
		return "VRRP"
	case 132:
		return "SCTP"
	}
	return fmt.Sprintf("uncatalogued IP protocol %d", n)
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
