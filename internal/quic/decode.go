// Package quic decodes QUIC long-header packets per RFC 9000.
// The short header (1-RTT, post-handshake) and frame-level
// dissection inside encrypted payloads are out of scope; this
// package gets you the connection-setup visibility (Initial /
// 0-RTT / Handshake / Retry / Version Negotiation) that's
// useful for HTTP/3 + QUIC traffic forensics.
//
// Wrap-vs-native judgement
//
//	Native. RFC 9000 is fully public; the long-header wire
//	format is a tight bit-packed byte (header form / fixed
//	bit / long packet type / type-specific bits) plus a
//	32-bit version + 1-byte-length-prefixed Destination
//	Connection ID + 1-byte-length-prefixed Source Connection
//	ID + per-type body. Variable-Length Integer encoding
//	(§16) is a 2-bit-prefix variant with payload lengths of
//	1/2/4/8 bytes. No crypto at the long-header layer —
//	the payload is header-protected and packet-protected,
//	but the SCID / DCID / Version / Token are all in the
//	clear. Operators paste UDP-payload bytes from a
//	Wireshark Follow-UDP-Stream view, a `tcpdump -X udp
//	port 443` line, or any QUIC-emitting tool and inspect
//	the cleartext header fields.
//
// What this package covers
//
//   - **First-byte dispatch**:
//
//   - high bit 1 = long header (this package)
//
//   - high bit 0 = short header (not decoded; surfaced
//     with a note pointing at the truncated header)
//
//   - **Version Negotiation** is the special case where
//     the Version field is 0x00000000; the packet then
//     carries a list of supported versions.
//
//   - **Long header common** (RFC 9000 §17.2):
//
//   - byte 0: Header Form (1 bit) + Fixed Bit (1 bit) +
//     Long Packet Type (2 bits) + Type-Specific (4 bits;
//     low 2 bits are the encrypted-length of the packet
//     number, but the high 2 bits are header-protected so
//     we surface the raw type-specific nibble verbatim).
//
//   - Version (4 bytes BE): 0x00000001 = QUIC v1
//     (canonical); 0x00000000 = Version Negotiation;
//     0x6B3343CF = QUIC v2 (RFC 9369); IANA-registered
//     Force-Greasing version 0xFAFAFAFA etc.
//
//   - DCID Length (1 byte; 0-160 per RFC 9000 §17.2).
//
//   - DCID (DCID Length bytes).
//
//   - SCID Length (1 byte; 0-160).
//
//   - SCID (SCID Length bytes).
//
//   - **Long Packet Types** (RFC 9000 §17.2):
//
//   - 0 Initial: Token Length (VLI) + Token + Length (VLI)
//
//   - Packet Number (1-4 bytes, header-protected) +
//     Protected Payload.
//
//   - 1 0-RTT: Length (VLI) + Packet Number + Protected
//     Payload.
//
//   - 2 Handshake: Length (VLI) + Packet Number +
//     Protected Payload.
//
//   - 3 Retry: Retry Token (variable) + Retry Integrity
//     Tag (16 bytes, AES-128-GCM tag covering the original
//     DCID).
//
//   - **Variable-Length Integer** (RFC 9000 §16):
//
//   - 0b00 prefix: 6-bit value in 1 byte
//
//   - 0b01 prefix: 14-bit value in 2 bytes
//
//   - 0b10 prefix: 30-bit value in 4 bytes
//
//   - 0b11 prefix: 62-bit value in 8 bytes
//
//   - **Version Negotiation** (RFC 9000 §17.2.1): if Version
//     == 0, the bytes after SCID are a list of uint32 BE
//     supported versions chosen by the server.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - Short-header (1-RTT) packets — the packet number length
//     and key-phase bits are in the header-protected first
//     byte, so without the header-protection key we can't
//     unambiguously parse the packet number. A future Spec
//     could surface the cleartext fields (DCID — but only if
//     the operator already knows the agreed DCID length, which
//     varies per connection).
//
//   - 0-RTT / Handshake / 1-RTT payload decryption — requires
//     the TLS-handshake secrets, which are not on the wire.
//     Those protected payloads are surfaced as hex. (The
//     **Initial** payload is the exception: its keys are public,
//     so it IS decrypted — see initial_decrypt.go.)
//
//   - UDP / IP framing — feed the UDP payload bytes after the
//     IP+UDP headers.
//
// What this package additionally covers (see initial_decrypt.go)
//
//   - **QUIC v1 Initial decryption.** The Initial packet is
//     protected with keys derived deterministically from the
//     clear-text Destination Connection ID and a fixed salt
//     (RFC 9001 §5.2), so it is fully decryptable offline. For
//     v1 Initials this package removes header protection, runs
//     AES-128-GCM, dissects the frames (PADDING / PING / ACK /
//     CRYPTO / CONNECTION_CLOSE) and reassembles the CRYPTO
//     stream into the TLS ClientHello / ServerHello — the bytes
//     QUIC otherwise hides, ready for tls_handshake_decode.
package quic

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	HeaderForm         string `json:"header_form"`
	IsLongHeader       bool   `json:"is_long_header"`
	FixedBit           bool   `json:"fixed_bit"`
	LongPacketType     int    `json:"long_packet_type,omitempty"`
	LongPacketTypeName string `json:"long_packet_type_name,omitempty"`
	TypeSpecificNibble int    `json:"type_specific_nibble,omitempty"`
	FirstByteHex       string `json:"first_byte_hex"`
	Version            uint32 `json:"version"`
	VersionName        string `json:"version_name"`
	VersionHex         string `json:"version_hex"`
	DCIDLength         int    `json:"dcid_length"`
	DCIDHex            string `json:"dcid_hex,omitempty"`
	SCIDLength         int    `json:"scid_length"`
	SCIDHex            string `json:"scid_hex,omitempty"`

	Initial            *InitialPacket    `json:"initial,omitempty"`
	ZeroRTT            *LengthOnlyPacket `json:"zero_rtt,omitempty"`
	Handshake          *LengthOnlyPacket `json:"handshake,omitempty"`
	Retry              *RetryPacket      `json:"retry,omitempty"`
	VersionNegotiation *VersionNeg       `json:"version_negotiation,omitempty"`

	TotalBytes int      `json:"total_bytes"`
	Notes      []string `json:"notes,omitempty"`
}

// InitialPacket is the type-0 long-header body.
type InitialPacket struct {
	TokenLength         uint64 `json:"token_length"`
	TokenHex            string `json:"token_hex,omitempty"`
	Length              uint64 `json:"length"`
	ProtectedPayloadLen int    `json:"protected_payload_length"`
	ProtectedPayloadHex string `json:"protected_payload_hex,omitempty"`

	// Decrypted is populated for QUIC v1 Initials, whose protection
	// keys are public (derived from the DCID + a fixed salt). nil when
	// decryption is not applicable or fails authentication.
	Decrypted *DecryptedInitial `json:"decrypted,omitempty"`
}

// LengthOnlyPacket covers 0-RTT and Handshake (same body
// shape: length + protected packet number + protected payload).
type LengthOnlyPacket struct {
	Length              uint64 `json:"length"`
	ProtectedPayloadLen int    `json:"protected_payload_length"`
	ProtectedPayloadHex string `json:"protected_payload_hex,omitempty"`
}

// RetryPacket is the type-3 long-header body.
type RetryPacket struct {
	RetryTokenLen   int    `json:"retry_token_length"`
	RetryTokenHex   string `json:"retry_token_hex,omitempty"`
	IntegrityTagHex string `json:"integrity_tag_hex"`
}

// VersionNeg is the Version Negotiation packet body
// (RFC 9000 §17.2.1).
type VersionNeg struct {
	SupportedVersions    []uint32 `json:"supported_versions"`
	SupportedVersionsHex []string `json:"supported_versions_hex"`
}

// Decode parses a QUIC packet from hex.
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
	if len(b) < 1 {
		return nil, fmt.Errorf("packet too short")
	}

	first := b[0]
	r := &Result{
		TotalBytes:   len(b),
		FirstByteHex: fmt.Sprintf("0x%02X", first),
		IsLongHeader: first&0x80 != 0,
		FixedBit:     first&0x40 != 0,
	}
	if r.IsLongHeader {
		r.HeaderForm = "long"
	} else {
		r.HeaderForm = "short (1-RTT, not decoded in this Spec)"
		r.Notes = append(r.Notes,
			"short-header (1-RTT) packets have header-protected packet-number length "+
				"bits; this Spec only decodes long-header packets")
		return r, nil
	}

	r.LongPacketType = int((first >> 4) & 0x03)
	r.LongPacketTypeName = longPacketTypeName(r.LongPacketType)
	r.TypeSpecificNibble = int(first & 0x0F)

	if len(b) < 1+4+1 { // header + version + dcid_len byte
		return nil, fmt.Errorf("long header truncated (%d bytes; need ≥6)", len(b))
	}

	r.Version = binary.BigEndian.Uint32(b[1:5])
	r.VersionHex = fmt.Sprintf("0x%08X", r.Version)
	r.VersionName = versionName(r.Version)

	off := 5
	if r.Version == 0 {
		// Version Negotiation: still has DCID + SCID + version list.
		dcid, scid, used, err := readDCIDSCID(b[off:])
		if err != nil {
			return nil, fmt.Errorf("version negotiation: %w", err)
		}
		r.DCIDLength = len(dcid)
		r.DCIDHex = strings.ToUpper(hex.EncodeToString(dcid))
		r.SCIDLength = len(scid)
		r.SCIDHex = strings.ToUpper(hex.EncodeToString(scid))
		off += used
		// Remaining: list of uint32 BE versions.
		if (len(b)-off)%4 != 0 {
			return nil, fmt.Errorf("version negotiation: trailing %d bytes is not a multiple of 4",
				len(b)-off)
		}
		vn := &VersionNeg{}
		for i := off; i+4 <= len(b); i += 4 {
			v := binary.BigEndian.Uint32(b[i : i+4])
			vn.SupportedVersions = append(vn.SupportedVersions, v)
			vn.SupportedVersionsHex = append(vn.SupportedVersionsHex,
				fmt.Sprintf("0x%08X", v))
		}
		r.LongPacketTypeName = "Version Negotiation"
		r.VersionNegotiation = vn
		return r, nil
	}

	dcid, scid, used, err := readDCIDSCID(b[off:])
	if err != nil {
		return nil, fmt.Errorf("long header: %w", err)
	}
	r.DCIDLength = len(dcid)
	r.DCIDHex = strings.ToUpper(hex.EncodeToString(dcid))
	r.SCIDLength = len(scid)
	r.SCIDHex = strings.ToUpper(hex.EncodeToString(scid))
	off += used

	switch r.LongPacketType {
	case 0: // Initial
		ip, used, err := decodeInitial(b[off:])
		if err != nil {
			return nil, fmt.Errorf("initial: %w", err)
		}
		r.Initial = ip
		_ = used
		// QUIC v1 Initial keys are public (RFC 9001 §5.2): try to
		// decrypt and surface the CRYPTO stream / ClientHello. Try the
		// client role first, then the server role; nil on failure.
		if r.Version == 0x00000001 {
			if dec, derr := DecryptInitial(b, "client"); derr == nil {
				r.Initial.Decrypted = dec
			} else if dec, derr := DecryptInitial(b, "server"); derr == nil {
				r.Initial.Decrypted = dec
			} else {
				r.Notes = append(r.Notes,
					"Initial payload could not be decrypted (truncated capture, "+
						"non-first-flight packet number, or corrupt packet)")
			}
		}
	case 1: // 0-RTT
		ln, lo, err := readVLI(b[off:])
		if err != nil {
			return nil, fmt.Errorf("0-RTT length VLI: %w", err)
		}
		r.ZeroRTT = decodeLengthOnly(b[off+lo:], ln)
	case 2: // Handshake
		ln, lo, err := readVLI(b[off:])
		if err != nil {
			return nil, fmt.Errorf("handshake length VLI: %w", err)
		}
		r.Handshake = decodeLengthOnly(b[off+lo:], ln)
	case 3: // Retry
		r.Retry = decodeRetry(b[off:])
	}

	return r, nil
}

func readDCIDSCID(b []byte) (dcid, scid []byte, used int, err error) {
	if len(b) < 1 {
		return nil, nil, 0, fmt.Errorf("DCID length truncated")
	}
	dcidLen := int(b[0])
	if dcidLen > 20 {
		return nil, nil, 0, fmt.Errorf("DCID length %d exceeds 20 (RFC 9000 §17.2)",
			dcidLen)
	}
	if 1+dcidLen+1 > len(b) {
		return nil, nil, 0, fmt.Errorf("DCID truncated")
	}
	dcid = b[1 : 1+dcidLen]
	off := 1 + dcidLen
	scidLen := int(b[off])
	if scidLen > 20 {
		return nil, nil, 0, fmt.Errorf("SCID length %d exceeds 20 (RFC 9000 §17.2)",
			scidLen)
	}
	off++
	if off+scidLen > len(b) {
		return nil, nil, 0, fmt.Errorf("SCID truncated")
	}
	scid = b[off : off+scidLen]
	off += scidLen
	return dcid, scid, off, nil
}

func decodeInitial(b []byte) (*InitialPacket, int, error) {
	tokLen, used, err := readVLI(b)
	if err != nil {
		return nil, 0, fmt.Errorf("token length VLI: %w", err)
	}
	if uint64(used)+tokLen > uint64(len(b)) {
		return nil, 0, fmt.Errorf("token (%d bytes) overruns buffer", tokLen)
	}
	off := used + int(tokLen)
	token := b[used:off]
	ip := &InitialPacket{
		TokenLength: tokLen,
	}
	if tokLen > 0 {
		ip.TokenHex = strings.ToUpper(hex.EncodeToString(token))
	}
	if off >= len(b) {
		return ip, off, nil
	}
	plen, plo, err := readVLI(b[off:])
	if err != nil {
		return nil, 0, fmt.Errorf("length VLI: %w", err)
	}
	off += plo
	ip.Length = plen
	if off+int(plen) > len(b) {
		ip.ProtectedPayloadLen = len(b) - off
	} else {
		ip.ProtectedPayloadLen = int(plen)
	}
	if ip.ProtectedPayloadLen > 0 {
		end := off + ip.ProtectedPayloadLen
		if end > len(b) {
			end = len(b)
		}
		if ip.ProtectedPayloadLen > 256 {
			ip.ProtectedPayloadHex =
				strings.ToUpper(hex.EncodeToString(b[off:off+256])) + "..."
		} else {
			ip.ProtectedPayloadHex = strings.ToUpper(hex.EncodeToString(b[off:end]))
		}
	}
	return ip, off + ip.ProtectedPayloadLen, nil
}

func decodeLengthOnly(b []byte, declaredLen uint64) *LengthOnlyPacket {
	lo := &LengthOnlyPacket{Length: declaredLen}
	available := len(b)
	if uint64(available) < declaredLen {
		lo.ProtectedPayloadLen = available
	} else {
		lo.ProtectedPayloadLen = int(declaredLen)
	}
	if lo.ProtectedPayloadLen > 0 {
		end := lo.ProtectedPayloadLen
		if end > len(b) {
			end = len(b)
		}
		if lo.ProtectedPayloadLen > 256 {
			lo.ProtectedPayloadHex =
				strings.ToUpper(hex.EncodeToString(b[:256])) + "..."
		} else {
			lo.ProtectedPayloadHex = strings.ToUpper(hex.EncodeToString(b[:end]))
		}
	}
	return lo
}

func decodeRetry(b []byte) *RetryPacket {
	rp := &RetryPacket{}
	if len(b) < 16 {
		// Retry packets always end with a 16-byte AEAD tag.
		rp.IntegrityTagHex = strings.ToUpper(hex.EncodeToString(b))
		return rp
	}
	tokLen := len(b) - 16
	rp.RetryTokenLen = tokLen
	if tokLen > 0 {
		if tokLen > 256 {
			rp.RetryTokenHex = strings.ToUpper(hex.EncodeToString(b[:256])) + "..."
		} else {
			rp.RetryTokenHex = strings.ToUpper(hex.EncodeToString(b[:tokLen]))
		}
	}
	rp.IntegrityTagHex = strings.ToUpper(hex.EncodeToString(b[tokLen:]))
	return rp
}

// readVLI parses a QUIC Variable-Length Integer per RFC 9000
// §16. Returns value, bytes consumed, error.
func readVLI(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("VLI: empty buffer")
	}
	first := b[0]
	prefix := first >> 6
	length := 1 << prefix
	if len(b) < length {
		return 0, 0, fmt.Errorf("VLI: prefix %d expects %d bytes, have %d",
			prefix, length, len(b))
	}
	v := uint64(first & 0x3F)
	for i := 1; i < length; i++ {
		v = (v << 8) | uint64(b[i])
	}
	return v, length, nil
}

func longPacketTypeName(t int) string {
	switch t {
	case 0:
		return "Initial"
	case 1:
		return "0-RTT"
	case 2:
		return "Handshake"
	case 3:
		return "Retry"
	}
	return fmt.Sprintf("unknown type %d", t)
}

func versionName(v uint32) string {
	switch v {
	case 0x00000000:
		return "Version Negotiation"
	case 0x00000001:
		return "QUIC v1 (RFC 9000)"
	case 0x6B3343CF:
		return "QUIC v2 (RFC 9369)"
	case 0xFF00001D:
		return "draft-29"
	case 0xFF000022:
		return "draft-34"
	}
	if v&0x0F0F0F0F == 0x0A0A0A0A {
		return fmt.Sprintf("GREASE 0x%08X (RFC 8701)", v)
	}
	return fmt.Sprintf("unknown 0x%08X", v)
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
