// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sshdecode parses SSH wire-protocol frames per RFC
// 4253 (SSH Transport Layer Protocol) and RFC 4250-4256.
// Specifically it covers the cleartext portions every SSH
// session emits before encryption is negotiated: the
// "SSH-2.0-..." version-exchange banner and the
// SSH_MSG_KEXINIT message that lists the algorithms each
// peer supports.
//
// # Wrap-vs-native judgement
//
// Native. RFC 4253 §4.2 defines the version banner as plain
// ASCII; §6 defines the binary packet envelope; §7.1 defines
// KEXINIT. SSH name-lists are comma-separated UTF-8 strings.
// Pasting either form into this decoder is enough — no SSH
// client/server, no key material, no live network attach.
//
// This is the SSH counterpart to tls_handshake_decode: the
// HASSH / HASSHServer fingerprint (Salesforce, ben-aaron-bowers,
// 2018) is the SSH analogue of JA3 and identifies SSH client/
// server stacks across thousands of distinct signatures.
//
// # What this package covers
//
//   - **Version exchange line** (RFC 4253 §4.2):
//     `SSH-protoversion-softwareversion [SP comments]` —
//     broken out into protocol version (1.x / 1.99 / 2.0),
//     software version (OpenSSH_8.9p1 / dropbear_2022.83 /
//     libssh2_1.10.0 / etc.), and optional comment field.
//   - **Binary packet envelope** (RFC 4253 §6):
//     `[packet_length:4][padding_length:1][payload][padding]
//     [MAC]`. The packet length excludes the length field
//     itself but includes padding_length, payload, and
//     padding. MAC length is session-dependent so we surface
//     it as raw trailing bytes (if any are present beyond
//     the declared packet length).
//   - **Message type dispatch** (27-entry table from RFC
//     4250 §4.1.2): SSH_MSG_DISCONNECT (1) /
//     SSH_MSG_IGNORE (2) / SSH_MSG_UNIMPLEMENTED (3) /
//     SSH_MSG_DEBUG (4) / SSH_MSG_SERVICE_REQUEST (5) /
//     SSH_MSG_SERVICE_ACCEPT (6) / SSH_MSG_EXT_INFO (7) /
//     SSH_MSG_NEWCOMPRESS (8) / SSH_MSG_KEXINIT (20) /
//     SSH_MSG_NEWKEYS (21) / SSH_MSG_KEXDH_INIT (30) /
//     SSH_MSG_KEXDH_REPLY (31) /
//     SSH_MSG_USERAUTH_REQUEST (50) /
//     SSH_MSG_USERAUTH_FAILURE (51) /
//     SSH_MSG_USERAUTH_SUCCESS (52) /
//     SSH_MSG_USERAUTH_BANNER (53) /
//     SSH_MSG_USERAUTH_INFO_REQUEST (60) /
//     SSH_MSG_USERAUTH_INFO_RESPONSE (61) /
//     SSH_MSG_GLOBAL_REQUEST (80) / SSH_MSG_REQUEST_SUCCESS
//     (81) / SSH_MSG_REQUEST_FAILURE (82) /
//     SSH_MSG_CHANNEL_OPEN (90) /
//     SSH_MSG_CHANNEL_OPEN_CONFIRMATION (91) /
//     SSH_MSG_CHANNEL_OPEN_FAILURE (92) /
//     SSH_MSG_CHANNEL_WINDOW_ADJUST (93) /
//     SSH_MSG_CHANNEL_DATA (94) /
//     SSH_MSG_CHANNEL_EXTENDED_DATA (95) /
//     SSH_MSG_CHANNEL_EOF (96) / SSH_MSG_CHANNEL_CLOSE (97)
//     / SSH_MSG_CHANNEL_REQUEST (98) /
//     SSH_MSG_CHANNEL_SUCCESS (99) /
//     SSH_MSG_CHANNEL_FAILURE (100).
//   - **SSH_MSG_KEXINIT decode** (RFC 4253 §7.1):
//     16-byte cookie + 10 name-lists (kex_algorithms,
//     server_host_key_algorithms, encryption_algorithms_c2s,
//     encryption_algorithms_s2c, mac_algorithms_c2s,
//     mac_algorithms_s2c, compression_algorithms_c2s,
//     compression_algorithms_s2c, languages_c2s,
//     languages_s2c) + first_kex_packet_follows + 4-byte
//     reserved.
//   - **HASSH / HASSHServer fingerprints** (Salesforce
//     spec): the colon-separated string
//     `kex_algos;encryption_algos;mac_algos;compression_algos`
//     using c2s lists for HASSH and s2c lists for
//     HASSHServer, plus the MD5 hash of each. The HASSH
//     client fingerprint identifies the SSH client stack
//     (OpenSSH version, PuTTY, libssh, JSch, ParamPro, etc.)
//     across thousands of distinct signatures.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - Encrypted body decode for post-KEXINIT packets:
//     SSH_MSG_USERAUTH_*, SSH_MSG_CHANNEL_*, and friends
//     are sent over the encrypted session. The envelope is
//     decoded but the body is surfaced as raw hex.
//   - SSH-1 protocol (deprecated since ~2006) — banner
//     parsing still works (the protocol-version field is
//     surfaced), but the binary-packet path assumes SSH-2.
//   - HASSH version of JA4 family (JA4SSH from FoxIO,
//     2023) — different algorithm; deferred until
//     real-world demand surfaces.
//   - Host-key extraction from SSH_MSG_KEXDH_REPLY — the
//     RSA/ECDSA/Ed25519 public key blob is surfaced as hex
//     but not parsed into structured form (that's a
//     separate ASN.1 walker effort).
package sshdecode

import (
	"crypto/md5" //nolint:gosec // HASSH is defined as MD5 by spec.
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Frame is the decoded view of an SSH frame. Exactly one of
// VersionBanner or BinaryPacket is non-nil per call.
type Frame struct {
	HexInput      string         `json:"hex_input,omitempty"`
	VersionBanner *VersionBanner `json:"version_banner,omitempty"`
	BinaryPacket  *BinaryPacket  `json:"binary_packet,omitempty"`
}

// VersionBanner is the decoded `SSH-...` text exchange.
type VersionBanner struct {
	Raw             string `json:"raw"`
	ProtocolVersion string `json:"protocol_version"`
	SoftwareVersion string `json:"software_version"`
	Comment         string `json:"comment,omitempty"`
}

// BinaryPacket is the decoded SSH binary-packet envelope plus
// the dispatched body.
type BinaryPacket struct {
	PacketLength   int      `json:"packet_length"`
	PaddingLength  int      `json:"padding_length"`
	PayloadLength  int      `json:"payload_length"`
	MessageType    int      `json:"message_type"`
	MessageName    string   `json:"message_name"`
	PaddingHex     string   `json:"padding_hex,omitempty"`
	TrailingMACHex string   `json:"trailing_mac_hex,omitempty"`
	PayloadBodyHex string   `json:"payload_body_hex,omitempty"`
	KEXInit        *KEXInit `json:"kex_init,omitempty"`
}

// KEXInit is the SSH_MSG_KEXINIT body.
type KEXInit struct {
	CookieHex                           string   `json:"cookie_hex"`
	KexAlgorithms                       []string `json:"kex_algorithms"`
	ServerHostKeyAlgorithms             []string `json:"server_host_key_algorithms"`
	EncryptionAlgorithmsClientToServer  []string `json:"encryption_algorithms_client_to_server"`
	EncryptionAlgorithmsServerToClient  []string `json:"encryption_algorithms_server_to_client"`
	MACAlgorithmsClientToServer         []string `json:"mac_algorithms_client_to_server"`
	MACAlgorithmsServerToClient         []string `json:"mac_algorithms_server_to_client"`
	CompressionAlgorithmsClientToServer []string `json:"compression_algorithms_client_to_server"`
	CompressionAlgorithmsServerToClient []string `json:"compression_algorithms_server_to_client"`
	LanguagesClientToServer             []string `json:"languages_client_to_server"`
	LanguagesServerToClient             []string `json:"languages_server_to_client"`
	FirstKexPacketFollows               bool     `json:"first_kex_packet_follows"`
	Reserved                            uint32   `json:"reserved"`
	HASSH                               string   `json:"hassh"`
	HASSHHash                           string   `json:"hassh_hash"`
	HASSHServer                         string   `json:"hassh_server"`
	HASSHServerHash                     string   `json:"hassh_server_hash"`
}

// Decode parses an SSH frame. Input starting with `SSH-` is
// treated as the version banner; anything else is parsed as
// a hex-encoded binary packet.
func Decode(input string) (*Frame, error) {
	s := strings.TrimRight(input, "\r\n")
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("sshdecode: empty input")
	}
	if strings.HasPrefix(s, "SSH-") {
		vb, err := parseVersionBanner(s)
		if err != nil {
			return nil, err
		}
		return &Frame{VersionBanner: vb}, nil
	}
	b, err := parseHex(s)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a raw SSH binary-packet byte slice.
func DecodeBytes(b []byte) (*Frame, error) {
	if len(b) < 6 {
		return nil, fmt.Errorf("sshdecode: binary packet too short (need at least 6 bytes, got %d)", len(b))
	}
	pktLen := int(binary.BigEndian.Uint32(b[0:4]))
	padLen := int(b[4])
	if pktLen < 1+padLen+1 {
		return nil, fmt.Errorf("sshdecode: packet length %d less than minimum (1 padlen + 1 msgtype + %d padding)", pktLen, padLen)
	}
	if 4+pktLen > len(b) {
		return nil, fmt.Errorf(
			"sshdecode: declared packet length %d exceeds buffer (%d bytes available after length field)",
			pktLen, len(b)-4)
	}
	payloadLen := pktLen - 1 - padLen
	if payloadLen < 1 {
		return nil, fmt.Errorf("sshdecode: payload length %d implies missing message type byte", payloadLen)
	}
	payload := b[5 : 5+payloadLen]
	padding := b[5+payloadLen : 5+payloadLen+padLen]
	trailing := b[4+pktLen:]
	msgType := int(payload[0])
	pkt := &BinaryPacket{
		PacketLength:   pktLen,
		PaddingLength:  padLen,
		PayloadLength:  payloadLen,
		MessageType:    msgType,
		MessageName:    messageTypeName(msgType),
		PaddingHex:     strings.ToUpper(hex.EncodeToString(padding)),
		PayloadBodyHex: strings.ToUpper(hex.EncodeToString(payload[1:])),
	}
	if len(trailing) > 0 {
		pkt.TrailingMACHex = strings.ToUpper(hex.EncodeToString(trailing))
	}
	if msgType == 20 {
		kx, err := decodeKEXInit(payload[1:])
		if err != nil {
			return nil, fmt.Errorf("sshdecode: KEXINIT: %w", err)
		}
		pkt.KEXInit = kx
		pkt.PayloadBodyHex = "" // structured form is enough
	}
	return &Frame{
		HexInput:     strings.ToUpper(hex.EncodeToString(b)),
		BinaryPacket: pkt,
	}, nil
}

// parseVersionBanner handles the SSH-protoversion-softwareversion form.
func parseVersionBanner(s string) (*VersionBanner, error) {
	vb := &VersionBanner{Raw: s}
	// Format: SSH-PROTO-SOFTWARE[ COMMENT]
	rest := strings.TrimPrefix(s, "SSH-")
	// Split off optional SP-prefixed comment.
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		vb.Comment = rest[sp+1:]
		rest = rest[:sp]
	}
	dash := strings.IndexByte(rest, '-')
	if dash < 0 {
		return nil, fmt.Errorf("version banner missing '-' between protoversion and softwareversion")
	}
	vb.ProtocolVersion = rest[:dash]
	vb.SoftwareVersion = rest[dash+1:]
	return vb, nil
}

// decodeKEXInit walks the KEXINIT body (already advanced past
// the 1-byte message type).
func decodeKEXInit(body []byte) (*KEXInit, error) {
	if len(body) < 16 {
		return nil, fmt.Errorf("KEXINIT body shorter than 16-byte cookie")
	}
	kx := &KEXInit{
		CookieHex: strings.ToUpper(hex.EncodeToString(body[:16])),
	}
	off := 16
	listSlots := []*[]string{
		&kx.KexAlgorithms,
		&kx.ServerHostKeyAlgorithms,
		&kx.EncryptionAlgorithmsClientToServer,
		&kx.EncryptionAlgorithmsServerToClient,
		&kx.MACAlgorithmsClientToServer,
		&kx.MACAlgorithmsServerToClient,
		&kx.CompressionAlgorithmsClientToServer,
		&kx.CompressionAlgorithmsServerToClient,
		&kx.LanguagesClientToServer,
		&kx.LanguagesServerToClient,
	}
	for i, slot := range listSlots {
		list, n, err := readNameList(body, off)
		if err != nil {
			return nil, fmt.Errorf("name-list %d: %w", i, err)
		}
		*slot = list
		off += n
	}
	if off < len(body) {
		kx.FirstKexPacketFollows = body[off] != 0
		off++
	}
	if off+4 <= len(body) {
		kx.Reserved = binary.BigEndian.Uint32(body[off : off+4])
	}
	kx.HASSH, kx.HASSHHash = computeHASSH(
		kx.KexAlgorithms,
		kx.EncryptionAlgorithmsClientToServer,
		kx.MACAlgorithmsClientToServer,
		kx.CompressionAlgorithmsClientToServer,
	)
	kx.HASSHServer, kx.HASSHServerHash = computeHASSH(
		kx.KexAlgorithms,
		kx.EncryptionAlgorithmsServerToClient,
		kx.MACAlgorithmsServerToClient,
		kx.CompressionAlgorithmsServerToClient,
	)
	return kx, nil
}

// readNameList reads `[len:4][bytes:len]` from body starting
// at off, returning the comma-split slice and total bytes
// consumed.
func readNameList(body []byte, off int) ([]string, int, error) {
	if off+4 > len(body) {
		return nil, 0, fmt.Errorf("truncated length prefix at offset %d", off)
	}
	length := int(binary.BigEndian.Uint32(body[off : off+4]))
	if off+4+length > len(body) {
		return nil, 0, fmt.Errorf("declared length %d exceeds remaining buffer (%d bytes)", length, len(body)-off-4)
	}
	if length == 0 {
		return nil, 4, nil
	}
	s := string(body[off+4 : off+4+length])
	return strings.Split(s, ","), 4 + length, nil
}

// computeHASSH builds the HASSH fingerprint string + MD5
// hash per https://github.com/salesforce/hassh. Format:
// `kex;encryption;mac;compression` (semicolon-separated,
// each list comma-separated as on the wire).
func computeHASSH(kex, encryption, mac, compression []string) (string, string) {
	str := strings.Join(kex, ",") + ";" +
		strings.Join(encryption, ",") + ";" +
		strings.Join(mac, ",") + ";" +
		strings.Join(compression, ",")
	sum := md5.Sum([]byte(str)) //nolint:gosec // HASSH defines MD5.
	return str, hex.EncodeToString(sum[:])
}

func messageTypeName(t int) string {
	switch t {
	case 1:
		return "SSH_MSG_DISCONNECT"
	case 2:
		return "SSH_MSG_IGNORE"
	case 3:
		return "SSH_MSG_UNIMPLEMENTED"
	case 4:
		return "SSH_MSG_DEBUG"
	case 5:
		return "SSH_MSG_SERVICE_REQUEST"
	case 6:
		return "SSH_MSG_SERVICE_ACCEPT"
	case 7:
		return "SSH_MSG_EXT_INFO"
	case 8:
		return "SSH_MSG_NEWCOMPRESS"
	case 20:
		return "SSH_MSG_KEXINIT"
	case 21:
		return "SSH_MSG_NEWKEYS"
	case 30:
		return "SSH_MSG_KEXDH_INIT (or KEXECDH_INIT / KEX_ECDH_INIT)"
	case 31:
		return "SSH_MSG_KEXDH_REPLY (or KEXECDH_REPLY)"
	case 50:
		return "SSH_MSG_USERAUTH_REQUEST"
	case 51:
		return "SSH_MSG_USERAUTH_FAILURE"
	case 52:
		return "SSH_MSG_USERAUTH_SUCCESS"
	case 53:
		return "SSH_MSG_USERAUTH_BANNER"
	case 60:
		return "SSH_MSG_USERAUTH_INFO_REQUEST (or PK_OK / PASSWD_CHANGEREQ)"
	case 61:
		return "SSH_MSG_USERAUTH_INFO_RESPONSE"
	case 80:
		return "SSH_MSG_GLOBAL_REQUEST"
	case 81:
		return "SSH_MSG_REQUEST_SUCCESS"
	case 82:
		return "SSH_MSG_REQUEST_FAILURE"
	case 90:
		return "SSH_MSG_CHANNEL_OPEN"
	case 91:
		return "SSH_MSG_CHANNEL_OPEN_CONFIRMATION"
	case 92:
		return "SSH_MSG_CHANNEL_OPEN_FAILURE"
	case 93:
		return "SSH_MSG_CHANNEL_WINDOW_ADJUST"
	case 94:
		return "SSH_MSG_CHANNEL_DATA"
	case 95:
		return "SSH_MSG_CHANNEL_EXTENDED_DATA"
	case 96:
		return "SSH_MSG_CHANNEL_EOF"
	case 97:
		return "SSH_MSG_CHANNEL_CLOSE"
	case 98:
		return "SSH_MSG_CHANNEL_REQUEST"
	case 99:
		return "SSH_MSG_CHANNEL_SUCCESS"
	case 100:
		return "SSH_MSG_CHANNEL_FAILURE"
	}
	return fmt.Sprintf("Unknown message type %d", t)
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("sshdecode: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("sshdecode: invalid hex: %w", err)
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
