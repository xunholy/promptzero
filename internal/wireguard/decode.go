// Package wireguard decodes WireGuard UDP packets per the
// official protocol specification at
// https://www.wireguard.com/protocol/.
//
// Wrap-vs-native judgement
//
//	Native. The WireGuard wire format is a tight fixed-
//	layout binary header with a documented set of four
//	message types. There are no variable-length integers,
//	no version negotiation, no extensions, and no
//	compression at this layer. Operators paste UDP payload
//	bytes from a Wireshark wg dissector, an `iptables -j
//	LOG` capture, or any `tcpdump -X udp port 51820` line
//	and inspect every documented field. Pure offline parser.
//	The cryptographic primitives (Curve25519, Blake2s,
//	ChaCha20Poly1305, XChaCha20Poly1305) are NOT decoded —
//	encrypted material is surfaced as hex for traceability,
//	and decryption belongs in a separate Spec.
//
// What this package covers
//
//   - Auto-detect by leading message-type byte: 0x01
//     Handshake Initiation, 0x02 Handshake Response, 0x03
//     Cookie Reply, 0x04 Transport Data. The 3 reserved
//     bytes after the type are required to be zero per spec
//     — non-zero values are surfaced as a note (some
//     middleboxes / forks abuse them).
//
//   - **Handshake Initiation** (148 bytes fixed): sender
//     index (u32 LE) + unencrypted ephemeral Curve25519
//     public key (32 bytes) + encrypted static key (32+16
//     AEAD) + encrypted timestamp (12+16 AEAD) + MAC1 (16
//     bytes Blake2s(MAC1_key || msg)) + MAC2 (16 bytes,
//     zero when no cookie).
//
//   - **Handshake Response** (92 bytes fixed): sender index
//
//   - receiver index + unencrypted ephemeral key (32 bytes)
//
//   - encrypted nothing (0+16 AEAD — proves the static
//     keypair was used) + MAC1 + MAC2.
//
//   - **Cookie Reply** (64 bytes fixed): receiver index +
//     nonce (24 bytes XChaCha20Poly1305) + encrypted cookie
//     (16+16 AEAD).
//
//   - **Transport Data** (variable, ≥ 32 bytes): receiver
//     index + counter (u64 LE — increments per direction;
//     replay-protection nonce) + encrypted encapsulated
//     packet (≥0 bytes plaintext IP packet + 16-byte
//     Poly1305 tag). Surfaces the payload length as the
//     inner-IP-packet length minus the 16-byte tag.
//
//   - MAC2 detection: the all-zero pattern is recognised and
//     flagged as "no cookie applied" — clients only populate
//     MAC2 after they receive a Cookie Reply.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - Decryption — operators need the static + ephemeral key
//     material plus the noise-IK handshake state. A separate
//     Spec would handle the symmetric layer.
//
//   - Noise IK handshake state machine — we surface what's
//     on the wire; reconstructing the chain of derived keys
//     is a session-tracker's job.
//
//   - UDP / IP framing — feed the UDP payload bytes after
//     the IP+UDP headers (or after a Wireshark Follow UDP
//     Stream extraction).
//
//   - MAC1 / MAC2 verification — would require the
//     responder's static public key. The values are surfaced
//     so an operator with the key can re-derive and verify.
//
//   - Cookie reply re-derivation (Blake2s of source IP +
//     port + responder mac1_key) — same reason.
package wireguard

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	MessageType     int    `json:"message_type"`
	MessageTypeName string `json:"message_type_name"`
	TotalBytes      int    `json:"total_bytes"`
	ReservedZero    bool   `json:"reserved_zero"`
	ReservedHex     string `json:"reserved_hex,omitempty"`

	Initiation *Initiation `json:"initiation,omitempty"`
	Response   *Response   `json:"response,omitempty"`
	Cookie     *Cookie     `json:"cookie_reply,omitempty"`
	Transport  *Transport  `json:"transport,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// Initiation is the body of message type 1.
type Initiation struct {
	SenderIndex           uint32 `json:"sender_index"`
	SenderIndexHex        string `json:"sender_index_hex"`
	EphemeralPubKeyHex    string `json:"unencrypted_ephemeral_pubkey_hex"`
	EncryptedStaticHex    string `json:"encrypted_static_hex"`
	EncryptedTimestampHex string `json:"encrypted_timestamp_hex"`
	MAC1Hex               string `json:"mac1_hex"`
	MAC2Hex               string `json:"mac2_hex"`
	MAC2Zero              bool   `json:"mac2_zero"`
}

// Response is the body of message type 2.
type Response struct {
	SenderIndex         uint32 `json:"sender_index"`
	SenderIndexHex      string `json:"sender_index_hex"`
	ReceiverIndex       uint32 `json:"receiver_index"`
	ReceiverIndexHex    string `json:"receiver_index_hex"`
	EphemeralPubKeyHex  string `json:"unencrypted_ephemeral_pubkey_hex"`
	EncryptedNothingHex string `json:"encrypted_nothing_hex"`
	MAC1Hex             string `json:"mac1_hex"`
	MAC2Hex             string `json:"mac2_hex"`
	MAC2Zero            bool   `json:"mac2_zero"`
}

// Cookie is the body of message type 3.
type Cookie struct {
	ReceiverIndex    uint32 `json:"receiver_index"`
	ReceiverIndexHex string `json:"receiver_index_hex"`
	NonceHex         string `json:"nonce_hex"`
	EncryptedCookie  string `json:"encrypted_cookie_hex"`
}

// Transport is the body of message type 4.
type Transport struct {
	ReceiverIndex       uint32 `json:"receiver_index"`
	ReceiverIndexHex    string `json:"receiver_index_hex"`
	Counter             uint64 `json:"counter"`
	EncryptedPayloadHex string `json:"encrypted_payload_hex,omitempty"`
	EncryptedPayloadLen int    `json:"encrypted_payload_length"`
	InnerPlaintextLen   int    `json:"inner_plaintext_length_inferred"`
	KeepAlive           bool   `json:"keep_alive,omitempty"`
}

// Decode parses a WireGuard datagram from hex.
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
		return nil, fmt.Errorf("datagram too short (%d bytes; need ≥4 for type+reserved)",
			len(b))
	}

	r := &Result{
		MessageType:  int(b[0]),
		TotalBytes:   len(b),
		ReservedHex:  strings.ToUpper(hex.EncodeToString(b[1:4])),
		ReservedZero: b[1] == 0 && b[2] == 0 && b[3] == 0,
	}
	r.MessageTypeName = messageTypeName(r.MessageType)

	if !r.ReservedZero {
		r.Notes = append(r.Notes,
			fmt.Sprintf("reserved bytes are non-zero (%s); WireGuard spec requires "+
				"these to be zero — some middleboxes / forks abuse the field",
				r.ReservedHex))
	}

	switch r.MessageType {
	case 1:
		if len(b) != 148 {
			return nil, fmt.Errorf("handshake initiation must be 148 bytes, got %d",
				len(b))
		}
		init, err := decodeInitiation(b)
		if err != nil {
			return nil, err
		}
		r.Initiation = init
		if init.MAC2Zero {
			r.Notes = append(r.Notes,
				"MAC2 is all zero — no cookie has been applied; this is a fresh "+
					"initiation (no prior Cookie Reply received)")
		}
	case 2:
		if len(b) != 92 {
			return nil, fmt.Errorf("handshake response must be 92 bytes, got %d", len(b))
		}
		resp, err := decodeResponse(b)
		if err != nil {
			return nil, err
		}
		r.Response = resp
		if resp.MAC2Zero {
			r.Notes = append(r.Notes,
				"MAC2 is all zero — no cookie applied")
		}
	case 3:
		if len(b) != 64 {
			return nil, fmt.Errorf("cookie reply must be 64 bytes, got %d", len(b))
		}
		c, err := decodeCookie(b)
		if err != nil {
			return nil, err
		}
		r.Cookie = c
	case 4:
		if len(b) < 32 {
			return nil, fmt.Errorf("transport packet must be ≥32 bytes "+
				"(4 type+reserved + 4 receiver_index + 8 counter + 16 AEAD tag), got %d",
				len(b))
		}
		tr, err := decodeTransport(b)
		if err != nil {
			return nil, err
		}
		r.Transport = tr
		if tr.InnerPlaintextLen == 0 {
			tr.KeepAlive = true
			r.Notes = append(r.Notes,
				"inner plaintext is empty (only the 16-byte Poly1305 tag is present) — "+
					"this is a keep-alive packet (sent every 25 seconds when idle)")
		}
	default:
		return nil, fmt.Errorf("unknown WireGuard message type 0x%02X (valid: 1-4)",
			r.MessageType)
	}

	return r, nil
}

func decodeInitiation(b []byte) (*Initiation, error) {
	init := &Initiation{
		SenderIndex:           binary.LittleEndian.Uint32(b[4:8]),
		EphemeralPubKeyHex:    strings.ToUpper(hex.EncodeToString(b[8:40])),
		EncryptedStaticHex:    strings.ToUpper(hex.EncodeToString(b[40:88])),
		EncryptedTimestampHex: strings.ToUpper(hex.EncodeToString(b[88:116])),
		MAC1Hex:               strings.ToUpper(hex.EncodeToString(b[116:132])),
		MAC2Hex:               strings.ToUpper(hex.EncodeToString(b[132:148])),
	}
	init.SenderIndexHex = fmt.Sprintf("0x%08X", init.SenderIndex)
	init.MAC2Zero = allZero(b[132:148])
	return init, nil
}

func decodeResponse(b []byte) (*Response, error) {
	resp := &Response{
		SenderIndex:         binary.LittleEndian.Uint32(b[4:8]),
		ReceiverIndex:       binary.LittleEndian.Uint32(b[8:12]),
		EphemeralPubKeyHex:  strings.ToUpper(hex.EncodeToString(b[12:44])),
		EncryptedNothingHex: strings.ToUpper(hex.EncodeToString(b[44:60])),
		MAC1Hex:             strings.ToUpper(hex.EncodeToString(b[60:76])),
		MAC2Hex:             strings.ToUpper(hex.EncodeToString(b[76:92])),
	}
	resp.SenderIndexHex = fmt.Sprintf("0x%08X", resp.SenderIndex)
	resp.ReceiverIndexHex = fmt.Sprintf("0x%08X", resp.ReceiverIndex)
	resp.MAC2Zero = allZero(b[76:92])
	return resp, nil
}

func decodeCookie(b []byte) (*Cookie, error) {
	c := &Cookie{
		ReceiverIndex:   binary.LittleEndian.Uint32(b[4:8]),
		NonceHex:        strings.ToUpper(hex.EncodeToString(b[8:32])),
		EncryptedCookie: strings.ToUpper(hex.EncodeToString(b[32:64])),
	}
	c.ReceiverIndexHex = fmt.Sprintf("0x%08X", c.ReceiverIndex)
	return c, nil
}

func decodeTransport(b []byte) (*Transport, error) {
	tr := &Transport{
		ReceiverIndex:       binary.LittleEndian.Uint32(b[4:8]),
		Counter:             binary.LittleEndian.Uint64(b[8:16]),
		EncryptedPayloadLen: len(b) - 16,
		InnerPlaintextLen:   len(b) - 16 - 16, // total - header - AEAD tag.
	}
	tr.ReceiverIndexHex = fmt.Sprintf("0x%08X", tr.ReceiverIndex)
	if len(b) > 16 {
		payload := b[16:]
		if len(payload) > 256 {
			tr.EncryptedPayloadHex = strings.ToUpper(hex.EncodeToString(payload[:256])) +
				"..."
		} else {
			tr.EncryptedPayloadHex = strings.ToUpper(hex.EncodeToString(payload))
		}
	}
	if tr.InnerPlaintextLen < 0 {
		tr.InnerPlaintextLen = 0
	}
	return tr, nil
}

func messageTypeName(t int) string {
	switch t {
	case 1:
		return "Handshake Initiation"
	case 2:
		return "Handshake Response"
	case 3:
		return "Cookie Reply"
	case 4:
		return "Transport Data"
	}
	return fmt.Sprintf("Unknown (0x%02X)", t)
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
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
