// Package wsframe decodes WebSocket frames per RFC 6455.
//
// Wrap-vs-native judgement
//
//	Native. RFC 6455 is fully public; the wire format is a
//	tight bit-packed header (FIN/RSV/opcode/MASK/payload-len)
//	with two variable-length escape hatches (extended 16-bit
//	and extended 64-bit payload length) and an optional
//	4-byte mask key. The walker handles fragmentation
//	(Continuation opcode 0x0 after a Text/Binary opener) and
//	demasks payload bytes when the MASK bit is set
//	(client→server frames per §5.3 must be masked).
//	Operators paste WebSocket frame bytes from a mitmproxy /
//	wsdump / Chrome DevTools Network panel export and inspect
//	every documented field. Pure offline parser — no
//	transport, no hardware.
//
// What this package covers
//
//   - Frame header (2 bytes minimum):
//     byte 0: FIN | RSV1 | RSV2 | RSV3 | opcode (4)
//     byte 1: MASK | payload-len (7)
//
//   - Extended payload length: when payload-len == 126, the
//     next 2 bytes are the actual length (uint16 BE); when
//     payload-len == 127, the next 8 bytes are the actual
//     length (uint64 BE).
//
//   - Mask key: 4 bytes immediately after the length field
//     when MASK == 1. Per RFC 6455 §5.3, every client→server
//     frame MUST be masked; server→client frames MUST NOT be
//     masked.
//
//   - Opcodes (RFC 6455 §11.8):
//     0x0 Continuation
//     0x1 Text (UTF-8)
//     0x2 Binary
//     0x3-0x7 reserved (non-control)
//     0x8 Close
//     0x9 Ping
//     0xA Pong
//     0xB-0xF reserved (control)
//
//   - Payload demasking: when MASK == 1, each payload byte
//     b[i] is XORed with maskKey[i%4] to recover plaintext.
//
//   - Close frame body (opcode 0x8): first 2 bytes are a
//     uint16 BE status code (RFC 6455 §7.4.1), remaining
//     bytes are optional UTF-8 reason text. The status-code
//     table covers documented 1xxx codes (1000-1015) plus
//     the user/library ranges (3000-3999 / 4000-4999).
//
//   - Text/Binary frame body: text is surfaced as a string
//     when the bytes are valid UTF-8 and free of control
//     characters; otherwise as uppercase hex. Binary frames
//     always surface as uppercase hex.
//
//   - Multi-frame buffer walking: a single buffer may carry
//     several concatenated frames (server→client streams
//     often do this). The walker iterates frame-by-frame
//     until the buffer is consumed and surfaces a summary
//     of opcodes seen.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - HTTP/1.x Upgrade handshake (Sec-WebSocket-Key / Accept
//     / Version / Extensions / Protocol) — already handled
//     by internal/httpmsg (the Upgrade headers are preserved
//     verbatim; this package starts at the first frame after
//     the 101 Switching Protocols response).
//
//   - Per-message Deflate (RFC 7692) — RSV1 indicates that
//     the payload is permessage-deflate compressed; we
//     surface RSV1=true and the raw (still-compressed)
//     payload as hex. Operators who need cleartext can pipe
//     the bytes through their own decompressor.
//
//   - Subprotocols (e.g. MQTT-over-WebSocket, STOMP,
//     graphql-ws) — opcode 0x1/0x2 payloads are surfaced as
//     text or hex; subprotocol-specific framing belongs in a
//     sibling helper.
//
//   - Statefulness across frames — fragmentation is detected
//     (FIN=0 + opcode!=0 on opener; FIN=0/1 + opcode=0 on
//     continuation) and surfaced in each frame's flags, but
//     the package does not reassemble continuation chains
//     into a single logical message.
package wsframe

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Result is the top-level decoded view.
type Result struct {
	Frames     []Frame `json:"frames"`
	FrameCount int     `json:"frame_count"`
	TotalBytes int     `json:"total_bytes"`
	Summary    string  `json:"summary"`
}

// Frame is one decoded WebSocket frame.
type Frame struct {
	FIN            bool       `json:"fin"`
	RSV1           bool       `json:"rsv1"`
	RSV2           bool       `json:"rsv2"`
	RSV3           bool       `json:"rsv3"`
	Opcode         int        `json:"opcode"`
	OpcodeName     string     `json:"opcode_name"`
	IsControl      bool       `json:"is_control"`
	Masked         bool       `json:"masked"`
	PayloadLenRaw  int        `json:"payload_len_raw"`
	PayloadLength  uint64     `json:"payload_length"`
	MaskKey        string     `json:"mask_key,omitempty"`
	HeaderBytes    int        `json:"header_bytes"`
	FrameBytes     int        `json:"frame_bytes"`
	PayloadHex     string     `json:"payload_hex,omitempty"`
	PayloadHexClip bool       `json:"payload_hex_truncated,omitempty"`
	PayloadText    string     `json:"payload_text,omitempty"`
	Close          *CloseInfo `json:"close,omitempty"`
	Notes          []string   `json:"notes,omitempty"`
}

// CloseInfo is the parsed Close-frame body (opcode 0x8).
type CloseInfo struct {
	StatusCode int    `json:"status_code"`
	StatusName string `json:"status_name"`
	Reason     string `json:"reason,omitempty"`
}

// Decode parses a buffer of one or more concatenated WebSocket
// frames from hex.
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
		return nil, fmt.Errorf("buffer too short (%d bytes; need ≥2 for a header)", len(b))
	}

	var frames []Frame
	off := 0
	for off < len(b) {
		f, used, err := parseFrame(b[off:])
		if err != nil {
			return nil, fmt.Errorf("frame %d at offset %d: %w", len(frames), off, err)
		}
		frames = append(frames, *f)
		off += used
	}

	summary := make([]string, 0, len(frames))
	for _, f := range frames {
		summary = append(summary, f.OpcodeName)
	}
	return &Result{
		Frames:     frames,
		FrameCount: len(frames),
		TotalBytes: len(b),
		Summary:    strings.Join(summary, " + "),
	}, nil
}

func parseFrame(b []byte) (*Frame, int, error) {
	if len(b) < 2 {
		return nil, 0, fmt.Errorf("header truncated (%d bytes; need ≥2)", len(b))
	}
	f := &Frame{
		FIN:           (b[0]>>7)&1 == 1,
		RSV1:          (b[0]>>6)&1 == 1,
		RSV2:          (b[0]>>5)&1 == 1,
		RSV3:          (b[0]>>4)&1 == 1,
		Opcode:        int(b[0] & 0x0F),
		Masked:        (b[1]>>7)&1 == 1,
		PayloadLenRaw: int(b[1] & 0x7F),
	}
	f.OpcodeName = opcodeName(f.Opcode)
	f.IsControl = f.Opcode >= 0x8

	off := 2
	switch f.PayloadLenRaw {
	case 126:
		if len(b) < off+2 {
			return nil, 0, fmt.Errorf("extended 16-bit length truncated")
		}
		f.PayloadLength = uint64(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
	case 127:
		if len(b) < off+8 {
			return nil, 0, fmt.Errorf("extended 64-bit length truncated")
		}
		v := binary.BigEndian.Uint64(b[off : off+8])
		if v&(1<<63) != 0 {
			return nil, 0, fmt.Errorf("extended 64-bit length has MSB set (RFC 6455 §5.2)")
		}
		f.PayloadLength = v
		off += 8
	default:
		f.PayloadLength = uint64(f.PayloadLenRaw)
	}

	if f.IsControl {
		if f.PayloadLength > 125 {
			return nil, 0, fmt.Errorf("control frame payload %d exceeds 125 (RFC 6455 §5.5)",
				f.PayloadLength)
		}
		if !f.FIN {
			return nil, 0, fmt.Errorf("control frame must not be fragmented (RFC 6455 §5.5)")
		}
	}

	if f.Masked {
		if len(b) < off+4 {
			return nil, 0, fmt.Errorf("mask key truncated")
		}
		f.MaskKey = strings.ToUpper(hex.EncodeToString(b[off : off+4]))
		off += 4
	}

	f.HeaderBytes = off
	end := off + int(f.PayloadLength)
	if uint64(end) < f.PayloadLength || end < off { // overflow guard
		return nil, 0, fmt.Errorf("payload length overflow")
	}
	if end > len(b) {
		return nil, 0, fmt.Errorf("payload truncated (declared %d, have %d)",
			f.PayloadLength, len(b)-off)
	}

	payload := make([]byte, f.PayloadLength)
	copy(payload, b[off:end])
	if f.Masked {
		mk, _ := hex.DecodeString(f.MaskKey)
		for i := range payload {
			payload[i] ^= mk[i%4]
		}
	}
	f.FrameBytes = end

	switch f.Opcode {
	case 0x1: // Text
		f.PayloadText, f.PayloadHex = renderText(payload)
	case 0x8: // Close
		f.Close = decodeClose(payload)
		if len(payload) > 0 {
			f.PayloadHex = upperHex(payload)
		}
	default:
		// Binary, Continuation, Ping, Pong, Reserved.
		if len(payload) > 0 {
			f.PayloadHex = upperHex(clipHex(payload, 256, &f.PayloadHexClip))
			if f.Opcode == 0x9 || f.Opcode == 0xA {
				// Ping/Pong commonly carry text echoes — try
				// to surface a readable view if printable.
				if txt, ok := tryText(payload); ok {
					f.PayloadText = txt
				}
			}
		}
	}

	if f.RSV1 {
		f.Notes = append(f.Notes,
			"RSV1 set — payload may be permessage-deflate compressed (RFC 7692); "+
				"raw bytes surfaced as-is")
	}
	if f.RSV2 || f.RSV3 {
		f.Notes = append(f.Notes,
			"RSV2/RSV3 set — extension-defined semantics")
	}
	if !f.FIN && !f.IsControl {
		f.Notes = append(f.Notes,
			"FIN=0 — this is part of a fragmented message; a Continuation (opcode 0x0) "+
				"with FIN=1 will close it")
	}
	if f.Opcode == 0x0 {
		f.Notes = append(f.Notes,
			"Continuation frame — payload continues the message opened by the "+
				"prior non-zero opcode")
	}

	return f, end, nil
}

func decodeClose(payload []byte) *CloseInfo {
	c := &CloseInfo{}
	if len(payload) == 0 {
		c.StatusCode = -1
		c.StatusName = "no status code (empty Close body)"
		return c
	}
	if len(payload) < 2 {
		c.StatusCode = -1
		c.StatusName = "malformed (Close body must be empty or ≥2 bytes)"
		return c
	}
	c.StatusCode = int(binary.BigEndian.Uint16(payload[:2]))
	c.StatusName = closeStatusName(c.StatusCode)
	if len(payload) > 2 {
		reason := payload[2:]
		if utf8.Valid(reason) {
			c.Reason = string(reason)
		} else {
			c.Reason = upperHex(reason)
		}
	}
	return c
}

func opcodeName(op int) string {
	switch op {
	case 0x0:
		return "Continuation"
	case 0x1:
		return "Text"
	case 0x2:
		return "Binary"
	case 0x8:
		return "Close"
	case 0x9:
		return "Ping"
	case 0xA:
		return "Pong"
	}
	if op >= 0x3 && op <= 0x7 {
		return fmt.Sprintf("Reserved non-control (0x%X)", op)
	}
	if op >= 0xB && op <= 0xF {
		return fmt.Sprintf("Reserved control (0x%X)", op)
	}
	return fmt.Sprintf("Unknown opcode (0x%X)", op)
}

func closeStatusName(code int) string {
	switch code {
	case 1000:
		return "Normal Closure"
	case 1001:
		return "Going Away"
	case 1002:
		return "Protocol Error"
	case 1003:
		return "Unsupported Data"
	case 1004:
		return "Reserved (1004)"
	case 1005:
		return "No Status Rcvd (reserved — must not be sent on the wire)"
	case 1006:
		return "Abnormal Closure (reserved — must not be sent on the wire)"
	case 1007:
		return "Invalid Frame Payload Data"
	case 1008:
		return "Policy Violation"
	case 1009:
		return "Message Too Big"
	case 1010:
		return "Mandatory Extension"
	case 1011:
		return "Internal Error"
	case 1012:
		return "Service Restart"
	case 1013:
		return "Try Again Later"
	case 1014:
		return "Bad Gateway"
	case 1015:
		return "TLS Handshake (reserved — must not be sent on the wire)"
	}
	switch {
	case code >= 3000 && code <= 3999:
		return fmt.Sprintf("Library/framework-defined (%d, IANA-registered)", code)
	case code >= 4000 && code <= 4999:
		return fmt.Sprintf("Application-defined (%d, private use)", code)
	case code >= 1016 && code <= 2999:
		return fmt.Sprintf("Reserved for future IETF use (%d)", code)
	}
	return fmt.Sprintf("Out-of-range status code (%d)", code)
}

func renderText(b []byte) (text, hexFallback string) {
	if utf8.Valid(b) {
		for _, c := range b {
			if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
				return "", upperHex(b)
			}
		}
		return string(b), ""
	}
	return "", upperHex(b)
}

func tryText(b []byte) (string, bool) {
	if !utf8.Valid(b) {
		return "", false
	}
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return "", false
		}
	}
	return string(b), true
}

func clipHex(b []byte, max int, clipped *bool) []byte {
	if len(b) > max {
		*clipped = true
		return b[:max]
	}
	return b
}

func upperHex(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
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
