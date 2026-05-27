// Package rtmp decodes RTMP (Real-Time Messaging Protocol) wire
// frames. Originally developed by Macromedia/Adobe for Flash;
// still the dominant live-streaming ingest protocol on TCP/1935
// (default). Widely used by OBS Studio, Twitch, YouTube Live,
// Facebook Live, Nginx-RTMP, Wowza, SRS (Simple Realtime Server).
//
// Operationally, RTMP is a **high-value live-streaming ingest
// target** — stream keys transmitted in cleartext. Stream keys
// are effectively authentication tokens for live-streaming
// platforms; capturing one lets an attacker broadcast arbitrary
// content to the victim's channel.
//
// The wire format leaks:
//
//   - **Handshake version via C0/S0** — first byte is the RTMP
//     version: 0x03 = plaintext RTMP; 0x06 = RTMPE (encrypted
//     RTMP using Diffie-Hellman). The C1/S1 blocks that follow
//     contain a 4-byte timestamp plus 1528 bytes of random data.
//
//   - **Application name and server URL via AMF0 "connect"
//     command (message type 20)** — the first AMF0 command sent
//     by any RTMP client is "connect"; its argument object
//     contains "app" (the application name, e.g. "live"),
//     "tcUrl" (the full RTMP URL, e.g. "rtmp://server/live"),
//     "flashVer" (client version string), "swfUrl", "pageUrl".
//     The tcUrl often contains auth tokens or stream keys
//     embedded as query parameters.
//
//   - **Stream keys via "publish" command** — when a client
//     starts publishing, it sends an AMF0 Command Message
//     (type 20) with command name "publish"; the second string
//     argument is the stream name / stream key, transmitted in
//     cleartext. Stream keys are auth tokens for Twitch / YouTube
//     Live / Facebook Live / Wowza / Nginx-RTMP.
//
//   - **Stream name via "play" command** — consumer clients send
//     "play" with the stream name as the second argument.
//
//   - **RTMPE (version 0x06) uses Diffie-Hellman key exchange**
//     but has known implementation weaknesses. Standard RTMP
//     (version 0x03) is entirely cleartext.
//
//   - **Protocol control message types 1-6** — Set Chunk Size
//     (1), Abort (2), Acknowledgement (3), User Control (4),
//     Window Acknowledgement Size (5), Set Peer Bandwidth (6).
//     These reveal session-layer parameters.
//
//   - **Audio (type 8) and Video (type 9) message streams** —
//     identified by message type; payload not decoded.
//
// Wrap-vs-native judgement
//
//	Native. The RTMP specification is publicly available (Adobe
//	RTMP Specification 1.0, December 2012). The chunk format
//	is a deterministic binary layout with no crypto at the
//	parse layer for standard RTMP 0x03. RTMPE (0x06) is
//	detected but not decrypted. AMF0 command parsing is
//	limited to extracting the command name string and
//	best-effort extraction of the "app" and "tcUrl" fields
//	from the following AMF0 object.
//
// What this package covers
//
//   - **C0+C1 / S0+S1 handshake detection** — leading byte is
//     the RTMP version (0x03 or 0x06), followed by 1536 bytes.
//     Surfaces `is_handshake`, `handshake_version`,
//     `is_encrypted`.
//
//   - **RTMP chunk header walker** — basic_header (1-3 bytes):
//     fmt (2 bits) + cs_id (6 bits / 1-byte extended / 2-byte LE
//     extended). Message header per fmt: fmt 0 (11 bytes:
//     timestamp 3 BE + message_length 3 BE + message_type_id 1 +
//     message_stream_id 4 LE); fmt 1 (7 bytes: timestamp_delta 3
//
//   - message_length 3 + message_type_id 1); fmt 2 (3 bytes:
//     timestamp_delta 3); fmt 3 (0 bytes). Extended timestamp
//     (4 BE) if timestamp/delta == 0xFFFFFF.
//
//   - **17-entry message type name table**: Set Chunk Size (1) /
//     Abort (2) / Acknowledgement (3) / User Control (4) /
//     Window Acknowledgement Size (5) / Set Peer Bandwidth (6) /
//     Audio (8) / Video (9) / Data AMF3 (15) / Shared Object
//     AMF3 (17) / Data AMF0 (18) / Shared Object AMF0 (19) /
//     Command AMF0 (20) / Aggregate (22).
//
//   - **AMF0 Command Message walker (type 20)** — extracts the
//     command name from the first AMF0 string marker (0x02 +
//     2-byte BE length + data). Key commands: connect /
//     createStream / play / publish / deleteStream / FCPublish /
//     releaseStream / onStatus / _result / _error.
//
//   - **"connect" command argument extraction** — best-effort
//     scan for AMF0 object keys "app" and "tcUrl" following the
//     command name; surfaces `app_name` and `tc_url`.
//
//   - **Classification booleans**: `is_connect`, `is_play`,
//     `is_publish`, `is_audio`, `is_video`, `is_control_message`.
//
//   - **User Control Message event type decoder (message type
//     4)** — 6-entry event type name table: StreamBegin (0) /
//     StreamEOF (1) / StreamDry (2) / SetBufferLength (3) /
//     StreamIsRecorded (4) / PingRequest (6) / PingResponse (7).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **RTMPE decryption** — RTMPE (version 0x06) uses a
//     Diffie-Hellman key exchange; the decoder detects it but
//     does NOT decrypt. The DH exchange details are complex
//     and intentionally out of scope.
//   - **Full AMF0 / AMF3 parser** — only the command name string
//     and best-effort "app"/"tcUrl" extraction are implemented.
//     Full AMF0 value types (numbers, booleans, objects, arrays,
//     dates) and AMF3 are not parsed.
//   - **Multi-chunk message reassembly** — large messages span
//     multiple chunks; the decoder parses the first chunk header
//     only.
//   - **RTMPS (TLS-wrapped RTMP, TCP/443)** — handle TLS strip
//     first.
//   - **RTMPT (HTTP-tunneled RTMP)** — handle HTTP layer
//     separately.
//   - **Audio/Video payload decoding** — H.264/AAC/FLV codec
//     payloads are out of scope.
package rtmp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of an RTMP wire-protocol frame.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Handshake fields (C0+C1 or S0+S1)
	IsHandshake      bool `json:"is_handshake"`
	HandshakeVersion int  `json:"handshake_version,omitempty"`
	IsEncrypted      bool `json:"is_encrypted"`

	// Chunk header fields
	Fmt             int    `json:"fmt,omitempty"`
	ChunkStreamID   int    `json:"cs_id,omitempty"`
	Timestamp       int    `json:"timestamp,omitempty"`
	MessageLength   int    `json:"message_length,omitempty"`
	MessageTypeID   int    `json:"message_type_id,omitempty"`
	MessageTypeName string `json:"message_type_name,omitempty"`
	MessageStreamID int    `json:"message_stream_id,omitempty"`

	// AMF0 Command Message (type 20)
	CommandName string `json:"command_name,omitempty"`

	// "connect" command extracted fields
	AppName  string `json:"app_name,omitempty"`
	TcURL    string `json:"tc_url,omitempty"`
	FlashVer string `json:"flash_ver,omitempty"`

	// Classification booleans
	IsConnect        bool `json:"is_connect"`
	IsPlay           bool `json:"is_play"`
	IsPublish        bool `json:"is_publish"`
	IsAudio          bool `json:"is_audio"`
	IsVideo          bool `json:"is_video"`
	IsControlMessage bool `json:"is_control_message"`

	// User Control Message event (type 4)
	UserControlEventType int    `json:"user_control_event_type,omitempty"`
	UserControlEventName string `json:"user_control_event_name,omitempty"`
}

// handshakeSize is the C0+C1 / S0+S1 handshake block size:
// 1 (version byte) + 1536 (timestamp 4 + zero 4 + random 1528).
const handshakeSize = 1537

// Decode parses an RTMP wire-protocol frame from a hex string.
// It auto-discriminates between handshake blocks (C0+C1 / S0+S1)
// and post-handshake chunk headers by inspecting the buffer length
// and leading byte:
//
//   - Exactly 1537 bytes with leading 0x03 or 0x06 → handshake.
//   - All other inputs → RTMP chunk header.
//
// The discrimination uses the exact 1537-byte size to avoid the
// fmt=0 / cs_id=3 ambiguity (chunk basic-header byte 0x03 is also
// a valid first byte for a chunk with fmt=0 and cs_id=3).
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
	if len(b) < 2 {
		return nil, fmt.Errorf("rtmp frame truncated (%d bytes; need at least 2)", len(b))
	}

	r := &Result{TotalBytes: len(b)}

	// Handshake detection: require exactly 1537 bytes (full C0+C1 or
	// S0+S1 block) with the version byte 0x03 (plaintext RTMP) or
	// 0x06 (RTMPE). Using the exact size avoids false-positive
	// classification of short post-handshake chunks whose basic-header
	// byte happens to be 0x03 (fmt=0, cs_id=3).
	if len(b) == handshakeSize &&
		(b[0] == 0x03 || b[0] == 0x06) {
		r.IsHandshake = true
		r.HandshakeVersion = int(b[0])
		r.IsEncrypted = b[0] == 0x06
		return r, nil
	}

	// Post-handshake chunk header parsing.
	return decodeChunk(r, b)
}

// decodeChunk parses an RTMP chunk header from b.
func decodeChunk(r *Result, b []byte) (*Result, error) {
	off := 0

	// Basic header byte 0: fmt (bits 7-6) + cs_id_raw (bits 5-0).
	basicByte := b[off]
	off++
	fmt0 := int(basicByte >> 6)
	csIDRaw := int(basicByte & 0x3F)
	r.Fmt = fmt0

	// cs_id extended forms.
	switch csIDRaw {
	case 0:
		// cs_id = next byte + 64
		if off >= len(b) {
			return nil, fmt.Errorf("rtmp basic header truncated (cs_id form 0)")
		}
		r.ChunkStreamID = int(b[off]) + 64
		off++
	case 1:
		// cs_id = next 2 bytes LE + 64
		if off+1 >= len(b) {
			return nil, fmt.Errorf("rtmp basic header truncated (cs_id form 1)")
		}
		r.ChunkStreamID = int(b[off]) | (int(b[off+1]) << 8) + 64
		off += 2
	default:
		r.ChunkStreamID = csIDRaw
	}

	// Message header length depends on fmt.
	var timestamp uint32
	switch fmt0 {
	case 0:
		// fmt 0: 11 bytes — timestamp(3) + msg_len(3) + type_id(1) + stream_id(4 LE)
		if off+11 > len(b) {
			return nil, fmt.Errorf("rtmp fmt=0 header truncated (need 11 bytes, have %d)", len(b)-off)
		}
		timestamp = uint32(b[off])<<16 | uint32(b[off+1])<<8 | uint32(b[off+2])
		off += 3
		r.MessageLength = int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2])
		off += 3
		r.MessageTypeID = int(b[off])
		off++
		r.MessageStreamID = int(binary.LittleEndian.Uint32(b[off : off+4]))
		off += 4

	case 1:
		// fmt 1: 7 bytes — timestamp_delta(3) + msg_len(3) + type_id(1)
		if off+7 > len(b) {
			return nil, fmt.Errorf("rtmp fmt=1 header truncated (need 7 bytes, have %d)", len(b)-off)
		}
		timestamp = uint32(b[off])<<16 | uint32(b[off+1])<<8 | uint32(b[off+2])
		off += 3
		r.MessageLength = int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2])
		off += 3
		r.MessageTypeID = int(b[off])
		off++

	case 2:
		// fmt 2: 3 bytes — timestamp_delta(3)
		if off+3 > len(b) {
			return nil, fmt.Errorf("rtmp fmt=2 header truncated (need 3 bytes, have %d)", len(b)-off)
		}
		timestamp = uint32(b[off])<<16 | uint32(b[off+1])<<8 | uint32(b[off+2])
		off += 3

	case 3:
		// fmt 3: 0 bytes — no message header
	}

	// Extended timestamp: if timestamp/delta == 0xFFFFFF, read 4 BE bytes.
	if timestamp == 0xFFFFFF {
		if off+4 > len(b) {
			return nil, fmt.Errorf("rtmp extended timestamp truncated")
		}
		timestamp = binary.BigEndian.Uint32(b[off : off+4])
		off += 4
	}
	r.Timestamp = int(timestamp)

	// Classify message type.
	r.MessageTypeName = messageTypeName(r.MessageTypeID)
	classifyMessage(r, b[off:])

	return r, nil
}

func classifyMessage(r *Result, payload []byte) {
	switch r.MessageTypeID {
	case 1, 2, 3, 4, 5, 6:
		r.IsControlMessage = true
		if r.MessageTypeID == 4 && len(payload) >= 2 {
			evType := int(binary.BigEndian.Uint16(payload[0:2]))
			r.UserControlEventType = evType
			r.UserControlEventName = userControlEventName(evType)
		}
	case 8:
		r.IsAudio = true
	case 9:
		r.IsVideo = true
	case 20:
		// AMF0 Command Message — extract command name.
		decodeAMF0Command(r, payload)
	}
}

// decodeAMF0Command extracts the command name (first AMF0 string)
// and, for "connect", best-effort extracts "app", "tcUrl", and
// "flashVer" from the following AMF0 object.
func decodeAMF0Command(r *Result, payload []byte) {
	if len(payload) < 3 {
		return
	}
	// First element must be AMF0 string marker 0x02.
	if payload[0] != 0x02 {
		return
	}
	if len(payload) < 3 {
		return
	}
	strLen := int(binary.BigEndian.Uint16(payload[1:3]))
	if strLen <= 0 || 3+strLen > len(payload) {
		return
	}
	cmdName := string(payload[3 : 3+strLen])
	r.CommandName = cmdName

	switch cmdName {
	case "connect":
		r.IsConnect = true
	case "play":
		r.IsPlay = true
	case "publish":
		r.IsPublish = true
	}

	// For "connect", try to extract "app" and "tcUrl" from the AMF0
	// object that follows (best-effort scan, not a full AMF0 parser).
	if cmdName == "connect" {
		rest := payload[3+strLen:]
		r.AppName, _ = amf0FindStringKey(rest, "app")
		r.TcURL, _ = amf0FindStringKey(rest, "tcUrl")
		r.FlashVer, _ = amf0FindStringKey(rest, "flashVer")
	}
}

// amf0FindStringKey performs a best-effort scan for a named string
// property inside an AMF0 object or mixed blob. It looks for the
// key name encoded as an AMF0 short string (2-byte BE length +
// bytes) followed by an AMF0 string value (marker 0x02 + 2-byte BE
// length + bytes). Returns the value string and true on success.
func amf0FindStringKey(b []byte, key string) (string, bool) {
	keyBytes := []byte(key)
	keyLen := len(keyBytes)
	// We need at least: 2 (key len) + keyLen + 1 (0x02) + 2 (val len) + 1
	minNeeded := 2 + keyLen + 1 + 2 + 1
	for i := 0; i+minNeeded <= len(b); i++ {
		// Check for AMF0 short-string key: 2-byte BE length == keyLen.
		if int(b[i])<<8|int(b[i+1]) != keyLen {
			continue
		}
		if i+2+keyLen > len(b) {
			continue
		}
		if string(b[i+2:i+2+keyLen]) != key {
			continue
		}
		// Key matched. Value must immediately follow.
		vOff := i + 2 + keyLen
		if vOff >= len(b) {
			continue
		}
		// Value: AMF0 string marker 0x02 + 2-byte BE length + data.
		if b[vOff] != 0x02 {
			continue
		}
		vOff++
		if vOff+2 > len(b) {
			continue
		}
		vLen := int(b[vOff])<<8 | int(b[vOff+1])
		vOff += 2
		if vLen < 0 || vOff+vLen > len(b) {
			continue
		}
		return string(b[vOff : vOff+vLen]), true
	}
	return "", false
}

func messageTypeName(t int) string {
	switch t {
	case 1:
		return "Set Chunk Size"
	case 2:
		return "Abort Message"
	case 3:
		return "Acknowledgement"
	case 4:
		return "User Control Message"
	case 5:
		return "Window Acknowledgement Size"
	case 6:
		return "Set Peer Bandwidth"
	case 8:
		return "Audio Message"
	case 9:
		return "Video Message"
	case 15:
		return "Data Message (AMF3)"
	case 17:
		return "Shared Object Message (AMF3)"
	case 18:
		return "Data Message (AMF0)"
	case 19:
		return "Shared Object Message (AMF0)"
	case 20:
		return "Command Message (AMF0)"
	case 22:
		return "Aggregate Message"
	}
	if t == 0 {
		return ""
	}
	return fmt.Sprintf("message_type_%d", t)
}

func userControlEventName(t int) string {
	switch t {
	case 0:
		return "StreamBegin"
	case 1:
		return "StreamEOF"
	case 2:
		return "StreamDry"
	case 3:
		return "SetBufferLength"
	case 4:
		return "StreamIsRecorded"
	case 6:
		return "PingRequest"
	case 7:
		return "PingResponse"
	}
	return fmt.Sprintf("event_type_%d", t)
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
