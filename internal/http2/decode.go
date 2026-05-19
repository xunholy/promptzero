// Package http2 decodes HTTP/2 frames per RFC 9113.
//
// Wrap-vs-native judgement
//
//	Native. RFC 9113 is fully public; HTTP/2 wire format is
//	a tight 9-byte frame header (Length 24-bit + Type 8-bit
//	+ Flags 8-bit + Reserved 1-bit + Stream ID 31-bit) plus
//	per-type body layouts that are themselves fixed-field.
//	Operators paste TCP-stream bytes from a Wireshark Follow
//	HTTP/2 view, a curl --http2 -v trace, or a Go pprof
//	trace and inspect every documented frame field. Pure
//	offline parser, no encryption at this layer (TLS termi-
//	nation is upstream).
//
// What this package covers
//
//   - **Connection preface** — the literal 24-byte preface
//     "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" sent by the client
//     immediately after the upgrade. Auto-detected and
//     surfaced as a synthetic "preface" frame at the start
//     of the stream.
//
//   - **Frame header** (9 bytes fixed): Length (24-bit BE
//     payload-length-in-bytes) + Type (1 byte) + Flags (1
//     byte) + R+Stream Identifier (32-bit; high bit reserved,
//     31-bit stream ID). Stream ID 0 is the connection-level
//     stream (used for SETTINGS / PING / GOAWAY).
//
//   - **10 frame types** (RFC 9113 §6) with per-type bodies:
//
//   - **0x0 DATA** — optional pad-length (1 byte if
//     PADDED flag set) + data + padding. END_STREAM flag
//     marks the last frame in a request/response body.
//
//   - **0x1 HEADERS** — optional pad-length + optional
//     priority block (5 bytes: exclusive+stream-dep+weight,
//     PRIORITY flag) + HPACK header block + padding.
//     END_HEADERS flag marks the last header frame in a
//     CONTINUATION chain; END_STREAM marks no request body.
//
//   - **0x2 PRIORITY** (deprecated in RFC 9113 but still
//     valid) — exclusive bit + stream dependency (31-bit)
//
//   - weight (1 byte).
//
//   - **0x3 RST_STREAM** — error code (uint32 BE). 14-entry
//     name table (NO_ERROR / PROTOCOL_ERROR / INTERNAL_ERROR
//     / FLOW_CONTROL_ERROR / SETTINGS_TIMEOUT / STREAM_CLOSED
//     / FRAME_SIZE_ERROR / REFUSED_STREAM / CANCEL /
//     COMPRESSION_ERROR / CONNECT_ERROR / ENHANCE_YOUR_CALM
//     / INADEQUATE_SECURITY / HTTP_1_1_REQUIRED).
//
//   - **0x4 SETTINGS** — list of (Identifier uint16 BE +
//     Value uint32 BE) pairs. 7-entry parameter table
//     (HEADER_TABLE_SIZE / ENABLE_PUSH / MAX_CONCURRENT_
//     STREAMS / INITIAL_WINDOW_SIZE / MAX_FRAME_SIZE /
//     MAX_HEADER_LIST_SIZE / ENABLE_CONNECT_PROTOCOL).
//     ACK flag = empty body acknowledgement.
//
//   - **0x5 PUSH_PROMISE** (deprecated in RFC 9113) —
//     optional pad-length + R+promised-stream-ID (31-bit)
//
//   - HPACK header block + padding.
//
//   - **0x6 PING** — 8 bytes opaque payload. ACK flag =
//     reply to a peer's PING. Used as keep-alive + RTT
//     probe.
//
//   - **0x7 GOAWAY** — R+last-stream-ID (31-bit) + error
//     code (uint32) + opaque debug data.
//
//   - **0x8 WINDOW_UPDATE** — R+window-size-increment
//     (31-bit, must be > 0).
//
//   - **0x9 CONTINUATION** — HPACK header block fragment
//     (continuation of HEADERS or PUSH_PROMISE).
//
//   - **Multi-frame walker** — one buffer may carry multiple
//     concatenated frames; iterator walks frame-by-frame
//     until the buffer is consumed.
//
//   - **Flags decoding per frame type** — END_STREAM /
//     END_HEADERS / PADDED / PRIORITY / ACK flags surfaced
//     with their type-specific names.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - HPACK header decompression (RFC 7541) — the static-
//     table indexing + Huffman coding requires session state
//     (the dynamic table evolves across frames). Compressed
//     header bytes are surfaced as hex; a sibling Spec would
//     handle decoding.
//
//   - TLS layer — operators feed cleartext HTTP/2 frame
//     bytes after TLS decryption (handled by Wireshark's
//     SSL/TLS dissector with the appropriate key file).
//
//   - HTTP/2 connection state machine — frames are decoded
//     individually; tracking which stream is in which state
//     belongs in a session-tracker.
//
//   - HTTP/3 (RFC 9114) — wholly different wire format
//     (QPACK + QUIC); a separate Spec.
//
//   - WebSocket-over-HTTP/2 (RFC 8441 :protocol pseudo-
//     header) — surfaced via the HPACK bytes when present.
package http2

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// ConnectionPreface is the 24-byte literal sent by the client
// at the start of every HTTP/2 connection (RFC 9113 §3.4).
const ConnectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Result is the top-level decoded view.
type Result struct {
	Frames     []Frame `json:"frames"`
	FrameCount int     `json:"frame_count"`
	TotalBytes int     `json:"total_bytes"`
	HasPreface bool    `json:"has_preface"`
	Summary    string  `json:"summary"`
}

// Frame is one decoded HTTP/2 frame.
type Frame struct {
	Length       int    `json:"length"`
	Type         int    `json:"type"`
	TypeName     string `json:"type_name"`
	Flags        int    `json:"flags"`
	FlagsDecoded string `json:"flags_decoded,omitempty"`
	StreamID     uint32 `json:"stream_id"`
	IsPreface    bool   `json:"is_preface,omitempty"`
	BodyHex      string `json:"body_hex,omitempty"`

	Data         *DataFrame         `json:"data,omitempty"`
	Headers      *HeadersFrame      `json:"headers,omitempty"`
	Priority     *PriorityFrame     `json:"priority,omitempty"`
	RstStream    *RstStreamFrame    `json:"rst_stream,omitempty"`
	Settings     *SettingsFrame     `json:"settings,omitempty"`
	PushPromise  *PushPromiseFrame  `json:"push_promise,omitempty"`
	Ping         *PingFrame         `json:"ping,omitempty"`
	GoAway       *GoAwayFrame       `json:"goaway,omitempty"`
	WindowUpdate *WindowUpdateFrame `json:"window_update,omitempty"`
	Continuation *ContinuationFrame `json:"continuation,omitempty"`
}

// DataFrame is type 0x0.
type DataFrame struct {
	PaddingLen int    `json:"padding_length,omitempty"`
	DataLen    int    `json:"data_length"`
	DataHex    string `json:"data_hex,omitempty"`
}

// HeadersFrame is type 0x1.
type HeadersFrame struct {
	PaddingLen       int    `json:"padding_length,omitempty"`
	Exclusive        bool   `json:"priority_exclusive,omitempty"`
	StreamDependency uint32 `json:"priority_stream_dependency,omitempty"`
	Weight           int    `json:"priority_weight,omitempty"`
	HasPriority      bool   `json:"has_priority,omitempty"`
	HPACKBlockHex    string `json:"hpack_header_block_hex,omitempty"`
	HPACKBlockLen    int    `json:"hpack_header_block_length"`
}

// PriorityFrame is type 0x2.
type PriorityFrame struct {
	Exclusive        bool   `json:"exclusive"`
	StreamDependency uint32 `json:"stream_dependency"`
	Weight           int    `json:"weight"`
}

// RstStreamFrame is type 0x3.
type RstStreamFrame struct {
	ErrorCode     uint32 `json:"error_code"`
	ErrorCodeName string `json:"error_code_name"`
}

// SettingsFrame is type 0x4.
type SettingsFrame struct {
	IsAck      bool            `json:"is_ack"`
	Parameters []SettingsParam `json:"parameters,omitempty"`
}

// SettingsParam is one identifier/value pair in a SETTINGS frame.
type SettingsParam struct {
	Identifier     uint16 `json:"identifier"`
	IdentifierName string `json:"identifier_name"`
	Value          uint32 `json:"value"`
}

// PushPromiseFrame is type 0x5.
type PushPromiseFrame struct {
	PaddingLen       int    `json:"padding_length,omitempty"`
	PromisedStreamID uint32 `json:"promised_stream_id"`
	HPACKBlockHex    string `json:"hpack_header_block_hex,omitempty"`
	HPACKBlockLen    int    `json:"hpack_header_block_length"`
}

// PingFrame is type 0x6.
type PingFrame struct {
	IsAck     bool   `json:"is_ack"`
	OpaqueHex string `json:"opaque_hex"`
}

// GoAwayFrame is type 0x7.
type GoAwayFrame struct {
	LastStreamID  uint32 `json:"last_stream_id"`
	ErrorCode     uint32 `json:"error_code"`
	ErrorCodeName string `json:"error_code_name"`
	DebugHex      string `json:"debug_data_hex,omitempty"`
}

// WindowUpdateFrame is type 0x8.
type WindowUpdateFrame struct {
	WindowSizeIncrement uint32 `json:"window_size_increment"`
}

// ContinuationFrame is type 0x9.
type ContinuationFrame struct {
	HPACKBlockHex string `json:"hpack_header_block_hex,omitempty"`
	HPACKBlockLen int    `json:"hpack_header_block_length"`
}

// Decode parses one or more concatenated HTTP/2 frames from hex.
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
		return nil, fmt.Errorf("buffer empty")
	}

	r := &Result{TotalBytes: len(b)}
	off := 0

	// Check for connection preface.
	if len(b) >= len(ConnectionPreface) &&
		string(b[:len(ConnectionPreface)]) == ConnectionPreface {
		r.Frames = append(r.Frames, Frame{
			TypeName:  "Connection Preface (PRI * HTTP/2.0)",
			IsPreface: true,
			Length:    len(ConnectionPreface),
			BodyHex:   strings.ToUpper(hex.EncodeToString(b[:len(ConnectionPreface)])),
		})
		r.HasPreface = true
		off += len(ConnectionPreface)
	}

	for off < len(b) {
		if off+9 > len(b) {
			return nil, fmt.Errorf("frame header truncated at offset %d", off)
		}
		length := int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2])
		typ := int(b[off+3])
		flags := int(b[off+4])
		streamID := binary.BigEndian.Uint32(b[off+5:off+9]) & 0x7FFFFFFF

		if off+9+length > len(b) {
			return nil, fmt.Errorf("frame at offset %d declares %d-byte payload; %d left",
				off, length, len(b)-off-9)
		}

		f := Frame{
			Length:       length,
			Type:         typ,
			TypeName:     frameTypeName(typ),
			Flags:        flags,
			FlagsDecoded: flagsName(typ, flags),
			StreamID:     streamID,
		}
		body := b[off+9 : off+9+length]
		if length > 0 {
			if length > 256 {
				f.BodyHex = strings.ToUpper(hex.EncodeToString(body[:256])) + "..."
			} else {
				f.BodyHex = strings.ToUpper(hex.EncodeToString(body))
			}
		}

		switch typ {
		case 0x0:
			f.Data = decodeData(body, flags)
		case 0x1:
			f.Headers = decodeHeaders(body, flags)
		case 0x2:
			pr, err := decodePriority(body)
			if err != nil {
				return nil, fmt.Errorf("PRIORITY frame at offset %d: %w", off, err)
			}
			f.Priority = pr
		case 0x3:
			rs, err := decodeRstStream(body)
			if err != nil {
				return nil, fmt.Errorf("RST_STREAM frame at offset %d: %w", off, err)
			}
			f.RstStream = rs
		case 0x4:
			st, err := decodeSettings(body, flags)
			if err != nil {
				return nil, fmt.Errorf("SETTINGS frame at offset %d: %w", off, err)
			}
			f.Settings = st
		case 0x5:
			pp, err := decodePushPromise(body, flags)
			if err != nil {
				return nil, fmt.Errorf("PUSH_PROMISE frame at offset %d: %w", off, err)
			}
			f.PushPromise = pp
		case 0x6:
			pi, err := decodePing(body, flags)
			if err != nil {
				return nil, fmt.Errorf("PING frame at offset %d: %w", off, err)
			}
			f.Ping = pi
		case 0x7:
			ga, err := decodeGoAway(body)
			if err != nil {
				return nil, fmt.Errorf("GOAWAY frame at offset %d: %w", off, err)
			}
			f.GoAway = ga
		case 0x8:
			wu, err := decodeWindowUpdate(body)
			if err != nil {
				return nil, fmt.Errorf("WINDOW_UPDATE frame at offset %d: %w", off, err)
			}
			f.WindowUpdate = wu
		case 0x9:
			f.Continuation = &ContinuationFrame{
				HPACKBlockHex: strings.ToUpper(hex.EncodeToString(body)),
				HPACKBlockLen: len(body),
			}
		}

		r.Frames = append(r.Frames, f)
		off += 9 + length
	}

	r.FrameCount = len(r.Frames)
	names := make([]string, 0, len(r.Frames))
	for _, fr := range r.Frames {
		names = append(names, fr.TypeName)
	}
	r.Summary = strings.Join(names, " + ")
	return r, nil
}

func decodeData(b []byte, flags int) *DataFrame {
	d := &DataFrame{}
	off := 0
	if flags&0x08 != 0 && len(b) >= 1 { // PADDED
		d.PaddingLen = int(b[0])
		off = 1
	}
	dataEnd := len(b) - d.PaddingLen
	if dataEnd < off {
		dataEnd = off
	}
	data := b[off:dataEnd]
	d.DataLen = len(data)
	if len(data) > 0 {
		if len(data) > 256 {
			d.DataHex = strings.ToUpper(hex.EncodeToString(data[:256])) + "..."
		} else {
			d.DataHex = strings.ToUpper(hex.EncodeToString(data))
		}
	}
	return d
}

func decodeHeaders(b []byte, flags int) *HeadersFrame {
	h := &HeadersFrame{}
	off := 0
	if flags&0x08 != 0 && len(b) >= 1 { // PADDED
		h.PaddingLen = int(b[0])
		off = 1
	}
	if flags&0x20 != 0 && off+5 <= len(b) { // PRIORITY
		h.HasPriority = true
		depBytes := binary.BigEndian.Uint32(b[off : off+4])
		h.Exclusive = depBytes&0x80000000 != 0
		h.StreamDependency = depBytes & 0x7FFFFFFF
		h.Weight = int(b[off+4]) + 1
		off += 5
	}
	hpackEnd := len(b) - h.PaddingLen
	if hpackEnd < off {
		hpackEnd = off
	}
	block := b[off:hpackEnd]
	h.HPACKBlockLen = len(block)
	if len(block) > 0 {
		if len(block) > 256 {
			h.HPACKBlockHex = strings.ToUpper(hex.EncodeToString(block[:256])) + "..."
		} else {
			h.HPACKBlockHex = strings.ToUpper(hex.EncodeToString(block))
		}
	}
	return h
}

func decodePriority(b []byte) (*PriorityFrame, error) {
	if len(b) != 5 {
		return nil, fmt.Errorf("PRIORITY must be 5 bytes, got %d", len(b))
	}
	depBytes := binary.BigEndian.Uint32(b[0:4])
	return &PriorityFrame{
		Exclusive:        depBytes&0x80000000 != 0,
		StreamDependency: depBytes & 0x7FFFFFFF,
		Weight:           int(b[4]) + 1,
	}, nil
}

func decodeRstStream(b []byte) (*RstStreamFrame, error) {
	if len(b) != 4 {
		return nil, fmt.Errorf("RST_STREAM must be 4 bytes, got %d", len(b))
	}
	code := binary.BigEndian.Uint32(b[0:4])
	return &RstStreamFrame{
		ErrorCode:     code,
		ErrorCodeName: errorCodeName(code),
	}, nil
}

func decodeSettings(b []byte, flags int) (*SettingsFrame, error) {
	s := &SettingsFrame{IsAck: flags&0x01 != 0}
	if s.IsAck && len(b) != 0 {
		return nil, fmt.Errorf("SETTINGS ACK must have empty body, got %d bytes", len(b))
	}
	if len(b)%6 != 0 {
		return nil, fmt.Errorf("SETTINGS body must be a multiple of 6 bytes, got %d",
			len(b))
	}
	for i := 0; i < len(b); i += 6 {
		id := binary.BigEndian.Uint16(b[i : i+2])
		val := binary.BigEndian.Uint32(b[i+2 : i+6])
		s.Parameters = append(s.Parameters, SettingsParam{
			Identifier:     id,
			IdentifierName: settingsParamName(id),
			Value:          val,
		})
	}
	return s, nil
}

func decodePushPromise(b []byte, flags int) (*PushPromiseFrame, error) {
	p := &PushPromiseFrame{}
	off := 0
	if flags&0x08 != 0 && len(b) >= 1 { // PADDED
		p.PaddingLen = int(b[0])
		off = 1
	}
	if off+4 > len(b) {
		return nil, fmt.Errorf("PUSH_PROMISE truncated before promised stream ID")
	}
	depBytes := binary.BigEndian.Uint32(b[off : off+4])
	p.PromisedStreamID = depBytes & 0x7FFFFFFF
	off += 4
	hpackEnd := len(b) - p.PaddingLen
	if hpackEnd < off {
		hpackEnd = off
	}
	block := b[off:hpackEnd]
	p.HPACKBlockLen = len(block)
	if len(block) > 0 {
		if len(block) > 256 {
			p.HPACKBlockHex = strings.ToUpper(hex.EncodeToString(block[:256])) + "..."
		} else {
			p.HPACKBlockHex = strings.ToUpper(hex.EncodeToString(block))
		}
	}
	return p, nil
}

func decodePing(b []byte, flags int) (*PingFrame, error) {
	if len(b) != 8 {
		return nil, fmt.Errorf("PING must be 8 bytes, got %d", len(b))
	}
	return &PingFrame{
		IsAck:     flags&0x01 != 0,
		OpaqueHex: strings.ToUpper(hex.EncodeToString(b)),
	}, nil
}

func decodeGoAway(b []byte) (*GoAwayFrame, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("GOAWAY must be ≥8 bytes, got %d", len(b))
	}
	last := binary.BigEndian.Uint32(b[0:4]) & 0x7FFFFFFF
	code := binary.BigEndian.Uint32(b[4:8])
	g := &GoAwayFrame{
		LastStreamID:  last,
		ErrorCode:     code,
		ErrorCodeName: errorCodeName(code),
	}
	if len(b) > 8 {
		g.DebugHex = strings.ToUpper(hex.EncodeToString(b[8:]))
	}
	return g, nil
}

func decodeWindowUpdate(b []byte) (*WindowUpdateFrame, error) {
	if len(b) != 4 {
		return nil, fmt.Errorf("WINDOW_UPDATE must be 4 bytes, got %d", len(b))
	}
	inc := binary.BigEndian.Uint32(b[0:4]) & 0x7FFFFFFF
	if inc == 0 {
		return nil, fmt.Errorf("WINDOW_UPDATE increment must be > 0")
	}
	return &WindowUpdateFrame{WindowSizeIncrement: inc}, nil
}

func frameTypeName(t int) string {
	switch t {
	case 0x0:
		return "DATA"
	case 0x1:
		return "HEADERS"
	case 0x2:
		return "PRIORITY"
	case 0x3:
		return "RST_STREAM"
	case 0x4:
		return "SETTINGS"
	case 0x5:
		return "PUSH_PROMISE"
	case 0x6:
		return "PING"
	case 0x7:
		return "GOAWAY"
	case 0x8:
		return "WINDOW_UPDATE"
	case 0x9:
		return "CONTINUATION"
	}
	return fmt.Sprintf("Unknown (0x%02X)", t)
}

func flagsName(typ, flags int) string {
	if flags == 0 {
		return ""
	}
	parts := []string{}
	switch typ {
	case 0x0: // DATA
		if flags&0x01 != 0 {
			parts = append(parts, "END_STREAM")
		}
		if flags&0x08 != 0 {
			parts = append(parts, "PADDED")
		}
	case 0x1: // HEADERS
		if flags&0x01 != 0 {
			parts = append(parts, "END_STREAM")
		}
		if flags&0x04 != 0 {
			parts = append(parts, "END_HEADERS")
		}
		if flags&0x08 != 0 {
			parts = append(parts, "PADDED")
		}
		if flags&0x20 != 0 {
			parts = append(parts, "PRIORITY")
		}
	case 0x4, 0x6: // SETTINGS, PING
		if flags&0x01 != 0 {
			parts = append(parts, "ACK")
		}
	case 0x5: // PUSH_PROMISE
		if flags&0x04 != 0 {
			parts = append(parts, "END_HEADERS")
		}
		if flags&0x08 != 0 {
			parts = append(parts, "PADDED")
		}
	case 0x9: // CONTINUATION
		if flags&0x04 != 0 {
			parts = append(parts, "END_HEADERS")
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%02X", flags)
	}
	return strings.Join(parts, " | ")
}

func errorCodeName(c uint32) string {
	switch c {
	case 0x0:
		return "NO_ERROR"
	case 0x1:
		return "PROTOCOL_ERROR"
	case 0x2:
		return "INTERNAL_ERROR"
	case 0x3:
		return "FLOW_CONTROL_ERROR"
	case 0x4:
		return "SETTINGS_TIMEOUT"
	case 0x5:
		return "STREAM_CLOSED"
	case 0x6:
		return "FRAME_SIZE_ERROR"
	case 0x7:
		return "REFUSED_STREAM"
	case 0x8:
		return "CANCEL"
	case 0x9:
		return "COMPRESSION_ERROR"
	case 0xA:
		return "CONNECT_ERROR"
	case 0xB:
		return "ENHANCE_YOUR_CALM"
	case 0xC:
		return "INADEQUATE_SECURITY"
	case 0xD:
		return "HTTP_1_1_REQUIRED"
	}
	return fmt.Sprintf("error 0x%X (uncatalogued)", c)
}

func settingsParamName(id uint16) string {
	switch id {
	case 0x1:
		return "HEADER_TABLE_SIZE"
	case 0x2:
		return "ENABLE_PUSH"
	case 0x3:
		return "MAX_CONCURRENT_STREAMS"
	case 0x4:
		return "INITIAL_WINDOW_SIZE"
	case 0x5:
		return "MAX_FRAME_SIZE"
	case 0x6:
		return "MAX_HEADER_LIST_SIZE"
	case 0x8:
		return "ENABLE_CONNECT_PROTOCOL"
	}
	return fmt.Sprintf("setting 0x%04X (uncatalogued)", id)
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
