// Package rtsp decodes RTSP (Real-Time Streaming Protocol)
// messages per RFC 7826 (RTSP 2.0) and the more widely-deployed
// RFC 2326 (RTSP 1.0). RTSP is the **canonical streaming-
// session control protocol** for IP cameras + streaming-server
// fronts — the wire format an operator sees when interrogating
// Hikvision / Axis / Dahua / Bosch / Vivotek / Pelco IP cameras
// (which all expose an RTSP server on TCP/554) or talking to a
// streaming-server product (Wowza, RTSP Simple Server, GStreamer
// rtspserver, Live555 testOnDemandRTSPServer, VLC).
//
// Operationally, RTSP is the **first protocol an IP-camera
// pentester touches**:
//
//   - **Default-credential brute force** — the canonical
//     `DESCRIBE rtsp://admin:admin@target/Streaming/Channels/101`
//     URL probe enumerates whether a camera is online + which
//     authentication scheme it speaks.
//   - **Path enumeration** — vendor-specific URL paths
//     (`/Streaming/Channels/<n>` for Hikvision, `/axis-media/
//     media.amp` for Axis, `/cam/realmonitor` for Dahua,
//     `/live/ch00_0` for Bosch) reveal vendor + model + camera
//     channel layout.
//   - **Authentication harvesting** — the `WWW-Authenticate:`
//     header on a 401 response leaks the realm + nonce for an
//     offline Digest crack.
//   - **CVE-2017-7921 / -7923 (Hikvision)** — historically
//     unauthenticated /System/configurationFile + magic backdoor
//     accounts; `DESCRIBE` is the recon step.
//
// Wrap-vs-native judgement
//
//	Native. RFC 7826 + 2326 are publicly available; RTSP is a
//	tiny text-based protocol — three message kinds (Request,
//	Response, Interleaved RTP), CRLF-terminated lines, and a
//	flat header set borrowed largely from HTTP/1.1. The
//	encapsulated bodies (SDP in `Content-Type: application/sdp`
//	responses, RTP packets in the Interleaved case) are
//	separate decoders; the RTSP envelope is uniform and
//	deterministic. No crypto at the parse layer (RTSPS over
//	TLS handles transport security at the TLS layer).
//
// What this package covers
//
//   - **Three message kinds** discriminated by the first byte
//     of the input:
//
//   - **Request** — first whitespace-delimited token is one
//     of the 11 documented methods (`OPTIONS` /
//     `DESCRIBE` / `ANNOUNCE` / `SETUP` / `PLAY` / `PAUSE` /
//     `TEARDOWN` / `GET_PARAMETER` / `SET_PARAMETER` /
//     `REDIRECT` / `RECORD`). Format:
//     `<METHOD> <URL> RTSP/<version>\r\n`.
//
//   - **Response** — first token is `RTSP/<version>`. Format:
//     `RTSP/<version> <status-code> <reason-phrase>\r\n`.
//
//   - **Interleaved RTP** — first byte is `$` (0x24) per RFC
//     7826 §14.4. Followed by 1-byte channel + 2-byte BE
//     length + length-many bytes of RTP / RTCP payload. The
//     decoder surfaces channel + length + payload-bytes
//     hex for downstream RTP / RTCP decoders.
//
//   - **11-entry Method name table** (RFC 7826 §13):
//     `OPTIONS` (discover server capabilities — the canonical
//     first probe) / `DESCRIBE` (request a SDP description of
//     the stream — the canonical enumeration step that reveals
//     stream tracks + codec parameters) / `ANNOUNCE` (push a
//     SDP description to the server — used in record-mode
//     publishing like ffmpeg upload) / `SETUP` (negotiate
//     transport parameters per track — RTP/AVP or RTP/AVP/TCP
//     for the Interleaved tunnel mode) / `PLAY` (start media
//     delivery) / `PAUSE` / `TEARDOWN` (close the session) /
//     `GET_PARAMETER` (keep-alive + per-server parameter
//     query) / `SET_PARAMETER` / `REDIRECT` (server informs
//     client of a new location) / `RECORD`.
//
//   - **HTTP-style status code categories**: 1xx Informational
//     / 2xx Success (200 OK is overwhelmingly common; 451
//     Parameter Not Understood + 454 Session Not Found +
//     455 Method Not Valid in This State are RTSP-specific) /
//     3xx Redirection / 4xx Client Error (401 Unauthorized
//     triggers Digest auth; 461 Unsupported Transport is
//     common when SETUP requests an unsupported transport
//     spec) / 5xx Server Error / 6xx Camera-specific Error
//     (some Hikvision firmwares use 6xx for vendor errors).
//     The decoder categorises the integer status code into
//     `status_category` (`Informational` / `Success` /
//     `Redirection` / `Client_Error` / `Server_Error` /
//     `Vendor_Error`).
//
//   - **Case-insensitive header parser** (RFC 7826 borrows the
//     HTTP/1.1 header model). Surfaces canonical RTSP fields
//     as dedicated typed fields:
//
//   - `CSeq` — per-session monotonic sequence number that
//     pairs requests to responses.
//
//   - `Session` — opaque session identifier the server
//     assigns on SETUP; subsequent requests echo it.
//
//   - `Transport` — RTP/AVP transport spec (e.g.
//     `RTP/AVP/UDP;unicast;client_port=8000-8001`) or
//     `RTP/AVP/TCP;unicast;interleaved=0-1` for the
//     Interleaved tunnel mode.
//
//   - `Range` — playback range (e.g. `npt=0-`,
//     `npt=10.0-20.5`, `clock=20251101T...`).
//
//   - `Scale` / `Speed` — playback rate (1.0 = normal;
//     2.0 = double-speed).
//
//   - `Public` / `Allow` — server-advertised method lists
//     (returned on OPTIONS / 405 respectively).
//
//   - `RTP-Info` — per-track RTP synchronisation info
//     (sequence number + RTP timestamp at the start of
//     PLAY).
//
//   - `Content-Type` — usually `application/sdp` on
//     DESCRIBE responses.
//
//   - `Content-Length` — body length in bytes.
//
//   - `User-Agent` / `Server` — client / server identification
//     strings; the canonical fingerprinting fields.
//
//   - `WWW-Authenticate` — `Basic realm="..."` or `Digest
//     realm="...", nonce="...", ...`; the Digest realm +
//     nonce are what an attacker cracks offline.
//
//   - `Authorization` — `Basic <base64>` or `Digest
//     username="...", realm="...", nonce="...", uri="...",
//     response="..."`.
//
//   - All other headers — surfaced as a generic
//     `other_headers` map.
//
//   - **Body bytes** — when `Content-Length: N` is set and N
//     bytes follow the blank line, the body is surfaced as
//     `body_string` (if UTF-8) or `body_hex` (otherwise).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed RTSP bytes after the TCP-
//     segment header strip (default TCP port 554; RTSPS over
//     TLS on TCP port 322 wraps the same bytes in TLS records
//     — handle the TLS strip first).
//   - **SDP body decoding** — DESCRIBE responses carry an SDP
//     (Session Description Protocol) body that itself has a
//     rich line-based format (v=, o=, s=, c=, m=, a=); the
//     existing `sdp_decode` Spec covers it. This decoder
//     surfaces the body for the SDP decoder to handle.
//   - **Encapsulated RTP / RTCP** — Interleaved RTP frames
//     (the `$` channel-byte-length-payload sequences) carry
//     RTP / RTCP packets in the body; the existing `rtp_decode`
//     Spec covers RTP.
//   - **Authentication evaluation** — Digest nonce validation,
//     Basic credential extraction, MD5 / SHA-256 response
//     verification are higher-level concerns.
//   - **RTSP-over-HTTP tunnelling** — the RTSP-over-HTTP
//     tunnel (used to traverse HTTP proxies; RFC 7826 §A.3)
//     wraps RTSP in HTTP requests with `application/x-rtsp-
//     tunnelled`; out of scope.
//   - **WebRTC / WHIP / WHEP** — the modern streaming-
//     signalling alternatives that replace RTSP in some
//     deployments; separate decoders.
package rtsp

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MessageKind enumerates the three RTSP message kinds.
type MessageKind string

const (
	KindRequest     MessageKind = "Request"
	KindResponse    MessageKind = "Response"
	KindInterleaved MessageKind = "Interleaved"
	KindUnknown     MessageKind = "uncatalogued"
)

// Result is the structured decode of an RTSP message.
type Result struct {
	TotalBytes int         `json:"total_bytes"`
	Kind       MessageKind `json:"kind"`
	StartLine  string      `json:"start_line,omitempty"`

	// Request only
	Method  string `json:"method,omitempty"`
	URL     string `json:"url,omitempty"`
	Version string `json:"version,omitempty"`

	// Response only
	StatusCode     int    `json:"status_code,omitempty"`
	StatusPhrase   string `json:"status_phrase,omitempty"`
	StatusCategory string `json:"status_category,omitempty"`

	// Interleaved only. Channel + length must not be
	// `omitempty` — channel 0 is the canonical primary
	// track and a 0-byte interleaved frame is valid.
	InterleavedChannel int    `json:"interleaved_channel"`
	InterleavedLength  int    `json:"interleaved_length"`
	InterleavedHex     string `json:"interleaved_hex,omitempty"`

	// Canonical headers
	CSeq            string `json:"cseq,omitempty"`
	Session         string `json:"session,omitempty"`
	Transport       string `json:"transport,omitempty"`
	Range           string `json:"range,omitempty"`
	Scale           string `json:"scale,omitempty"`
	Speed           string `json:"speed,omitempty"`
	Public          string `json:"public,omitempty"`
	Allow           string `json:"allow,omitempty"`
	RTPInfo         string `json:"rtp_info,omitempty"`
	ContentType     string `json:"content_type,omitempty"`
	ContentLength   int    `json:"content_length,omitempty"`
	UserAgent       string `json:"user_agent,omitempty"`
	Server          string `json:"server,omitempty"`
	Date            string `json:"date,omitempty"`
	WWWAuthenticate string `json:"www_authenticate,omitempty"`
	Authorization   string `json:"authorization,omitempty"`

	// Other headers + body
	OtherHeaders map[string]string `json:"other_headers,omitempty"`
	BodyString   string            `json:"body_string,omitempty"`
	BodyHex      string            `json:"body_hex,omitempty"`
}

// Decode parses an RTSP message from a hex string. Separators
// (':' '-' '_' whitespace) tolerated; '0x' prefix tolerated.
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
	if len(b) < 4 {
		return nil, fmt.Errorf("RTSP message truncated (%d bytes; need ≥4)", len(b))
	}

	r := &Result{TotalBytes: len(b)}

	// Detect Interleaved RTP (first byte = '$' / 0x24).
	if b[0] == 0x24 {
		if len(b) < 4 {
			return r, fmt.Errorf("interleaved frame truncated")
		}
		r.Kind = KindInterleaved
		r.InterleavedChannel = int(b[1])
		r.InterleavedLength = int(binary.BigEndian.Uint16(b[2:4]))
		end := 4 + r.InterleavedLength
		if end > len(b) {
			end = len(b)
		}
		if end > 4 {
			r.InterleavedHex = strings.ToUpper(hex.EncodeToString(b[4:end]))
		}
		return r, nil
	}

	// Text RTSP message. Parse line-by-line.
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)
	if !scanner.Scan() {
		return r, fmt.Errorf("no start line")
	}
	r.StartLine = strings.TrimRight(scanner.Text(), "\r")
	r.Kind = classifyStartLine(r.StartLine)
	switch r.Kind {
	case KindRequest:
		decodeRequestLine(r)
	case KindResponse:
		decodeStatusLine(r)
	}

	// Walk headers until blank line.
	headerEnd := len(b)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			// Compute body offset (bytes after the blank
			// line). bufio.Scanner advances per line; we
			// can't trivially get the byte offset, so use
			// a manual CRLFCRLF search instead.
			if idx := strings.Index(string(b), "\r\n\r\n"); idx >= 0 {
				headerEnd = idx + 4
			}
			break
		}
		key, val, ok := splitHeader(line)
		if !ok {
			continue
		}
		r.applyHeader(key, val)
	}
	// Surface body if a Content-Length declared it.
	if r.ContentLength > 0 && headerEnd < len(b) {
		bodyEnd := headerEnd + r.ContentLength
		if bodyEnd > len(b) {
			bodyEnd = len(b)
		}
		body := b[headerEnd:bodyEnd]
		if utf8.Valid(body) {
			r.BodyString = string(body)
		} else {
			r.BodyHex = strings.ToUpper(hex.EncodeToString(body))
		}
	}
	return r, nil
}

func classifyStartLine(line string) MessageKind {
	upper := strings.ToUpper(line)
	if strings.HasPrefix(upper, "RTSP/") {
		return KindResponse
	}
	first := strings.IndexByte(line, ' ')
	if first <= 0 {
		return KindUnknown
	}
	method := strings.ToUpper(line[:first])
	if isMethod(method) {
		return KindRequest
	}
	return KindUnknown
}

func isMethod(m string) bool {
	switch m {
	case "OPTIONS", "DESCRIBE", "ANNOUNCE", "SETUP",
		"PLAY", "PAUSE", "TEARDOWN",
		"GET_PARAMETER", "SET_PARAMETER",
		"REDIRECT", "RECORD":
		return true
	}
	return false
}

func decodeRequestLine(r *Result) {
	parts := strings.SplitN(r.StartLine, " ", 3)
	if len(parts) < 3 {
		return
	}
	r.Method = parts[0]
	r.URL = parts[1]
	r.Version = parts[2]
}

func decodeStatusLine(r *Result) {
	parts := strings.SplitN(r.StartLine, " ", 3)
	if len(parts) < 2 {
		return
	}
	r.Version = parts[0]
	code, err := strconv.Atoi(parts[1])
	if err == nil {
		r.StatusCode = code
		r.StatusCategory = statusCategory(code)
	}
	if len(parts) == 3 {
		r.StatusPhrase = parts[2]
	}
}

func statusCategory(c int) string {
	switch {
	case c >= 100 && c < 200:
		return "Informational"
	case c >= 200 && c < 300:
		return "Success"
	case c >= 300 && c < 400:
		return "Redirection"
	case c >= 400 && c < 500:
		return "Client_Error"
	case c >= 500 && c < 600:
		return "Server_Error"
	case c >= 600 && c < 700:
		return "Vendor_Error"
	}
	return ""
}

func splitHeader(line string) (string, string, bool) {
	idx := strings.Index(line, ":")
	if idx <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:idx]),
		strings.TrimSpace(line[idx+1:]), true
}

func (r *Result) applyHeader(key, val string) {
	switch strings.ToUpper(key) {
	case "CSEQ":
		r.CSeq = val
	case "SESSION":
		r.Session = val
	case "TRANSPORT":
		r.Transport = val
	case "RANGE":
		r.Range = val
	case "SCALE":
		r.Scale = val
	case "SPEED":
		r.Speed = val
	case "PUBLIC":
		r.Public = val
	case "ALLOW":
		r.Allow = val
	case "RTP-INFO":
		r.RTPInfo = val
	case "CONTENT-TYPE":
		r.ContentType = val
	case "CONTENT-LENGTH":
		if n, err := strconv.Atoi(val); err == nil {
			r.ContentLength = n
		}
	case "USER-AGENT":
		r.UserAgent = val
	case "SERVER":
		r.Server = val
	case "DATE":
		r.Date = val
	case "WWW-AUTHENTICATE":
		r.WWWAuthenticate = val
	case "AUTHORIZATION":
		r.Authorization = val
	default:
		if r.OtherHeaders == nil {
			r.OtherHeaders = map[string]string{}
		}
		r.OtherHeaders[key] = val
	}
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
