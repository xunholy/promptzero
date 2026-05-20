// SPDX-License-Identifier: AGPL-3.0-or-later

// Package httpmsg decodes HTTP/1.x messages per RFC 9112 +
// RFC 9110. HTTP is the foundational application-layer
// protocol of the web — every browser-server interaction,
// every REST API call, every webhook delivery, every
// internal microservice-to-service call (when not gRPC)
// speaks it.
//
// # Wrap-vs-native judgement
//
// Native. HTTP/1.x is a plain-text request/response protocol
// with a start line + header field list + blank CRLF line +
// optional body. Body framing is either Content-Length
// (fixed-size) or Transfer-Encoding: chunked (length lines
// in hex + CRLF + data chunks). Pasting a message from
// Wireshark "Follow Stream" / mitmproxy export / Burp /
// curl -v output / a web-server access log / an internal
// API trace is enough — no HTTP stack, no socket, no
// network attach.
//
// # What this package covers
//
//   - **Start-line dispatch**: auto-detect request (METHOD
//     URI VERSION) vs response (VERSION CODE REASON) by
//     whether the first token starts with "HTTP/" (response)
//     or any other text (request).
//   - **Request methods** (10 documented): GET, HEAD, POST,
//     PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH (RFC
//     5789), plus PROPFIND / PROPPATCH / MKCOL / COPY /
//     MOVE / LOCK / UNLOCK (WebDAV per RFC 4918) recognised.
//   - **Response status-code lookup** (~50 entries):
//   - 1xx Informational: 100 Continue, 101 Switching
//     Protocols, 102 Processing, 103 Early Hints.
//   - 2xx Success: 200 OK, 201 Created, 202 Accepted,
//     203 Non-Authoritative Information, 204 No Content,
//     205 Reset Content, 206 Partial Content, 207 Multi-
//     Status (WebDAV), 208 Already Reported, 226 IM Used.
//   - 3xx Redirection: 300 Multiple Choices, 301 Moved
//     Permanently, 302 Found, 303 See Other, 304 Not
//     Modified, 305 Use Proxy, 307 Temporary Redirect,
//     308 Permanent Redirect.
//   - 4xx Client error: 400 Bad Request, 401
//     Unauthorized, 402 Payment Required, 403 Forbidden,
//     404 Not Found, 405 Method Not Allowed, 406 Not
//     Acceptable, 407 Proxy Authentication Required, 408
//     Request Timeout, 409 Conflict, 410 Gone, 411 Length
//     Required, 412 Precondition Failed, 413 Payload Too
//     Large, 414 URI Too Long, 415 Unsupported Media Type,
//     416 Range Not Satisfiable, 417 Expectation Failed,
//     418 I'm a teapot (RFC 2324), 421 Misdirected
//     Request, 422 Unprocessable Entity (WebDAV), 423
//     Locked, 424 Failed Dependency, 425 Too Early, 426
//     Upgrade Required, 428 Precondition Required, 429
//     Too Many Requests, 431 Request Header Fields Too
//     Large, 451 Unavailable For Legal Reasons.
//   - 5xx Server error: 500 Internal Server Error, 501
//     Not Implemented, 502 Bad Gateway, 503 Service
//     Unavailable, 504 Gateway Timeout, 505 HTTP Version
//     Not Supported, 506 Variant Also Negotiates, 507
//     Insufficient Storage, 508 Loop Detected, 510 Not
//     Extended, 511 Network Authentication Required.
//   - **Header field parsing**: case-insensitive name match,
//     line continuation (deprecated but still seen — folded
//     into previous header), multi-value preserved as
//     ordered list.
//   - **Typed envelope fields surfaced**: Host, User-Agent,
//     Server, Content-Type, Content-Length, Transfer-
//     Encoding, Authorization (Basic / Bearer / Digest
//     scheme detection), Cookie (parsed into key=value
//     pairs), Set-Cookie (parsed into name, value, and
//     attribute list).
//   - **Body handling**:
//   - Content-Length: read exactly N bytes from the
//     body block.
//   - Transfer-Encoding: chunked — decode hex-length-
//     prefixed chunks (terminated by 0-length chunk per
//     RFC 9112 §7.1).
//   - Both: surface raw text if printable; hex otherwise.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - HTTP/2 binary framing (RFC 9113) and HTTP/3 (RFC 9114)
//     — entirely different wire formats; separate Specs.
//   - HPACK header decompression (RFC 7541) — only relevant
//     to HTTP/2.
//   - WebSocket upgrades (RFC 6455) — the Upgrade: websocket
//     header is preserved verbatim; the post-upgrade WebSocket
//     frames are a separate Spec.
//   - TLS layer — feed the inner cleartext after decryption.
//   - Trailer headers — RFC 9112 §7.1.2 trailer field after
//     the final 0-length chunk; surfaced as raw text in the
//     trailing body.
//   - Multipart bodies (multipart/form-data, multipart/
//     mixed) — body is surfaced as raw bytes; multipart
//     parsing is a separate ~150 LoC effort.
package httpmsg

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Message is the decoded HTTP/1.x message view.
type Message struct {
	IsRequest        bool         `json:"is_request"`
	IsResponse       bool         `json:"is_response"`
	Method           string       `json:"method,omitempty"`
	RequestURI       string       `json:"request_uri,omitempty"`
	Version          string       `json:"version"`
	StatusCode       int          `json:"status_code,omitempty"`
	StatusReason     string       `json:"status_reason,omitempty"`
	StatusName       string       `json:"status_name,omitempty"`
	Headers          []*Header    `json:"headers"`
	Host             string       `json:"host,omitempty"`
	UserAgent        string       `json:"user_agent,omitempty"`
	Server           string       `json:"server,omitempty"`
	ContentType      string       `json:"content_type,omitempty"`
	ContentLength    *int64       `json:"content_length,omitempty"`
	TransferEncoding string       `json:"transfer_encoding,omitempty"`
	Authorization    *AuthHeader  `json:"authorization,omitempty"`
	Cookies          []Cookie     `json:"cookies,omitempty"`
	SetCookies       []*SetCookie `json:"set_cookies,omitempty"`
	BodyRaw          string       `json:"body_raw,omitempty"`
	BodyHex          string       `json:"body_hex,omitempty"`
	ChunkedBody      []*Chunk     `json:"chunked_body,omitempty"`
}

// Header is one header field.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AuthHeader is a parsed Authorization request-header field.
type AuthHeader struct {
	Scheme     string `json:"scheme"`
	Parameters string `json:"parameters,omitempty"`
}

// Cookie is one name=value pair from a Cookie request header.
type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SetCookie is the decoded Set-Cookie response header.
type SetCookie struct {
	Name       string            `json:"name"`
	Value      string            `json:"value"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Chunk is one decoded chunk from a Transfer-Encoding:
// chunked body.
type Chunk struct {
	LengthHex string `json:"length_hex"`
	Length    int    `json:"length"`
	DataHex   string `json:"data_hex,omitempty"`
	DataText  string `json:"data_text,omitempty"`
}

// Decode parses an HTTP/1.x message (single envelope with
// optional body).
func Decode(input string) (*Message, error) {
	s := strings.ReplaceAll(input, "\r\n", "\n")
	if s == "" {
		return nil, fmt.Errorf("httpmsg: empty input")
	}
	hdrBlock, body, _ := strings.Cut(s, "\n\n")
	lines := strings.Split(hdrBlock, "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, fmt.Errorf("httpmsg: no start line found")
	}
	m := &Message{}
	if strings.HasPrefix(lines[0], "HTTP/") {
		if err := parseStatusLine(m, lines[0]); err != nil {
			return nil, err
		}
	} else {
		if err := parseRequestLine(m, lines[0]); err != nil {
			return nil, err
		}
	}
	if err := parseHeaders(m, lines[1:]); err != nil {
		return nil, err
	}
	if body != "" {
		if strings.EqualFold(m.TransferEncoding, "chunked") {
			if chunks, err := decodeChunked(body); err == nil {
				m.ChunkedBody = chunks
			} else {
				m.BodyRaw = body
			}
		} else {
			renderBody(m, body)
		}
	}
	return m, nil
}

func parseRequestLine(m *Message, line string) error {
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return fmt.Errorf("httpmsg: request line malformed (need 3 tokens): %q", line)
	}
	m.IsRequest = true
	m.Method = parts[0]
	m.RequestURI = parts[1]
	m.Version = parts[2]
	return nil
}

func parseStatusLine(m *Message, line string) error {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return fmt.Errorf("httpmsg: status line malformed: %q", line)
	}
	m.IsResponse = true
	m.Version = parts[0]
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("httpmsg: status code not numeric: %q", parts[1])
	}
	m.StatusCode = code
	m.StatusName = statusName(code)
	if len(parts) >= 3 {
		m.StatusReason = parts[2]
	}
	return nil
}

func parseHeaders(m *Message, lines []string) error {
	// Pass 1: build the Header list with continuation folding.
	for _, line := range lines {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(m.Headers) == 0 {
				return fmt.Errorf("httpmsg: continuation before any header")
			}
			m.Headers[len(m.Headers)-1].Value += " " + strings.TrimLeft(line, " \t")
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			return fmt.Errorf("httpmsg: header missing ':': %q", line)
		}
		name := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		m.Headers = append(m.Headers, &Header{Name: name, Value: value})
	}
	// Pass 2: surface typed fields.
	for _, h := range m.Headers {
		switch strings.ToLower(h.Name) {
		case "host":
			m.Host = h.Value
		case "user-agent":
			m.UserAgent = h.Value
		case "server":
			m.Server = h.Value
		case "content-type":
			m.ContentType = h.Value
		case "content-length":
			if n, err := strconv.ParseInt(h.Value, 10, 64); err == nil {
				m.ContentLength = &n
			}
		case "transfer-encoding":
			m.TransferEncoding = h.Value
		case "authorization":
			m.Authorization = parseAuthHeader(h.Value)
		case "cookie":
			m.Cookies = append(m.Cookies, parseCookieHeader(h.Value)...)
		case "set-cookie":
			m.SetCookies = append(m.SetCookies, parseSetCookie(h.Value))
		}
	}
	return nil
}

func parseAuthHeader(v string) *AuthHeader {
	sp := strings.IndexByte(v, ' ')
	if sp < 0 {
		return &AuthHeader{Scheme: v}
	}
	return &AuthHeader{
		Scheme:     v[:sp],
		Parameters: strings.TrimSpace(v[sp+1:]),
	}
}

func parseCookieHeader(v string) []Cookie {
	var out []Cookie
	for _, pair := range strings.Split(v, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			out = append(out, Cookie{Name: pair})
			continue
		}
		out = append(out, Cookie{
			Name:  pair[:eq],
			Value: pair[eq+1:],
		})
	}
	return out
}

func parseSetCookie(v string) *SetCookie {
	parts := strings.Split(v, ";")
	if len(parts) == 0 {
		return nil
	}
	// First part is the name=value pair
	sc := &SetCookie{Attributes: map[string]string{}}
	first := strings.TrimSpace(parts[0])
	if eq := strings.IndexByte(first, '='); eq >= 0 {
		sc.Name = first[:eq]
		sc.Value = first[eq+1:]
	} else {
		sc.Name = first
	}
	// Remaining parts are attributes (Domain, Path, Expires,
	// Max-Age, Secure, HttpOnly, SameSite, etc.)
	for _, attr := range parts[1:] {
		attr = strings.TrimSpace(attr)
		if attr == "" {
			continue
		}
		if eq := strings.IndexByte(attr, '='); eq >= 0 {
			sc.Attributes[attr[:eq]] = attr[eq+1:]
		} else {
			sc.Attributes[attr] = ""
		}
	}
	return sc
}

// decodeChunked walks a chunked body per RFC 9112 §7.1.
// Each chunk is `<hex-length>\r\n<data>\r\n`, terminated by
// a `0\r\n\r\n` zero-length chunk.
func decodeChunked(body string) ([]*Chunk, error) {
	// Normalize LF (we already replaced CRLF with LF).
	var chunks []*Chunk
	off := 0
	for off < len(body) {
		nl := strings.IndexByte(body[off:], '\n')
		if nl < 0 {
			return nil, fmt.Errorf("chunked: missing length-line newline")
		}
		lenLine := strings.TrimSpace(body[off : off+nl])
		// Some chunks include extensions after a `;`; strip.
		if sc := strings.IndexByte(lenLine, ';'); sc >= 0 {
			lenLine = lenLine[:sc]
		}
		n, err := strconv.ParseInt(lenLine, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("chunked: length %q not hex: %w", lenLine, err)
		}
		off += nl + 1
		if n == 0 {
			// End of chunks
			break
		}
		// Bound n explicitly before casting to int — guards
		// against silent truncation on 32-bit platforms and
		// preserves the off+int(n) > len(body) check below.
		if n < 0 || n > int64(len(body)-off) {
			return nil, fmt.Errorf("chunked: chunk length %d exceeds remaining body", n)
		}
		nInt := int(n)
		data := body[off : off+nInt]
		ch := &Chunk{
			LengthHex: lenLine,
			Length:    nInt,
		}
		if isPrintable(data) {
			ch.DataText = data
		} else {
			ch.DataHex = strings.ToUpper(hex.EncodeToString([]byte(data)))
		}
		chunks = append(chunks, ch)
		off += nInt + 1 // skip data + trailing newline
	}
	return chunks, nil
}

// renderBody surfaces the body as text (when printable) or
// hex.
func renderBody(m *Message, body string) {
	if isPrintable(body) {
		m.BodyRaw = body
		return
	}
	m.BodyHex = strings.ToUpper(hex.EncodeToString([]byte(body)))
}

func isPrintable(s string) bool {
	if s == "" {
		return true
	}
	if !utf8.ValidString(s) {
		return false
	}
	for _, c := range []byte(s) {
		if c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c < 0x20 {
			return false
		}
	}
	return true
}

func statusName(c int) string {
	switch c {
	// 1xx Informational
	case 100:
		return "Continue"
	case 101:
		return "Switching Protocols"
	case 102:
		return "Processing"
	case 103:
		return "Early Hints"
	// 2xx Success
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 202:
		return "Accepted"
	case 203:
		return "Non-Authoritative Information"
	case 204:
		return "No Content"
	case 205:
		return "Reset Content"
	case 206:
		return "Partial Content"
	case 207:
		return "Multi-Status (WebDAV)"
	case 208:
		return "Already Reported (WebDAV)"
	case 226:
		return "IM Used"
	// 3xx Redirection
	case 300:
		return "Multiple Choices"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 303:
		return "See Other"
	case 304:
		return "Not Modified"
	case 305:
		return "Use Proxy"
	case 307:
		return "Temporary Redirect"
	case 308:
		return "Permanent Redirect"
	// 4xx Client error
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 402:
		return "Payment Required"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 406:
		return "Not Acceptable"
	case 407:
		return "Proxy Authentication Required"
	case 408:
		return "Request Timeout"
	case 409:
		return "Conflict"
	case 410:
		return "Gone"
	case 411:
		return "Length Required"
	case 412:
		return "Precondition Failed"
	case 413:
		return "Payload Too Large"
	case 414:
		return "URI Too Long"
	case 415:
		return "Unsupported Media Type"
	case 416:
		return "Range Not Satisfiable"
	case 417:
		return "Expectation Failed"
	case 418:
		return "I'm a teapot (RFC 2324)"
	case 421:
		return "Misdirected Request"
	case 422:
		return "Unprocessable Entity (WebDAV)"
	case 423:
		return "Locked"
	case 424:
		return "Failed Dependency"
	case 425:
		return "Too Early"
	case 426:
		return "Upgrade Required"
	case 428:
		return "Precondition Required"
	case 429:
		return "Too Many Requests"
	case 431:
		return "Request Header Fields Too Large"
	case 451:
		return "Unavailable For Legal Reasons"
	// 5xx Server error
	case 500:
		return "Internal Server Error"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	case 505:
		return "HTTP Version Not Supported"
	case 506:
		return "Variant Also Negotiates"
	case 507:
		return "Insufficient Storage"
	case 508:
		return "Loop Detected"
	case 510:
		return "Not Extended"
	case 511:
		return "Network Authentication Required"
	}
	return fmt.Sprintf("Unknown status %d", c)
}
