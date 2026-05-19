// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sip decodes SIP messages per RFC 3261. SIP
// (Session Initiation Protocol) is the dominant VoIP /
// video / IM signaling protocol on the internet — every PBX
// / softphone / SBC (Session Border Controller) / WebRTC
// gateway / unified-communications platform speaks it on
// UDP/5060 + TCP/5060 + TLS/5061 + WebSocket.
//
// # Wrap-vs-native judgement
//
// Native. SIP is a plain-text request/response protocol
// modelled on HTTP/1.1. The wire format is a start line
// (request or status) + header field list + blank line +
// optional body. Headers can use compact forms (m for
// Contact, v for Via, etc. per RFC 3261 §7.3.3). The
// optional body is typically SDP (RFC 4566) when carrying
// media negotiation. Pasting a message from Wireshark
// "Follow Stream" / tshark sip.* extraction / a captured
// SIP trace file / a PBX log line is enough — no SIP
// stack, no DNS lookup, no live network attach.
//
// # What this package covers
//
//   - **Start line dispatch**: request (METHOD URI VERSION)
//     vs response (VERSION CODE REASON), distinguished by
//     whether the first token starts with "SIP/" (response)
//     or any other text (request).
//   - **Request methods** (RFC 3261 + 3262 + 3265 + 3428 +
//     3515 + 3903): INVITE, ACK, BYE, CANCEL, OPTIONS,
//     REGISTER, PRACK, SUBSCRIBE, NOTIFY, PUBLISH, INFO,
//     REFER, MESSAGE, UPDATE.
//   - **Response status-code lookup** (~40 entries covering
//     all six classes):
//   - 1xx Provisional: 100 Trying, 180 Ringing, 181 Call
//     Is Being Forwarded, 182 Queued, 183 Session
//     Progress, 199 Early Dialog Terminated.
//   - 2xx Success: 200 OK, 202 Accepted, 204 No
//     Notification.
//   - 3xx Redirection: 300 Multiple Choices, 301 Moved
//     Permanently, 302 Moved Temporarily, 305 Use Proxy,
//     380 Alternative Service.
//   - 4xx Client error: 400 Bad Request, 401
//     Unauthorized, 403 Forbidden, 404 Not Found, 405
//     Method Not Allowed, 406 Not Acceptable, 407 Proxy
//     Authentication Required, 408 Request Timeout, 409
//     Conflict, 410 Gone, 413 Request Entity Too Large,
//     414 Request-URI Too Long, 415 Unsupported Media
//     Type, 420 Bad Extension, 422 Session Interval Too
//     Small, 423 Interval Too Brief, 480 Temporarily
//     Unavailable, 481 Call/Transaction Does Not Exist,
//     482 Loop Detected, 483 Too Many Hops, 484 Address
//     Incomplete, 485 Ambiguous, 486 Busy Here, 487
//     Request Terminated, 488 Not Acceptable Here, 491
//     Request Pending, 493 Undecipherable.
//   - 5xx Server error: 500 Server Internal Error, 501
//     Not Implemented, 502 Bad Gateway, 503 Service
//     Unavailable, 504 Server Time-out, 505 Version Not
//     Supported, 513 Message Too Large.
//   - 6xx Global failure: 600 Busy Everywhere, 603
//     Decline, 604 Does Not Exist Anywhere, 606 Not
//     Acceptable.
//   - **Header field parsing**: case-insensitive name match
//   - compact-form expansion (RFC 3261 §7.3.3): m→Contact,
//     v→Via, l→Content-Length, t→To, f→From, i→Call-ID,
//     e→Content-Encoding, k→Supported, c→Content-Type,
//     s→Subject. Multi-value headers preserved as ordered
//     lists.
//   - **Key envelope headers surfaced**: Via (route trace),
//     From, To, Call-ID, CSeq (sequence number + method),
//     Contact, Content-Type, Content-Length, Max-Forwards,
//     User-Agent / Server.
//   - **CSeq parsing**: sequence number + method broken
//     out (the only header with a fixed two-token grammar).
//   - **Body decode**: when Content-Type is application/sdp,
//     the body is walked as SDP (RFC 4566) with line-by-line
//     type-name lookup (v=version, o=origin, s=session-name,
//     i=session-info, u=URI, e=email, p=phone, c=connection-
//     info, b=bandwidth, t=timing, r=repeat, z=time-zones,
//     k=encryption, a=attributes, m=media-description) — for
//     media (m=) lines, the protocol + port + RTP-payload-
//     types are surfaced. For other Content-Types, the body
//     is exposed as raw text.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - Full SDP attribute (a=) semantic decode — `rtpmap`,
//     `fmtp`, `crypto`, `setup`, `fingerprint`, `ice-ufrag`,
//     `ice-pwd`, `candidate` are surfaced as raw text; full
//     ICE/DTLS-SRTP attribute parsing is a separate ~300
//     LoC effort.
//   - Authorization / WWW-Authenticate digest credential
//     parsing — the header value is surfaced but the
//     comma-separated key=value tokens aren't broken out.
//   - SIP message body parsing for non-SDP content types
//     (multipart/mixed, application/dialog-info+xml,
//     application/pidf+xml, etc.) — body is surfaced as raw
//     text.
//   - SIP-TLS transport details (the inner message decodes
//     identically once decrypted).
package sip

import (
	"fmt"
	"strconv"
	"strings"
)

// Message is the decoded SIP message view.
type Message struct {
	IsRequest     bool      `json:"is_request"`
	IsResponse    bool      `json:"is_response"`
	Method        string    `json:"method,omitempty"`
	RequestURI    string    `json:"request_uri,omitempty"`
	Version       string    `json:"version"`
	StatusCode    int       `json:"status_code,omitempty"`
	StatusReason  string    `json:"status_reason,omitempty"`
	StatusName    string    `json:"status_name,omitempty"`
	Headers       []*Header `json:"headers"`
	CallID        string    `json:"call_id,omitempty"`
	From          string    `json:"from,omitempty"`
	To            string    `json:"to,omitempty"`
	Via           []string  `json:"via,omitempty"`
	CSeq          *CSeq     `json:"cseq,omitempty"`
	Contact       []string  `json:"contact,omitempty"`
	ContentType   string    `json:"content_type,omitempty"`
	ContentLength int       `json:"content_length,omitempty"`
	MaxForwards   int       `json:"max_forwards,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
	Server        string    `json:"server,omitempty"`
	BodyRaw       string    `json:"body_raw,omitempty"`
	SDP           *SDP      `json:"sdp,omitempty"`
}

// Header is one header field. Multi-value headers (Via,
// Contact, Route) preserve their original order.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CSeq is the parsed CSeq header.
type CSeq struct {
	Sequence uint64 `json:"sequence"`
	Method   string `json:"method"`
}

// SDP is the decoded session description (RFC 4566).
type SDP struct {
	Version     string      `json:"version,omitempty"`
	Origin      string      `json:"origin,omitempty"`
	SessionName string      `json:"session_name,omitempty"`
	Connection  string      `json:"connection,omitempty"`
	Timing      string      `json:"timing,omitempty"`
	Media       []*SDPMedia `json:"media,omitempty"`
	OtherLines  []string    `json:"other_lines,omitempty"`
}

// SDPMedia is one m= line + its attributes.
type SDPMedia struct {
	Type         string   `json:"type"` // audio / video / application / etc.
	Port         int      `json:"port"`
	Protocol     string   `json:"protocol"` // RTP/AVP, RTP/SAVP, UDP, etc.
	PayloadTypes []string `json:"payload_types"`
	Attributes   []string `json:"attributes,omitempty"`
}

// Decode parses a SIP message (single envelope, headers
// terminated by a blank CRLF line, optional body).
func Decode(input string) (*Message, error) {
	s := strings.ReplaceAll(input, "\r\n", "\n")
	if s == "" {
		return nil, fmt.Errorf("sip: empty input")
	}
	// Split header block from body at the first blank line.
	hdrBlock, body, _ := strings.Cut(s, "\n\n")
	lines := strings.Split(hdrBlock, "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, fmt.Errorf("sip: no start line found")
	}
	m := &Message{}
	if strings.HasPrefix(lines[0], "SIP/") {
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
		m.BodyRaw = body
		if strings.HasPrefix(strings.ToLower(m.ContentType), "application/sdp") {
			m.SDP = parseSDP(body)
		}
	}
	return m, nil
}

func parseRequestLine(m *Message, line string) error {
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return fmt.Errorf("sip: request line missing fields: %q", line)
	}
	m.IsRequest = true
	m.Method = parts[0]
	// Request URI may contain spaces if quoted, but per RFC
	// it's a SIP URI / SIPS URI / absolute URI with no
	// embedded whitespace — last token is the version, rest
	// is URI.
	m.Version = parts[len(parts)-1]
	m.RequestURI = strings.Join(parts[1:len(parts)-1], " ")
	return nil
}

func parseStatusLine(m *Message, line string) error {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return fmt.Errorf("sip: status line malformed: %q", line)
	}
	m.IsResponse = true
	m.Version = parts[0]
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("sip: status code not numeric: %q", parts[1])
	}
	m.StatusCode = code
	m.StatusName = statusName(code)
	if len(parts) >= 3 {
		m.StatusReason = parts[2]
	}
	return nil
}

func parseHeaders(m *Message, lines []string) error {
	// First pass: build the Header list, folding continuation
	// lines into the previous header value.
	for _, line := range lines {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(m.Headers) == 0 {
				return fmt.Errorf("sip: continuation before any header")
			}
			m.Headers[len(m.Headers)-1].Value += " " + strings.TrimLeft(line, " \t")
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			return fmt.Errorf("sip: header missing ':': %q", line)
		}
		rawName := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		m.Headers = append(m.Headers, &Header{
			Name:  expandCompactName(rawName),
			Value: value,
		})
	}
	// Second pass: surface key envelope headers into typed
	// fields, using the now-fully-folded values.
	for _, h := range m.Headers {
		switch strings.ToLower(h.Name) {
		case "call-id":
			m.CallID = h.Value
		case "from":
			m.From = h.Value
		case "to":
			m.To = h.Value
		case "via":
			m.Via = append(m.Via, h.Value)
		case "contact":
			m.Contact = append(m.Contact, h.Value)
		case "content-type":
			m.ContentType = h.Value
		case "content-length":
			if n, err := strconv.Atoi(h.Value); err == nil {
				m.ContentLength = n
			}
		case "max-forwards":
			if n, err := strconv.Atoi(h.Value); err == nil {
				m.MaxForwards = n
			}
		case "user-agent":
			m.UserAgent = h.Value
		case "server":
			m.Server = h.Value
		case "cseq":
			m.CSeq = parseCSeq(h.Value)
		}
	}
	return nil
}

func parseCSeq(v string) *CSeq {
	parts := strings.Fields(v)
	if len(parts) != 2 {
		return nil
	}
	n, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return nil
	}
	return &CSeq{Sequence: n, Method: parts[1]}
}

// expandCompactName turns the single-letter compact-form
// header names into their canonical names per RFC 3261 §7.3.3
// + extensions.
func expandCompactName(raw string) string {
	if len(raw) != 1 {
		return raw
	}
	switch strings.ToLower(raw) {
	case "m":
		return "Contact"
	case "v":
		return "Via"
	case "l":
		return "Content-Length"
	case "t":
		return "To"
	case "f":
		return "From"
	case "i":
		return "Call-ID"
	case "e":
		return "Content-Encoding"
	case "k":
		return "Supported"
	case "c":
		return "Content-Type"
	case "s":
		return "Subject"
	case "b":
		return "Referred-By"
	case "r":
		return "Refer-To"
	case "o":
		return "Event"
	case "u":
		return "Allow-Events"
	}
	return raw
}

// parseSDP walks an RFC 4566 session description into a
// structured view.
func parseSDP(body string) *SDP {
	sdp := &SDP{}
	var current *SDPMedia
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		key := line[0]
		val := line[2:]
		switch key {
		case 'v':
			sdp.Version = val
		case 'o':
			sdp.Origin = val
		case 's':
			sdp.SessionName = val
		case 'c':
			if current == nil {
				sdp.Connection = val
			}
		case 't':
			sdp.Timing = val
		case 'm':
			current = parseSDPMedia(val)
			if current != nil {
				sdp.Media = append(sdp.Media, current)
			}
		case 'a':
			if current != nil {
				current.Attributes = append(current.Attributes, val)
			} else {
				sdp.OtherLines = append(sdp.OtherLines, "a="+val)
			}
		default:
			sdp.OtherLines = append(sdp.OtherLines, string(key)+"="+val)
		}
	}
	return sdp
}

// parseSDPMedia parses an m= line: media-type port[/portcount]
// proto fmt+
func parseSDPMedia(val string) *SDPMedia {
	parts := strings.Fields(val)
	if len(parts) < 4 {
		return nil
	}
	port := 0
	portTok := parts[1]
	// Strip optional /portcount suffix.
	if slash := strings.IndexByte(portTok, '/'); slash > 0 {
		portTok = portTok[:slash]
	}
	if n, err := strconv.Atoi(portTok); err == nil {
		port = n
	}
	return &SDPMedia{
		Type:         parts[0],
		Port:         port,
		Protocol:     parts[2],
		PayloadTypes: parts[3:],
	}
}

func statusName(c int) string {
	switch c {
	// 1xx Provisional
	case 100:
		return "Trying"
	case 180:
		return "Ringing"
	case 181:
		return "Call Is Being Forwarded"
	case 182:
		return "Queued"
	case 183:
		return "Session Progress"
	case 199:
		return "Early Dialog Terminated"
	// 2xx Success
	case 200:
		return "OK"
	case 202:
		return "Accepted"
	case 204:
		return "No Notification"
	// 3xx Redirection
	case 300:
		return "Multiple Choices"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Moved Temporarily"
	case 305:
		return "Use Proxy"
	case 380:
		return "Alternative Service"
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
	case 413:
		return "Request Entity Too Large"
	case 414:
		return "Request-URI Too Long"
	case 415:
		return "Unsupported Media Type"
	case 416:
		return "Unsupported URI Scheme"
	case 420:
		return "Bad Extension"
	case 421:
		return "Extension Required"
	case 422:
		return "Session Interval Too Small"
	case 423:
		return "Interval Too Brief"
	case 480:
		return "Temporarily Unavailable"
	case 481:
		return "Call/Transaction Does Not Exist"
	case 482:
		return "Loop Detected"
	case 483:
		return "Too Many Hops"
	case 484:
		return "Address Incomplete"
	case 485:
		return "Ambiguous"
	case 486:
		return "Busy Here"
	case 487:
		return "Request Terminated"
	case 488:
		return "Not Acceptable Here"
	case 491:
		return "Request Pending"
	case 493:
		return "Undecipherable"
	// 5xx Server error
	case 500:
		return "Server Internal Error"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Server Time-out"
	case 505:
		return "Version Not Supported"
	case 513:
		return "Message Too Large"
	// 6xx Global failure
	case 600:
		return "Busy Everywhere"
	case 603:
		return "Decline"
	case 604:
		return "Does Not Exist Anywhere"
	case 606:
		return "Not Acceptable"
	}
	return fmt.Sprintf("Unknown status %d", c)
}
