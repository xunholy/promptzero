// sip.go — host-side SIP message dissector Spec, delegating
// to the internal/sip package for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/sip"
)

func init() { //nolint:gochecknoinits
	Register(sipMessageDecodeSpec)
}

var sipMessageDecodeSpec = Spec{
	Name: "sip_message_decode",
	Description: "Decode a SIP (Session Initiation Protocol) message per RFC 3261. SIP is " +
		"the dominant VoIP / video / IM signaling protocol on the internet — every PBX / " +
		"softphone / SBC (Session Border Controller) / WebRTC gateway / unified-" +
		"communications platform speaks it on UDP/5060 + TCP/5060 + TLS/5061 + " +
		"WebSocket. Decodes:\n\n" +
		"- **Start-line dispatch**: auto-detect request (METHOD URI VERSION) vs response " +
		"(VERSION CODE REASON) by whether the first token starts with 'SIP/'.\n" +
		"- **Request methods** (RFC 3261 + 3262 + 3265 + 3428 + 3515 + 3903): INVITE, " +
		"ACK, BYE, CANCEL, OPTIONS, REGISTER, PRACK, SUBSCRIBE, NOTIFY, PUBLISH, INFO, " +
		"REFER, MESSAGE, UPDATE.\n" +
		"- **Response status-code lookup** (~40 entries across all 6 classes):\n" +
		"  - 1xx Provisional: 100 Trying / 180 Ringing / 181 Forwarded / 182 Queued / " +
		"183 Session Progress / 199 Early Dialog Terminated.\n" +
		"  - 2xx Success: 200 OK / 202 Accepted / 204 No Notification.\n" +
		"  - 3xx Redirection: 300 Multiple Choices / 301 Moved Permanently / 302 Moved " +
		"Temporarily / 305 Use Proxy / 380 Alternative Service.\n" +
		"  - 4xx Client error: 400 Bad Request / 401 Unauthorized / 403 Forbidden / 404 " +
		"Not Found / 405 Method Not Allowed / 407 Proxy Authentication Required / 408 " +
		"Request Timeout / 410 Gone / 415 Unsupported Media Type / 420 Bad Extension / " +
		"480 Temporarily Unavailable / 481 Call/Transaction Does Not Exist / 482 Loop " +
		"Detected / 483 Too Many Hops / 486 Busy Here / 487 Request Terminated / 488 " +
		"Not Acceptable Here / 491 Request Pending.\n" +
		"  - 5xx Server error: 500 Server Internal Error / 501 Not Implemented / 502 " +
		"Bad Gateway / 503 Service Unavailable / 504 Server Time-out / 505 Version Not " +
		"Supported / 513 Message Too Large.\n" +
		"  - 6xx Global failure: 600 Busy Everywhere / 603 Decline / 604 Does Not Exist " +
		"Anywhere / 606 Not Acceptable.\n" +
		"- **Header field parsing** with case-insensitive name match + compact-form " +
		"expansion (RFC 3261 §7.3.3): m→Contact, v→Via, l→Content-Length, t→To, " +
		"f→From, i→Call-ID, e→Content-Encoding, k→Supported, c→Content-Type, s→Subject. " +
		"Multi-value headers (Via, Contact, Route) preserved as ordered lists. Line " +
		"continuation (lines starting with whitespace) folded into the previous header.\n" +
		"- **Key envelope headers surfaced** as typed fields: Via (route trace), From, " +
		"To, Call-ID, CSeq (sequence number + method broken out), Contact, Content-Type, " +
		"Content-Length, Max-Forwards, User-Agent, Server.\n" +
		"- **CSeq parsing**: sequence number + method split (the only header with a " +
		"fixed two-token grammar).\n" +
		"- **SDP body decode** (RFC 4566) when Content-Type is application/sdp: " +
		"v=version + o=origin + s=session-name + c=connection-info + t=timing + m=media-" +
		"description (audio/video/application/etc. + port + protocol + payload types) + " +
		"a=attribute lines collected per media section.\n\n" +
		"Pure offline parser — operators paste a SIP message from a Wireshark Follow " +
		"Stream view, a tshark sip.* extraction, a captured SIP trace file, a PBX log " +
		"line (Asterisk / FreeSWITCH / Kamailio / OpenSIPS), or a SBC audit trail and " +
		"inspect every documented field without re-attaching to the call. Pairs with " +
		"stun_packet_decode + ip_packet_decode for the complete VoIP/WebRTC decode " +
		"stack: IP/UDP for transport, STUN for NAT discovery, SIP for call signaling, " +
		"SDP for media negotiation.\n\n" +
		"Out of scope (deferred to future iterations): full SDP attribute (a=) semantic " +
		"decode for rtpmap / fmtp / crypto / setup / fingerprint / ice-ufrag / ice-pwd / " +
		"candidate (surfaced as raw text); Authorization / WWW-Authenticate digest " +
		"credential parsing (header value surfaced but comma-separated tokens not " +
		"broken out); non-SDP body content types (multipart/mixed, application/" +
		"dialog-info+xml, application/pidf+xml — body surfaced as raw text); SIP-TLS " +
		"transport details.\n\n" +
		"Source: docs/catalog/gap-analysis.md (VoIP / WebRTC signaling decode space). " +
		"Wrap-vs-native: native — RFC 3261 is fully public, wire format is plain-text " +
		"HTTP-like grammar with compact-form expansion, dispatch is method/status " +
		"lookup.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"message":{"type":"string","description":"Full SIP message including start line, headers, blank CRLF line, and optional body. CRLF and LF line endings both accepted."}
		},
		"required":["message"]
	}`),
	Required:  []string{"message"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   sipMessageDecodeHandler,
}

func sipMessageDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "message")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("sip_message_decode: 'message' is required")
	}
	res, err := sip.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("sip_message_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
