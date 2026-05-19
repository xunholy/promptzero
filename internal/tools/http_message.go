// http_message.go — host-side HTTP/1.x message dissector
// Spec, delegating to the internal/httpmsg package for the
// walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/httpmsg"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(httpMessageDecodeSpec)
}

var httpMessageDecodeSpec = Spec{
	Name: "http_message_decode",
	Description: "Decode an HTTP/1.x request or response per RFC 9112 + RFC 9110. HTTP is " +
		"the foundational application-layer protocol of the web — every browser-server " +
		"interaction, every REST API call, every webhook delivery, every internal " +
		"microservice-to-service call (when not gRPC) speaks it. Decodes:\n\n" +
		"- **Start-line dispatch**: auto-detect request (METHOD URI VERSION) vs response " +
		"(VERSION CODE REASON) by whether the first token starts with 'HTTP/'.\n" +
		"- **Request methods**: GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, " +
		"PATCH (RFC 5789), plus WebDAV methods (PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, " +
		"LOCK, UNLOCK per RFC 4918).\n" +
		"- **~50-entry status-code name table** across all 5 response classes:\n" +
		"  - 1xx Informational: 100 Continue / 101 Switching Protocols / 102 Processing " +
		"/ 103 Early Hints.\n" +
		"  - 2xx Success: 200 OK / 201 Created / 202 Accepted / 203 Non-Authoritative / " +
		"204 No Content / 205 Reset Content / 206 Partial Content / 207 Multi-Status / " +
		"208 Already Reported / 226 IM Used.\n" +
		"  - 3xx Redirection: 300 Multiple Choices / 301 Moved Permanently / 302 Found " +
		"/ 303 See Other / 304 Not Modified / 305 Use Proxy / 307 Temporary Redirect / " +
		"308 Permanent Redirect.\n" +
		"  - 4xx Client error: 400 Bad Request / 401 Unauthorized / 402 Payment " +
		"Required / 403 Forbidden / 404 Not Found / 405 Method Not Allowed / 406 Not " +
		"Acceptable / 407 Proxy Auth Required / 408 Request Timeout / 409 Conflict / " +
		"410 Gone / 411-418 (including 418 I'm a teapot RFC 2324) / 421-426 / 428-431 / " +
		"451 Unavailable For Legal Reasons.\n" +
		"  - 5xx Server error: 500 Internal Server Error / 501 Not Implemented / 502 " +
		"Bad Gateway / 503 Service Unavailable / 504 Gateway Timeout / 505 HTTP Version " +
		"Not Supported / 506-508 / 510-511.\n" +
		"- **Header field parsing**: case-insensitive name match + line continuation " +
		"folding (deprecated but still seen in legacy traffic) + multi-value preservation " +
		"as ordered lists.\n" +
		"- **Typed envelope fields surfaced**: Host, User-Agent, Server, Content-Type, " +
		"Content-Length, Transfer-Encoding, Authorization (with scheme breakout — " +
		"Basic / Bearer / Digest), Cookie (parsed into key=value pairs), Set-Cookie " +
		"(parsed into name + value + attribute map for Path / Domain / Expires / " +
		"Max-Age / HttpOnly / Secure / SameSite / etc.).\n" +
		"- **Body handling**:\n" +
		"  - **Content-Length**: read exactly N bytes, surface as text if printable " +
		"or hex if binary.\n" +
		"  - **Transfer-Encoding: chunked**: decode hex-length-prefixed chunks per RFC " +
		"9112 §7.1 (chunk extensions after ';' tolerated). Each chunk surfaced with " +
		"length + data (text or hex).\n\n" +
		"Pure offline parser — operators paste an HTTP message from a Wireshark Follow " +
		"Stream view, a mitmproxy / Burp / ZAP export, curl -v output, a web-server " +
		"access log replay, or any HTTP-emitting tool and inspect every documented " +
		"field. Pairs with tls_handshake_decode + x509_certificate_decode + jwt_decode " +
		"for the complete HTTPS-stack decode flow.\n\n" +
		"Out of scope (deferred to future iterations): HTTP/2 binary framing (RFC 9113) " +
		"and HTTP/3 (RFC 9114); HPACK header decompression (RFC 7541); WebSocket frames " +
		"(RFC 6455 — Upgrade header preserved verbatim but post-upgrade frames need a " +
		"separate Spec); TLS layer (feed cleartext after decryption); trailer headers " +
		"(surfaced as raw text in trailing body); multipart bodies (multipart/form-data " +
		", multipart/mixed — body is raw bytes; multipart parsing is a separate effort).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational web-protocol decode space — " +
		"essential for any HTTP traffic analysis workflow). Wrap-vs-native: native — " +
		"RFC 9112 + 9110 are fully public, wire format is plain-text request/response " +
		"with simple body framing.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"message":{"type":"string","description":"Full HTTP/1.x message including start line, headers, blank CRLF line, and optional body. CRLF and LF line endings both accepted."}
		},
		"required":["message"]
	}`),
	Required:  []string{"message"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   httpMessageDecodeHandler,
}

func httpMessageDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "message")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("http_message_decode: 'message' is required")
	}
	res, err := httpmsg.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("http_message_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
