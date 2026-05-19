// http2.go — host-side HTTP/2 frame decoder Spec.
// Wraps the internal/http2 walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/http2"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(http2FrameDecodeSpec)
}

var http2FrameDecodeSpec = Spec{
	Name: "http2_frame_decode",
	Description: "Decode one or more concatenated HTTP/2 frames per RFC 9113. HTTP/2 is " +
		"the dominant request-multiplexing protocol on the modern web — every gRPC " +
		"call, every modern browser-to-server HTTPS connection, every cloud-native API " +
		"that ALPN-negotiates 'h2' rides on it. Natural companion to " +
		"`http_message_decode` (HTTP/1.x) + `websocket_frame_decode` (WebSocket) for " +
		"the full HTTP stack. Decodes:\n\n" +
		"- **Connection preface** — the literal 24-byte preface " +
		"`PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n` sent by the client immediately after " +
		"the upgrade. Auto-detected and surfaced as a synthetic 'preface' frame at the " +
		"start of the stream.\n" +
		"- **Frame header** (9 bytes fixed): Length (24-bit BE payload-length) + Type " +
		"(1 byte) + Flags (1 byte) + R+Stream Identifier (32-bit; high bit reserved, " +
		"31-bit stream ID). Stream ID 0 is the connection-level stream (used for " +
		"SETTINGS / PING / GOAWAY).\n" +
		"- **10 frame types** (RFC 9113 §6) with per-type bodies:\n" +
		"  - **DATA (0x0)** — optional pad-length + data + padding. END_STREAM flag " +
		"marks the last frame in a request/response body.\n" +
		"  - **HEADERS (0x1)** — optional pad-length + optional priority block " +
		"(exclusive+stream-dep+weight) + HPACK-compressed header block + padding. " +
		"END_HEADERS marks the last header frame in a CONTINUATION chain; END_STREAM " +
		"marks no request body.\n" +
		"  - **PRIORITY (0x2)** (deprecated in RFC 9113) — exclusive bit + stream " +
		"dependency + weight.\n" +
		"  - **RST_STREAM (0x3)** — error code with **14-entry name table**: NO_ERROR " +
		"/ PROTOCOL_ERROR / INTERNAL_ERROR / FLOW_CONTROL_ERROR / SETTINGS_TIMEOUT / " +
		"STREAM_CLOSED / FRAME_SIZE_ERROR / REFUSED_STREAM / CANCEL / COMPRESSION_ERROR " +
		"/ CONNECT_ERROR / ENHANCE_YOUR_CALM / INADEQUATE_SECURITY / HTTP_1_1_REQUIRED.\n" +
		"  - **SETTINGS (0x4)** — list of (Identifier+Value) pairs with **7-entry " +
		"parameter table**: HEADER_TABLE_SIZE / ENABLE_PUSH / MAX_CONCURRENT_STREAMS / " +
		"INITIAL_WINDOW_SIZE / MAX_FRAME_SIZE / MAX_HEADER_LIST_SIZE / " +
		"ENABLE_CONNECT_PROTOCOL (RFC 8441 — for WebSockets over h2). ACK flag = " +
		"empty body acknowledgement.\n" +
		"  - **PUSH_PROMISE (0x5)** (deprecated in RFC 9113) — optional pad-length + " +
		"promised stream ID + HPACK header block.\n" +
		"  - **PING (0x6)** — 8 bytes opaque payload. ACK flag = reply to a peer's " +
		"PING. Used as keep-alive + RTT probe.\n" +
		"  - **GOAWAY (0x7)** — last stream ID + error code + opaque debug data.\n" +
		"  - **WINDOW_UPDATE (0x8)** — 31-bit window size increment (must be > 0).\n" +
		"  - **CONTINUATION (0x9)** — HPACK header block fragment (continuation of " +
		"HEADERS or PUSH_PROMISE).\n" +
		"- **Multi-frame walker** — one buffer may carry multiple concatenated frames; " +
		"iterator walks frame-by-frame until consumption and emits a per-frame " +
		"breakdown plus an opcode-sequence summary string.\n" +
		"- **Flags decoding per frame type** — END_STREAM / END_HEADERS / PADDED / " +
		"PRIORITY / ACK flags surfaced with their type-specific names.\n\n" +
		"Pure offline parser — operators paste TCP-stream bytes from a Wireshark Follow " +
		"HTTP/2 view, a `curl --http2 -v` trace, a Go `httptrace` dump, an h2load " +
		"benchmark capture, or any HTTP/2-emitting tool and inspect every documented " +
		"frame field.\n\n" +
		"Out of scope (deferred): HPACK header decompression (RFC 7541 — the static-" +
		"table indexing + Huffman coding requires session state since the dynamic " +
		"table evolves across frames; compressed bytes are surfaced as hex); TLS layer " +
		"(operators feed cleartext frame bytes after TLS decryption); HTTP/2 " +
		"connection state machine (frames decoded individually; stream-state tracking " +
		"belongs in a session-tracker); HTTP/3 (RFC 9114 — wholly different wire format " +
		"with QPACK + QUIC); WebSocket-over-HTTP/2 (RFC 8441 :protocol pseudo-header — " +
		"surfaced via the HPACK bytes when present).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational web protocol — completes " +
		"the HTTP/1.x + WebSocket + HTTP/2 decode stack). Wrap-vs-native: native — " +
		"RFC 9113 is fully public; wire format is a tight 9-byte frame header plus " +
		"per-type fixed-field bodies, no encryption at this layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"One or more concatenated HTTP/2 frame bytes as hex (optionally preceded by the 24-byte client connection preface). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   http2FrameDecodeHandler,
}

func http2FrameDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("http2_frame_decode: 'hex' is required")
	}
	res, err := http2.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("http2_frame_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
