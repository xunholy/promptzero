// wsframe.go — host-side WebSocket frame decoder Spec.
// Wraps the internal/wsframe walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/wsframe"
)

func init() { //nolint:gochecknoinits
	Register(websocketFrameDecodeSpec)
}

var websocketFrameDecodeSpec = Spec{
	Name: "websocket_frame_decode",
	Description: "Decode one or more concatenated WebSocket frames per RFC 6455. " +
		"WebSocket is the post-Upgrade duplex framing that HTTP/1.x switches into " +
		"for long-lived browser↔server channels — every real-time web app (chat, " +
		"trading dashboards, multiplayer games, collaborative editors), every " +
		"GraphQL subscription, every MQTT-over-WebSocket bridge, every JSON-RPC " +
		"live feed runs on it. Natural follow-on to `http_message_decode` (which " +
		"surfaces the Upgrade handshake but stops at the 101 Switching Protocols " +
		"response). Decodes:\n\n" +
		"- **Frame header** (2 bytes minimum):\n" +
		"  - byte 0: FIN | RSV1 | RSV2 | RSV3 | opcode (4 bits)\n" +
		"  - byte 1: MASK | payload-len (7 bits)\n" +
		"- **Extended payload length** — when payload-len == 126, the next 2 bytes are " +
		"the actual uint16 BE length; when payload-len == 127, the next 8 bytes are " +
		"the actual uint64 BE length (MSB must be 0 per §5.2).\n" +
		"- **Mask key** — 4 bytes immediately after the length field when MASK == 1. " +
		"Per RFC 6455 §5.3, every client→server frame MUST be masked; server→client " +
		"frames MUST NOT be masked. The decoder demasks payload bytes automatically " +
		"and surfaces the mask key as hex for traceability.\n" +
		"- **Opcodes** (RFC 6455 §11.8): 0x0 Continuation / 0x1 Text (UTF-8) / 0x2 " +
		"Binary / 0x8 Close / 0x9 Ping / 0xA Pong. 0x3-0x7 are reserved non-control; " +
		"0xB-0xF are reserved control. Control-frame invariants enforced: payload ≤125 " +
		"bytes, must not be fragmented (FIN==1).\n" +
		"- **Close frame body** (opcode 0x8) — first 2 bytes are uint16 BE status code " +
		"per RFC 6455 §7.4.1; remaining bytes are optional UTF-8 reason text. Status " +
		"name table covers: 1000 Normal / 1001 Going Away / 1002 Protocol Error / 1003 " +
		"Unsupported Data / 1005 No Status (reserved) / 1006 Abnormal Closure (reserved) " +
		"/ 1007 Invalid Frame / 1008 Policy Violation / 1009 Message Too Big / 1010 " +
		"Mandatory Extension / 1011 Internal Error / 1012 Service Restart / 1013 Try " +
		"Again Later / 1014 Bad Gateway / 1015 TLS Handshake (reserved). Ranges: " +
		"3000-3999 library/framework-defined (IANA-registered), 4000-4999 application-" +
		"defined (private use), 1016-2999 reserved for future IETF use.\n" +
		"- **Text/Binary body rendering** — Text frames surface as a UTF-8 string when " +
		"printable, otherwise as hex; Binary frames always as hex. Ping/Pong payloads " +
		"are surfaced as text when printable (operators often echo a string for " +
		"liveness debugging).\n" +
		"- **Fragmentation detection** — FIN=0 + opcode!=0 marks a fragment opener; " +
		"FIN=0/1 + opcode=0 marks a Continuation. Notes are emitted to flag the " +
		"fragment shape; reassembly is left to the caller.\n" +
		"- **Multi-frame buffer walking** — a single buffer may carry several " +
		"concatenated frames (server→client streams often do this). The walker " +
		"iterates frame-by-frame until consumption and emits a per-frame breakdown " +
		"plus an opcode-sequence summary.\n" +
		"- **Notes** — RSV1=1 emits a 'payload may be permessage-deflate compressed " +
		"(RFC 7692)' note; RSV2/RSV3 emit an extension-defined-semantics note; FIN=0 " +
		"non-control emits a fragmentation note.\n\n" +
		"Pure offline parser — operators paste WebSocket frame bytes from a mitmproxy " +
		"capture, `wsdump` output, a Chrome DevTools Network panel export, a Burp " +
		"WebSocket history entry, or any frame-emitting tool and inspect every " +
		"documented field. Pairs with `http_message_decode` for the complete HTTP→WS " +
		"upgrade flow.\n\n" +
		"Out of scope (deferred): HTTP/1.x Upgrade handshake (already in " +
		"http_message_decode); per-message Deflate (RFC 7692) — RSV1 flagged and " +
		"compressed bytes surfaced raw; subprotocol-specific framing (MQTT-over-" +
		"WebSocket, STOMP, graphql-ws) — Text/Binary payloads are surfaced raw; " +
		"continuation-chain reassembly — fragments are flagged but not stitched.\n\n" +
		"Source: docs/catalog/gap-analysis.md (explicitly deferred from " +
		"http_message_decode iteration). Wrap-vs-native: native — RFC 6455 is fully " +
		"public, the wire format is a tight bit-packed header with simple length " +
		"escape hatches and a straightforward XOR-masking scheme.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"One or more concatenated WebSocket frame bytes as hex. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   websocketFrameDecodeHandler,
}

func websocketFrameDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("websocket_frame_decode: 'hex' is required")
	}
	res, err := wsframe.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("websocket_frame_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
