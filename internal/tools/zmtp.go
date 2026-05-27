// zmtp.go — host-side ZMTP wire-protocol decoder Spec.
// Wraps the internal/zmtp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/zmtp"
)

func init() { //nolint:gochecknoinits
	Register(zmtpDecodeSpec)
}

var zmtpDecodeSpec = Spec{
	Name: "zmtp_decode",
	Description: "Decode a ZMTP (ZeroMQ Message Transport Protocol) wire-protocol " +
		"frame. ZMTP is the transport layer for every ZeroMQ socket — runs " +
		"on any TCP port; commonly TCP/5555-5560 (default ZMQ_REQ/REP " +
		"services), TCP/5570-5580 (financial data feeds), TCP/9000-9999 " +
		"(custom deployments). ZeroMQ is widely used in high-frequency " +
		"trading platforms, market-data feeds, scientific computing " +
		"(Jupyter kernel protocol is ZMTP), distributed task-queue systems, " +
		"industrial control and telemetry backplanes.\n\n" +
		"**Security posture**: default ZeroMQ uses the NULL mechanism — NO " +
		"authentication and NO encryption. Any TCP-reachable process can " +
		"send and receive messages. ZeroMQ pub/sub with NULL allows " +
		"unauthenticated subscription to any topic. PLAIN mechanism " +
		"transmits username + password in cleartext; passive capture yields " +
		"credentials immediately. CURVE (CurveZMQ / NaCl box) is the only " +
		"secure option. Shodan and ZGrab routinely find exposed ZMTP sockets " +
		"on the public internet; exposed sockets allow message injection, " +
		"subscription interception, and in PUSH/PULL topologies arbitrary " +
		"task injection into worker pools.\n\n" +
		"The wire format leaks: **ZMTP version fingerprint** — version " +
		"(major.minor) in the 64-byte greeting reveals ZMTP 3.0 (ZeroMQ " +
		"≥ 4.0), 3.1 (ZeroMQ ≥ 4.2), or 2.0 (legacy 3.x/2.x); **security " +
		"mechanism** — mechanism field in greeting names NULL (no auth) / " +
		"PLAIN (cleartext creds) / CURVE (NaCl encrypted) / GSSAPI " +
		"(Kerberos); **role disclosure** — as_server flag; **socket type + " +
		"identity** — READY command properties contain Socket-Type (REQ / " +
		"REP / DEALER / ROUTER / PUB / SUB / XPUB / XSUB / PUSH / PULL / " +
		"PAIR / STREAM) and optionally Identity, revealing the topology " +
		"role; **PING/PONG heartbeat** — ZMTP 3.1 heartbeat commands.\n\n" +
		"Decodes:\n\n" +
		"- **64-byte ZMTP 3.x greeting** — signature (0xFF + 8 padding + " +
		"0x7F at offsets 0 and 9) + version (major.minor) + mechanism " +
		"(20-byte null-padded string) + as_server flag + 31-byte filler. " +
		"Surfaces `is_greeting` + `version_major` + `version_minor` + " +
		"`mechanism` + `mechanism_name` + `as_server`.\n" +
		"- **ZMTP 2.0 greeting detection** — same signature but version " +
		"byte 0x01 + socket_type byte; surfaces `socket_type`.\n" +
		"- **Security mechanism classification** — NULL → `mechanism_name` " +
		"\"No authentication\"; PLAIN → \"Cleartext password\" + " +
		"`is_cleartext_auth=true` + `cleartext_auth_flag`; CURVE → " +
		"\"CurveZMQ encryption\"; GSSAPI → \"Kerberos\".\n" +
		"- **Command frame walking** — flags byte (bit 2 = command) + 1-byte " +
		"or 8-byte size (long frame bit 1) + 1-byte name_length + command " +
		"name + command data. Surfaces `is_command` + `command_name`.\n" +
		"- **READY command property walker** — 4-byte BE name_length + name " +
		"+ 4-byte BE value_length + value; surfaces `socket_type` and " +
		"`identity`.\n" +
		"- **Message frame detection** — flags byte with bit 2 clear; " +
		"surfaces `is_message`.\n\n" +
		"Pure offline parser — paste ZMTP bytes (TCP-segment payload hex; " +
		"any TCP port the ZMQ socket is bound to) from tcpdump / Wireshark " +
		"ZeroMQ dissector and get the per-frame breakdown.\n\n" +
		"Out of scope: CURVE/NaCl inner decryption (payload opaque — only " +
		"mechanism name decoded); PLAIN credential extraction (username + " +
		"password in HELLO command deliberately NOT decoded — presence noted " +
		"only); GSSAPI inner Kerberos blob (use `kerberos_decode`); " +
		"application message content (body bytes surfaced as total count " +
		"only); ZMTP over IPC / inproc (same frame format but Unix-domain " +
		"or in-process transport).\n\n" +
		"Source: gap analysis (distributed systems / financial messaging " +
		"backbone — canonical ZMTP dissector for security-mechanism " +
		"enumeration + NULL unauthenticated-exposure detection + PLAIN " +
		"cleartext-credential flagging + CURVE encryption confirmation + " +
		"socket-type topology disclosure; pairs with `kafka_decode` and " +
		"`amqp091_decode` for the enterprise messaging pentest surface). " +
		"Wrap-vs-native: native — ZMTP 3.x spec is publicly available at " +
		"rfc.zeromq.org; greeting is a fixed 64-byte structure with known " +
		"byte offsets; command frames have a deterministic flag+size+name " +
		"layout; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"ZMTP wire-protocol frame bytes as hex (the TCP-segment payload; any TCP port the ZMQ socket is bound to — commonly TCP/5555-5560). Feed one frame at a time: a 64-byte greeting, a greeting+READY concatenation, or a standalone command/message frame. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   zmtpDecodeHandler,
}

func zmtpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("zmtp_decode: 'hex' is required")
	}
	res, err := zmtp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("zmtp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
