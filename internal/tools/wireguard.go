// wireguard.go — host-side WireGuard packet decoder Spec.
// Wraps the internal/wireguard walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/wireguard"
)

func init() { //nolint:gochecknoinits
	Register(wireguardPacketDecodeSpec)
}

var wireguardPacketDecodeSpec = Spec{
	Name: "wireguard_packet_decode",
	Description: "Decode a WireGuard UDP packet per the official protocol specification " +
		"(https://www.wireguard.com/protocol/). WireGuard is the modern VPN protocol of " +
		"choice — shipped in the Linux kernel since 5.6, used as the wire format for " +
		"Tailscale / NetBird / Cloudflare WARP / Mullvad's protocol stack, and rapidly " +
		"becoming the corporate / consumer VPN default. Pure offline parser. Decodes:\n\n" +
		"- **Auto-detect by leading message-type byte**: 0x01 Handshake Initiation, " +
		"0x02 Handshake Response, 0x03 Cookie Reply, 0x04 Transport Data. The 3 " +
		"reserved bytes after the type are required to be zero per spec — non-zero " +
		"values are surfaced as a note (some middleboxes / forks abuse them).\n" +
		"- **Handshake Initiation** (148 bytes fixed): sender index (u32 LE) + " +
		"unencrypted ephemeral Curve25519 public key (32 bytes) + encrypted static " +
		"key (32 plaintext + 16 ChaCha20Poly1305 AEAD tag = 48 bytes) + encrypted " +
		"timestamp (12 plaintext TAI64N + 16 AEAD tag = 28 bytes) + MAC1 (16-byte " +
		"Blake2s(MAC1_key || msg) cookie precommitment) + MAC2 (16 bytes — zero when " +
		"no cookie has been applied, populated only after a Cookie Reply has been " +
		"received).\n" +
		"- **Handshake Response** (92 bytes fixed): sender index + receiver index + " +
		"unencrypted ephemeral key (32 bytes) + encrypted nothing (0+16 AEAD — proves " +
		"the responder's static keypair was used by encrypting an empty plaintext) + " +
		"MAC1 + MAC2.\n" +
		"- **Cookie Reply** (64 bytes fixed): receiver index + nonce (24 bytes " +
		"XChaCha20Poly1305) + encrypted cookie (16 plaintext + 16 AEAD tag = 32 " +
		"bytes). Sent by the responder when it's under load / wants to rate-limit " +
		"specific initiators.\n" +
		"- **Transport Data** (variable, ≥ 32 bytes): receiver index + counter (u64 " +
		"LE — increments per direction; serves as replay-protection nonce) + " +
		"encrypted encapsulated packet (≥0 bytes plaintext IP + 16-byte Poly1305 " +
		"tag). Surfaces the inner-plaintext length (total - 16 byte AEAD tag).\n" +
		"- **Keep-alive detection** — a Transport Data packet with an empty inner " +
		"plaintext (just the 16-byte Poly1305 tag remaining) is flagged as a " +
		"keep-alive. WireGuard clients send these every 25 seconds when idle to " +
		"maintain NAT-table state.\n" +
		"- **MAC2 zero detection** — handshake messages with all-zero MAC2 are " +
		"flagged as 'no cookie applied' (the operator can correlate Cookie Reply " +
		"messages with subsequent re-initiations).\n\n" +
		"Pure offline parser — operators paste UDP payload bytes from a Wireshark " +
		"`wg` dissector view, a `tcpdump -X udp port 51820` line, an `iptables -j " +
		"LOG` capture, or any WireGuard wire-format dump and inspect every documented " +
		"field. Useful for VPN-traffic forensics (replay-counter analysis, cookie/MAC " +
		"correlation, keep-alive cadence) without needing the secret key material.\n\n" +
		"Out of scope (deferred): decryption (operators need static + ephemeral " +
		"keypair material plus the Noise-IK handshake state — a separate Spec); " +
		"the Noise IK handshake state machine; UDP / IP framing (feed the UDP " +
		"payload after the IP+UDP headers); MAC1 / MAC2 verification (would require " +
		"the responder's static public key — values are surfaced so an operator with " +
		"the key can re-derive); Cookie reply re-derivation (Blake2s of source IP + " +
		"port + responder mac1_key).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational VPN protocol — modern " +
		"replacement for OpenVPN / IPsec / IKEv2 in many deployments). Wrap-vs-native: " +
		"native — the wire format is a tight fixed-layout binary header with no " +
		"variable-length integers, no version negotiation, no extensions, no " +
		"compression at this layer. The cryptographic primitives (Curve25519 / " +
		"Blake2s / ChaCha20Poly1305 / XChaCha20Poly1305) are NOT decoded; encrypted " +
		"material is surfaced as hex for traceability.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"WireGuard UDP-payload bytes as hex. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wireguardPacketDecodeHandler,
}

func wireguardPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("wireguard_packet_decode: 'hex' is required")
	}
	res, err := wireguard.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("wireguard_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
