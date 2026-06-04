// quic.go — host-side QUIC long-header packet decoder Spec.
// Wraps the internal/quic walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/quic"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(quicLongHeaderDecodeSpec)
}

var quicLongHeaderDecodeSpec = Spec{
	Name: "quic_long_header_decode",
	Description: "Decode a QUIC long-header packet per RFC 9000. QUIC is the modern " +
		"UDP-based transport that underpins HTTP/3 (every major CDN — Cloudflare / " +
		"Fastly / Akamai / Google Cloud CDN / AWS CloudFront / Vercel — serves HTTP/3 " +
		"by default to modern browsers), Google's QUIC-internal stack, MASQUE proxying, " +
		"and an increasing number of API gateways. The long header carries the " +
		"connection-setup visibility (Initial / 0-RTT / Handshake / Retry / Version " +
		"Negotiation) that's useful for forensic analysis without needing the TLS " +
		"handshake secrets. Decodes:\n\n" +
		"- **First-byte dispatch**: high bit 1 = long header (this Spec); high bit 0 " +
		"= short header (1-RTT, not decoded — surfaced with a note pointing at the " +
		"header-protected packet-number length bits that make the short header " +
		"unparseable without keys). Version Negotiation is detected when Version == 0.\n" +
		"- **Long header common** (RFC 9000 §17.2): byte 0 (Header Form 1 bit + Fixed " +
		"Bit 1 bit + Long Packet Type 2 bits + Type-Specific 4 bits) + Version " +
		"(uint32 BE) + DCID Length (1 byte) + DCID + SCID Length (1 byte) + SCID.\n" +
		"- **4 Long Packet Types** (RFC 9000 §17.2):\n" +
		"  - **0 Initial**: Token Length (VLI) + Token + Length (VLI) + Protected " +
		"Packet Number + Protected Payload. **For QUIC v1 the payload is DECRYPTED** " +
		"— Initial keys are public (HKDF-derived from the clear-text DCID + a fixed " +
		"salt, RFC 9001 §5.2), so this Spec removes header protection, runs " +
		"AES-128-GCM, dissects the frames (PADDING / PING / ACK / CRYPTO / " +
		"CONNECTION_CLOSE) and reassembles the CRYPTO stream into the TLS " +
		"ClientHello / ServerHello — the bytes QUIC otherwise hides, ready to paste " +
		"into `tls_handshake_decode` for the full JA4 / ALPN / SNI view. Verified " +
		"byte-for-byte against the RFC 9001 Appendix A worked example.\n" +
		"  - **1 0-RTT**: Length (VLI) + Protected Packet Number + Protected Payload.\n" +
		"  - **2 Handshake**: Length (VLI) + Protected Packet Number + Protected " +
		"Payload.\n" +
		"  - **3 Retry**: Retry Token (variable) + Retry Integrity Tag (16 bytes, " +
		"AES-128-GCM tag covering the original DCID).\n" +
		"- **Variable-Length Integer** (RFC 9000 §16): 2-bit prefix indicates length " +
		"(1/2/4/8 bytes), remaining bits hold the value:\n" +
		"  - 0b00 prefix: 6-bit value in 1 byte\n" +
		"  - 0b01 prefix: 14-bit value in 2 bytes\n" +
		"  - 0b10 prefix: 30-bit value in 4 bytes\n" +
		"  - 0b11 prefix: 62-bit value in 8 bytes\n" +
		"- **Version Negotiation** (RFC 9000 §17.2.1): when Version == 0, the bytes " +
		"after SCID are a list of uint32 BE supported versions chosen by the server. " +
		"The packet is the server's way of saying 'I don't support the version you " +
		"asked for, here are the ones I do support'.\n" +
		"- **Version name table** with 4 documented + GREASE pattern recognition:\n" +
		"  - 0x00000001 QUIC v1 (RFC 9000 — the canonical version)\n" +
		"  - 0x6B3343CF QUIC v2 (RFC 9369)\n" +
		"  - 0xFF00001D draft-29 / 0xFF000022 draft-34\n" +
		"  - 0x?A?A?A?A GREASE pattern (RFC 8701 — non-standard versions deliberately " +
		"used to detect middleboxes that hard-code version numbers).\n\n" +
		"Pure offline parser — operators paste UDP-payload bytes from a Wireshark " +
		"Follow-UDP-Stream view, a `tcpdump -X udp port 443` line, a `curl --http3 " +
		"-v` trace, or any QUIC-emitting tool and inspect the cleartext header fields. " +
		"Pairs with `http2_frame_decode` + `hpack_decode` for legacy HTTP/2 and " +
		"`tls_handshake_decode` + `dtls_record_decode` for the security-layer view.\n\n" +
		"Out of scope (deferred): short-header (1-RTT) packets — the packet number " +
		"length and key-phase bits are in the header-protected first byte, so without " +
		"the header-protection key we can't unambiguously parse the packet number; " +
		"0-RTT / Handshake / 1-RTT payload decryption (requires the TLS-handshake " +
		"secrets, which are not on the wire — protected payload surfaced as hex; the " +
		"Initial is the exception and IS decrypted); QUIC v2 / draft Initial decryption " +
		"(different salt + 'quicv2 ' key labels, no published vector to anchor against, " +
		"so held rather than risk a wrong decode); UDP / IP framing " +
		"(feed the UDP payload bytes after the IP+UDP headers); HTTP/3 framing layer " +
		"(future Spec — HTTP/3 frames live in QUIC STREAM frames).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational modern transport protocol " +
		"underpinning HTTP/3). Wrap-vs-native: native — RFC 9000 is fully public; " +
		"wire format is a tight bit-packed byte plus fixed-layout fields plus VLI " +
		"encoding; no cryptography at the long-header layer (DCID / SCID / Version / " +
		"Token / supported-versions list are all in the clear).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"QUIC packet UDP-payload bytes as hex. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   quicLongHeaderDecodeHandler,
}

func quicLongHeaderDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("quic_long_header_decode: 'hex' is required")
	}
	res, err := quic.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("quic_long_header_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
