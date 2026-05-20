// ipsec.go — host-side IPsec ESP + AH decoder Specs.
// Wraps the internal/ipsec walkers.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ipsec"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(espDecodeSpec)
	Register(ahDecodeSpec)
}

var espDecodeSpec = Spec{
	Name: "esp_decode",
	Description: "Decode an IPsec ESP (Encapsulating Security Payload) packet per RFC " +
		"4303. ESP is the dominant IPsec protocol — every site-to-site VPN " +
		"(between branch offices, between cloud VPCs, between on-prem and cloud) " +
		"and every IPsec-based remote-access VPN (StrongSwan, OpenSwan, Cisco " +
		"AnyConnect IPsec mode, Windows IPsec) wraps its payload in ESP. ESP " +
		"provides confidentiality (encryption) and optional integrity (ICV); the " +
		"payload + trailer + ICV are surfaced as opaque hex pending the SA's " +
		"negotiated key + algorithm (out of scope at the parse layer). Decodes:\n\n" +
		"- **8-byte plaintext header**: 4-byte **SPI** (Security Parameters Index " +
		"— identifies the Security Association) + 4-byte **Sequence Number** " +
		"(per-SA monotonic anti-replay counter).\n" +
		"- **SPI semantic notes**: SPI 0 is reserved for local use, 1-255 are " +
		"IANA-reserved for future allocation, and ≥ 256 are negotiated by peer " +
		"IKE agents.\n" +
		"- **Encrypted payload + trailer + ICV** (remainder after the 8-byte " +
		"header): surfaced as opaque hex preview (default 256-byte cap). The " +
		"encrypted blob contains Padding + Pad Length (1 byte) + Next Header " +
		"(1 byte) + Integrity Check Value (variable; size determined by the " +
		"negotiated integrity algorithm — HMAC-SHA1-96 = 12 bytes, HMAC-SHA-256-" +
		"128 = 16 bytes, AES-GMAC = 16 bytes, etc.).\n\n" +
		"Pure offline parser — operators paste ESP bytes (IP protocol 50 — feed " +
		"bytes after IPv4/IPv6 header strip) from a `tcpdump -X ip proto 50` line " +
		"or a Wireshark Follow-IP-Stream view and get the documented header + " +
		"opaque payload preview.\n\n" +
		"Out of scope (deferred): IP framing (feed ESP bytes after IPv4/IPv6 " +
		"header strip — ESP runs as IP protocol 50); cryptographic decryption + " +
		"integrity verification (without the SA's IKE-negotiated key + algorithm, " +
		"the payload is opaque ciphertext; surfaced as hex; full decryption is a " +
		"future IKE-state-aware iteration); IKE (Internet Key Exchange, RFC 7296) " +
		"— the control-plane protocol that negotiates IPsec SAs (would warrant " +
		"its own Spec); ESP-in-UDP / NAT-T encapsulation (RFC 3948) — UDP port " +
		"4500 with a 4-byte all-zeros marker distinguishes ESP-NAT-T from IKE-" +
		"NAT-T; feed the ESP bytes after stripping the UDP + marker; tunnel-mode " +
		"inner-IP-header dissection (once decrypted, would feed into " +
		"`ip_packet_decode`).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational IPsec data-plane " +
		"protocol; universal on every site-to-site VPN + IPsec remote-access " +
		"deployment; pairs with ah_decode for full IPsec data-plane coverage). " +
		"Wrap-vs-native: native — RFC 4303 is fully public; ESP has a tight 8-" +
		"byte plaintext preamble (SPI + Sequence) followed by an opaque encrypted " +
		"payload + trailer + ICV; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"ESP packet bytes (after IPv4/IPv6 header strip; IP protocol 50). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."},
			"max_payload_bytes":{"type":"integer","description":"Cap the encrypted payload hex preview (default 256). Zero surfaces the full payload."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   espDecodeHandler,
}

var ahDecodeSpec = Spec{
	Name: "ah_decode",
	Description: "Decode an IPsec AH (Authentication Header) packet per RFC 4302. AH " +
		"provides authentication (integrity) without confidentiality and is less " +
		"common today than ESP, but remains in use for specific compliance + " +
		"lawful-intercept scenarios where payload encryption is forbidden but " +
		"integrity is required. Decodes:\n\n" +
		"- **12-byte fixed header** (RFC 4302 §2.1): 1-byte **Next Header** (IP " +
		"protocol number of the next header) + 1-byte **Payload Length** (AH " +
		"header length in 32-bit words minus 2, so total header bytes = (PL + 2) " +
		"× 4) + 2-byte Reserved (RFC 4302 §2.2 requires 0; non-zero surfaces a " +
		"Note) + 4-byte **SPI** + 4-byte **Sequence Number**.\n" +
		"- **SPI semantic notes**: same as ESP — SPI 0 reserved for local use, " +
		"1-255 IANA-reserved, ≥ 256 negotiated by IKE peers.\n" +
		"- **Variable-length ICV** (Integrity Check Value): size derived from " +
		"Payload Length as (PL - 1) × 4 bytes. For HMAC-SHA1-96 PL=4 → ICV=12 " +
		"bytes; for HMAC-SHA-256-128 PL=5 → ICV=16 bytes (with 2-byte trailing " +
		"padding within the 4-word alignment). Surfaced as hex pending the " +
		"SA's IKE-negotiated key + algorithm.\n" +
		"- **Next Header name table** — 13-entry table covering the most common " +
		"IP protocol numbers: 1 ICMP / 2 IGMP / 4 IPv4 (tunnel mode inner " +
		"header) / 6 TCP / 17 UDP / 41 IPv6 (tunnel mode inner header) / 47 GRE " +
		"/ 50 ESP (chained IPsec) / 51 AH (chained IPsec) / 58 ICMPv6 / 89 OSPF " +
		"/ 103 PIM / 132 SCTP. Uncatalogued values surface as `uncatalogued IP " +
		"protocol N`.\n\n" +
		"Pure offline parser — operators paste AH bytes (IP protocol 51 — feed " +
		"bytes after IPv4/IPv6 header strip) and get the documented header + ICV " +
		"breakdown.\n\n" +
		"Out of scope (deferred): IP framing (feed AH bytes after IPv4/IPv6 " +
		"header strip — AH runs as IP protocol 51); ICV verification (without " +
		"the SA's IKE-negotiated key + algorithm, the ICV cannot be checked); " +
		"IKE (use future Spec when added); next-header inner dissection (operator " +
		"pulls bytes after the AH header end and feeds into the appropriate " +
		"`*_decode` Spec based on Next Header).\n\n" +
		"Source: docs/catalog/gap-analysis.md (IPsec authentication-only data-" +
		"plane protocol; pairs with esp_decode for full IPsec data-plane " +
		"coverage). Wrap-vs-native: native — RFC 4302 is fully public; AH has a " +
		"tight 12-byte fixed header followed by a variable-length ICV whose size " +
		"is derived from the Payload Length field; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"AH packet bytes (after IPv4/IPv6 header strip; IP protocol 51). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ahDecodeHandler,
}

func espDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("esp_decode: 'hex' is required")
	}
	opts := ipsec.DefaultDecodeOpts()
	if v, ok := p["max_payload_bytes"]; ok {
		if n, ok := intArg(v); ok {
			opts.MaxPayloadBytes = n
		}
	}
	res, err := ipsec.DecodeESP(raw, opts)
	if err != nil {
		return "", fmt.Errorf("esp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}

func ahDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ah_decode: 'hex' is required")
	}
	res, err := ipsec.DecodeAH(raw)
	if err != nil {
		return "", fmt.Errorf("ah_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
