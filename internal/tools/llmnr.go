// llmnr.go — host-side LLMNR (Link-Local Multicast Name
// Resolution) decoder Spec. Wraps the internal/llmnr walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/llmnr"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(llmnrDecodeSpec)
}

var llmnrDecodeSpec = Spec{
	Name: "llmnr_decode",
	Description: "Decode an LLMNR (Link-Local Multicast Name Resolution) message per " +
		"RFC 4795. LLMNR is the modern Windows multicast name-resolution " +
		"protocol that runs over UDP/5355 to multicast 224.0.0.252 (IPv4) or " +
		"FF02::1:3 (IPv6 link-local). LLMNR exists in the Windows lookup chain " +
		"as the second fallback when DNS fails to resolve a short, unqualified " +
		"name (Windows tries DNS, then LLMNR, then — on older configurations — " +
		"NBNS). Interesting because it is the canonical target of Responder.py " +
		"poisoning alongside NBNS: when a Windows host types `\\\\fileserv1` and " +
		"the corporate DNS doesn't know the name, the host broadcasts an LLMNR " +
		"QUERY to the local subnet; an attacker running Responder.py replies " +
		"with their own IP and captures the inbound NTLMv2 challenge/response " +
		"for offline cracking with hashcat mode 5600. Decodes:\n\n" +
		"- **DNS-style header** (RFC 4795 §2.1.1, 12 bytes, big-endian): " +
		"TransactionID + Flags + QD/AN/NS/AR counts.\n" +
		"- **Flags field** (16 bits BE) with LLMNR-specific interpretation: " +
		"bit 15 QR (response indicator) + bits 11-14 Opcode (always 0 = " +
		"LLMNR_QUERY) + bit 10 C (Conflict — set in a response to indicate " +
		"the queried name is in active use by multiple hosts; canonical LLMNR-" +
		"poisoning detection signal) + bit 9 TC (Truncated) + bit 8 T " +
		"(Tentative — set during name registration before the name has been " +
		"successfully defended on the link) + bits 0-3 RCODE.\n" +
		"- **DNS label-encoded name walker** (RFC 4795 §2.1.7): standard RFC " +
		"1035 length-prefixed labels terminated by a 0x00 root label. **LLMNR " +
		"explicitly forbids compression pointers**, so the walker rejects any " +
		"length byte with the high bits 11 (0xC0+) as malformed.\n" +
		"- **Question record**: encoded name + 2-byte Type + 2-byte Class.\n" +
		"- **Answer record**: encoded name + Type + Class + 4-byte TTL + 2-byte " +
		"RDLength + RDLength bytes of RDATA.\n" +
		"- **6+ entry resource-record Type name table**: 1 A (IPv4 host " +
		"address) / 2 NS / 5 CNAME (Canonical Name) / 6 SOA / 12 PTR (Pointer " +
		"— reverse lookup) / 15 MX (Mail Exchange) / 16 TXT (Text) / 28 AAAA " +
		"(IPv6 host address) / 33 SRV.\n" +
		"- **Per-RR-type RDATA decoders**: A → 4-byte IPv4 address; AAAA → " +
		"16-byte IPv6 address; PTR / CNAME → DNS-encoded name (label walker; " +
		"no compression pointers); other types → RDATA bytes surfaced as raw " +
		"hex.\n" +
		"- **RCODE name table** (RFC 1035 §4.1.1): 0 No_Error / 1 Format_Error " +
		"/ 2 Server_Failure / 3 Name_Error (the standard 'no such name' " +
		"response) / 4 Not_Implemented / 5 Refused.\n\n" +
		"Pure offline parser — operators paste LLMNR bytes (the UDP payload as " +
		"hex; default UDP port 5355) from a `tcpdump -X port 5355` line or a " +
		"Wireshark LLMNR dissector view and get the documented header + per-" +
		"record breakdown.\n\n" +
		"Out of scope (deferred): network framing (feed bytes after the UDP-" +
		"datagram header strip; default UDP port 5355); NBNS / mDNS (parallel " +
		"Windows / Bonjour name-resolution protocols on UDP/137 and UDP/5353 " +
		"— covered by nbns_decode + future mdns_decode Specs); generic DNS " +
		"(UDP/53 traffic uses the same RFC 1035 wire format but supports " +
		"compression pointers + the full RR-type registry — covered by the " +
		"existing dns_packet_decode Spec); per-RR-type decoders beyond " +
		"A/AAAA/PTR/CNAME (TXT key-value parsing, SRV target+port extraction, " +
		"MX preference + exchange decoding — out of scope since LLMNR " +
		"deployments overwhelmingly carry A + AAAA queries); multi-fragment " +
		"reassembly (per-message TC flag surfaced but reassembly out of " +
		"scope); name-conflict resolution state-machine (defend-name / " +
		"tentative / conflict / abandoned transitions per RFC 4795 §4.4 are " +
		"higher-level analysis).\n\n" +
		"Source: docs/catalog/gap-analysis.md (Windows AD reconnaissance " +
		"dissector — pairs with nbns_decode for the Windows name-resolution " +
		"duo + future mdns_decode for the consumer-IoT discovery layer; " +
		"canonical target of Responder.py poisoning; common in DEF CON Recon " +
		"Village + AD pentest engagements; the NTLMv2-hash-capture entry " +
		"point on Windows networks where DNS is locked down). Wrap-vs-native: " +
		"native — RFC 4795 is publicly available; the wire format is a tight " +
		"12-byte DNS-style header + per-record DNS-style encoding with the " +
		"critical LLMNR-specific constraint that compression pointers are " +
		"forbidden; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"LLMNR message bytes (the UDP payload; default UDP port 5355). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   llmnrDecodeHandler,
}

func llmnrDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("llmnr_decode: 'hex' is required")
	}
	res, err := llmnr.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("llmnr_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
