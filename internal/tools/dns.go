// dns.go — host-side DNS packet dissector Spec, delegating
// to the internal/dnsdecode package for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/dnsdecode"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dnsPacketDecodeSpec)
}

var dnsPacketDecodeSpec = Spec{
	Name: "dns_packet_decode",
	Description: "Decode a DNS message — the most-traffic-bearing UDP/53 protocol on the " +
		"internet. Per RFC 1035 + RFC 6891 (EDNS) + supporting RFCs. Workhorse blue-team " +
		"+ red-team + network-debugging primitive for inspecting DNS queries and responses " +
		"extracted from a Wireshark capture, a tshark `dns.qry.name` field, a tcpdump-of-53 " +
		"hex dump, or a DoH/DoT inner-message capture. Decodes:\n\n" +
		"- **DNS header**: transaction ID + flag bits broken out as QR (query/response), " +
		"Opcode (QUERY / IQUERY / STATUS / NOTIFY / UPDATE / DSO), AA, TC, RD, RA, AD, CD, " +
		"and RCODE (NOERROR / FORMERR / SERVFAIL / NXDOMAIN / NOTIMP / REFUSED / YXDOMAIN " +
		"/ YXRRSET / NXRRSET / NOTAUTH / NOTZONE + EDNS extended RCODEs BADVERS / BADKEY / " +
		"BADTIME / BADMODE / BADNAME / BADALG / BADTRUNC / BADCOOKIE) + section counts.\n" +
		"- **Question section**: QNAME with full compression-pointer resolution (RFC 1035 " +
		"§4.1.4), QTYPE, QCLASS.\n" +
		"- **Resource record sections** (Answer / Authority / Additional) with type-" +
		"specific decode for the operationally-important RR types:\n" +
		"  - **A** (1) → 4-byte IPv4 in dotted-decimal.\n" +
		"  - **NS** (2) → owner-domain name.\n" +
		"  - **CNAME** (5) → canonical name.\n" +
		"  - **SOA** (6) → primary NS + responsible-party email + serial + refresh + " +
		"retry + expire + minimum TTL.\n" +
		"  - **PTR** (12) → domain name (reverse-DNS).\n" +
		"  - **MX** (15) → preference + exchange.\n" +
		"  - **TXT** (16) → list of `<character-string>`s (SPF / DMARC / arbitrary " +
		"policy text).\n" +
		"  - **AAAA** (28) → 16-byte IPv6 in canonical colon form.\n" +
		"  - **SRV** (33) → priority + weight + port + target (the canonical service-" +
		"discovery record).\n" +
		"  - **OPT** (41, EDNS) → UDP-size from class field, extended RCODE + EDNS " +
		"version + DO flag (DNSSEC requested) from TTL field, per-option [code, name, " +
		"raw data] for ECS / COOKIE / EDE / Padding / NSID / etc.\n" +
		"  - **DNSKEY** (48) → flags (KSK/ZSK), protocol, algorithm name, key-tag (RFC " +
		"4034 Appx B), public-key hex.\n" +
		"  - **DS** (43) → key tag, algorithm name, digest type, digest hex.\n" +
		"  - **CAA** (257, RFC 6844) → flags (critical bit) + tag (issue / issuewild / " +
		"iodef / contactemail / contactphone) + value.\n" +
		"- **Name decompression** with pointer-chain max-depth guard (defeats the " +
		"classic pointer-loop DoS).\n" +
		"- **RR type / class / RCODE / Opcode lookup** tables covering ~40 RR types and " +
		"all documented codes.\n\n" +
		"Pure offline parser — operators paste a hex blob captured by any DNS-aware tool " +
		"and inspect every field. Pairs with tls_handshake_decode + x509_certificate_decode " +
		"+ jwt_decode to complete the network + auth decode stack: DNS for name resolution " +
		"telemetry, TLS handshake for connection envelope + SNI, X.509 for cert chains, " +
		"JWT for bearer-token decode.\n\n" +
		"Out of scope (deferred to future iterations): DNSSEC signature validation (RRSIG " +
		"is recognised by type name but the signature blob is exposed as hex; cryptographic " +
		"verification requires a trust-anchor store), TLSA (52) and SVCB/HTTPS (64/65) deep " +
		"decode, LOC / NAPTR / URI / experimental types (named but RDATA is raw hex), DNS-" +
		"over-HTTPS / DoT / DoQ framing (operators feed the inner message), TCP DNS 2-byte " +
		"length prefix (strip before passing).\n\n" +
		"Source: docs/catalog/gap-analysis.md (most-traffic-bearing UDP protocol; high " +
		"defensive + offensive value for any network analysis workflow). Wrap-vs-native: " +
		"native — RFC 1035 et al. are fully public, wire format is a fixed-format header " +
		"+ length-prefixed sections, dispatch is a switch.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded DNS message: 12-byte header + question section + answer/authority/additional resource records. Strip the 2-byte length prefix if extracted from a TCP DNS frame. ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dnsPacketDecodeHandler,
}

func dnsPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("dns_packet_decode: 'hex' is required")
	}
	res, err := dnsdecode.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("dns_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
