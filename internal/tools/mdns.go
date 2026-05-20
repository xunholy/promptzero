// mdns.go — host-side mDNS / DNS-SD decoder Spec. Wraps the
// internal/mdns walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/mdns"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(mdnsDecodeSpec)
}

var mdnsDecodeSpec = Spec{
	Name: "mdns_decode",
	Description: "Decode an mDNS (Multicast DNS) message per RFC 6762 + DNS-SD per RFC " +
		"6763. mDNS runs over UDP/5353 multicast 224.0.0.251 (IPv4) or FF02::FB " +
		"(IPv6 link-local) and is the discovery layer of every Bonjour / Avahi / " +
		"macOS / iOS device stack + the consumer IoT ecosystem. Operationally " +
		"the canonical signal for enumerating consumer IoT on a LAN: Apple " +
		"ecosystem (AirDrop / AirPrint / AirPlay / HomeKit / Apple TV); " +
		"streaming (Chromecast _googlecast / Spotify Connect / Sonos / Roku); " +
		"smart home (Philips Hue / HomeKit accessories / Plex); Linux/Unix LAN " +
		"discovery (Avahi _workstation / _sftp-ssh / _ssh / _http); developer " +
		"tooling (Docker / Kubernetes mDNS-augmented deployments). Decodes:\n\n" +
		"- **DNS-style header** (RFC 1035 §4.1.1 / RFC 6762 §18, 12 bytes, " +
		"big-endian): TransactionID + Flags + QD/AN/NS/AR counts. mDNS senders " +
		"typically set TransactionID = 0.\n" +
		"- **Flags field** (16 bits BE): bit 15 QR (response indicator) + bits " +
		"11-14 Opcode (0 = QUERY, only value used in mDNS) + bit 10 AA " +
		"(Authoritative Answer — set in mDNS responses) + bit 9 TC (Truncated) " +
		"+ bits 0-3 RCODE (must be 0 in mDNS).\n" +
		"- **DNS label-encoded name walker** with full RFC 1035 §4.1.4 " +
		"compression-pointer support (up to 5 hops deep). Note: unlike LLMNR " +
		"which forbids compression pointers, mDNS allows them.\n" +
		"- **Question record** with **QU bit** (RFC 6762 §5.4): encoded name + " +
		"Type + QCLASS where top bit 0x8000 is the QU flag (Question Unicast " +
		"response preferred) and bottom 15 bits are the normal class (typically " +
		"1 = IN). Surfaces qu_unicast as a derived field.\n" +
		"- **Answer record** with **Cache-Flush bit** (RFC 6762 §10.2): encoded " +
		"name + Type + CLASS (top bit 0x8000 = Cache-Flush; bottom 15 bits = " +
		"normal class) + TTL + RDLength + RDATA. Surfaces cache_flush as a " +
		"derived field.\n" +
		"- **9+ entry resource-record Type name table**: 1 A / 2 NS / 5 CNAME " +
		"/ 6 SOA / 12 PTR (DNS-SD service-type → instance-name mapping) / 15 MX " +
		"/ 16 TXT (DNS-SD key=value capability metadata) / 28 AAAA / 33 SRV " +
		"(DNS-SD instance → host:port + priority + weight) / 41 OPT (EDNS0) / " +
		"47 NSEC (re-purposed in mDNS to mean 'I have these record types for " +
		"this name and only these').\n" +
		"- **Per-RR-type RDATA decoders**: A → 4-byte IPv4; AAAA → 16-byte " +
		"IPv6; PTR / CNAME → DNS-encoded name (with compression-pointer " +
		"traversal); SRV → 2-byte Priority + 2-byte Weight + 2-byte Port + " +
		"DNS-encoded Target (reveals listening port + target hostname); TXT → " +
		"list of length-prefixed strings split on first '=' into key/value " +
		"pairs (DNS-SD §6 canonical metadata format); other types → opaque " +
		"hex.\n\n" +
		"Pure offline parser — operators paste mDNS bytes (the UDP payload as " +
		"hex; default UDP port 5353) from a `tcpdump -X port 5353` line or a " +
		"Wireshark mDNS dissector view and get the documented header + per-" +
		"record breakdown + DNS-SD QU/cache-flush bit decode.\n\n" +
		"Out of scope (deferred): network framing (feed bytes after the UDP-" +
		"datagram header strip; default UDP port 5353); NBNS / LLMNR (parallel " +
		"Windows name-resolution protocols on UDP/137 and UDP/5355 — covered " +
		"by nbns_decode + llmnr_decode Specs); generic DNS (UDP/53 traffic re-" +
		"uses the same RFC 1035 wire format — covered by the existing " +
		"dns_packet_decode Spec); DNS-SD service-type semantics beyond name " +
		"detection (the per-service-type schema for _homekit / _airplay / " +
		"_googlecast TXT keys is vendor-specific and out of scope — surfaces " +
		"TXT key=value pairs but does not interpret them); NSEC bitmap decode " +
		"(NSEC RDATA carries a compressed type-bitmap — surfaces next-name " +
		"portion but leaves type-bitmap as opaque hex); DNSSEC validation; " +
		"multi-fragment reassembly (TC flag surfaces but reassembly out of " +
		"scope).\n\n" +
		"Source: docs/catalog/gap-analysis.md (Bonjour / consumer-IoT discovery " +
		"dissector — completes the Windows + Bonjour name-resolution trio with " +
		"nbns_decode + llmnr_decode + mdns_decode; canonical decode for " +
		"AirDrop / AirPrint / Chromecast / HomeKit / Spotify Connect / Sonos " +
		"enumeration; common in DEF CON Recon Village + home-network pentests + " +
		"IoT enumeration workflows). Wrap-vs-native: native — RFC 6762 + 6763 " +
		"are publicly available; mDNS re-uses the RFC 1035 wire format with two " +
		"crucial bit-flag extensions (QU on QCLASS, Cache-Flush on CLASS); no " +
		"crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"mDNS message bytes (the UDP payload; default UDP port 5353). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   mdnsDecodeHandler,
}

func mdnsDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("mdns_decode: 'hex' is required")
	}
	res, err := mdns.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("mdns_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
