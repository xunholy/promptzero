// ntp.go — host-side NTP packet dissector Spec, delegating
// to the internal/ntp package for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ntp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ntpPacketDecodeSpec)
}

var ntpPacketDecodeSpec = Spec{
	Name: "ntp_packet_decode",
	Description: "Decode an NTP / SNTP packet — the time-synchronisation protocol every " +
		"networked device speaks against pool.ntp.org / its vendor pool / a local stratum-2 " +
		"server. Per RFC 5905 (v4) + RFC 1305 (v3) + RFC 4330 (SNTPv4). Workhorse for " +
		"time-sync forensics, NTP amplification DDoS detection (mode 7 / monlist abuse), " +
		"log-timestamp correlation, and certificate-validity-window debugging. Decodes:\n\n" +
		"- **Byte 0 broken out**: LI (Leap Indicator: 0 no warning / 1 +61sec / 2 -61sec / " +
		"3 alarm-unsynchronised), VN (Version Number — 1, 2, 3, 4), Mode (1 symmetric " +
		"active / 2 symmetric passive / 3 client / 4 server / 5 broadcast / 6 NTP control " +
		"message / 7 private use).\n" +
		"- **Stratum** (1=primary reference / 2-15=secondary / 16=unsynchronised / 17-255=" +
		"reserved) with name lookup.\n" +
		"- **Poll** (signed log2 seconds — maximum poll interval) and **Precision** " +
		"(signed log2 seconds — local clock precision), both surfaced as raw log2 and " +
		"as float seconds.\n" +
		"- **Root Delay** + **Root Dispersion** as 32-bit NTPv3 short-format fixed-point " +
		"seconds (16-bit integer + 16-bit fractional, rendered as float64 seconds).\n" +
		"- **Reference ID** with stratum-dependent interpretation:\n" +
		"  - **Stratum 0**: Kiss-o'-Death (KoD) 4-character code (ACST/AUTH/AUTO/BCST/" +
		"CRYP/DENY/DROP/RSTR/INIT/MCST/NKEY/NTSN/RATE/RMOT/STEP) per RFC 5905 §7.4 with " +
		"full name lookup.\n" +
		"  - **Stratum 1**: 4-character ASCII source identifier (GPS/GAL/PPS/IRIG/WWVB/" +
		"DCF77/HBG/MSF/JJY/LORC/TDF/CHU/WWV/WWVH/NIST/ACTS/USNO/PTB) per RFC 5905 §7.3 " +
		"with full name lookup.\n" +
		"  - **Stratum 2-15**: IPv4 of the upstream server (or the MD5 hash of the " +
		"upstream IPv6).\n" +
		"- **Four NTP timestamps**: Reference (last time the local clock was set), " +
		"Origin / T1 (when client sent the request), Receive / T2 (when server received " +
		"the request), Transmit / T3 (when server sent the response). Each is surfaced " +
		"as the raw 64-bit NTP value (32-bit integer seconds since 1900 + 32-bit " +
		"fractional at 2^-32 resolution) AND as Unix-epoch seconds AND as an RFC 3339 " +
		"string in UTC. All-zero timestamps (typical of Origin on a first-flight client " +
		"request) are flagged with is_zero=true.\n" +
		"- **NTPv4 extension fields** (RFC 5906): count + raw hex per extension.\n" +
		"- **Optional authenticator** (RFC 5905 §7.5): detected by trailing 20-byte " +
		"(4-byte Key ID + 16-byte MD5 MAC) or 24-byte (4-byte Key ID + 20-byte SHA-1 " +
		"MAC) tail. KeyID + MAC hex + algorithm name surfaced.\n\n" +
		"Pure offline parser — operators paste a hex blob from Wireshark / tshark / " +
		"tcpdump-of-123 / a captured NTP server response and inspect every documented " +
		"field without re-querying the time server. Pairs with dns_packet_decode + " +
		"dhcp_packet_decode + snmp_packet_decode for the complete network-infrastructure " +
		"decode stack.\n\n" +
		"Out of scope (deferred to future iterations): NTP control message (mode 6) " +
		"deep decode (RFC 1305 §3.5 op-code + sequence + status + assoc ID body — ~150 " +
		"LoC separate effort), NTP mode 7 vendor body (historically monlist-DDoS " +
		"abused), Autokey (RFC 5906) extension contents validation, NTS (Network Time " +
		"Security, RFC 8915) cookie/AEAD decryption (requires session keys).\n\n" +
		"Source: docs/catalog/gap-analysis.md (network-time decode space — high " +
		"defensive value for time-sync forensics + NTP amplification DDoS triage). " +
		"Wrap-vs-native: native — RFC 5905 + 1305 + 4330 are fully public, wire format " +
		"is fixed-position integers + fixed-point seconds + 64-bit NTP timestamps, " +
		"dispatch is straight-line code.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded NTP packet: 48-byte fixed header (LI+VN+Mode+Stratum+Poll+Precision+RootDelay+RootDispersion+ReferenceID + 4 × 64-bit timestamps) + optional NTPv4 extension fields + optional authenticator. Minimum 48 bytes. ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ntpPacketDecodeHandler,
}

func ntpPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ntp_packet_decode: 'hex' is required")
	}
	res, err := ntp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ntp_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
