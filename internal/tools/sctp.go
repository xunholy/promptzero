// sctp.go — host-side SCTP packet decoder Spec.
// Wraps the internal/sctp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/sctp"
)

func init() { //nolint:gochecknoinits
	Register(sctpDecodeSpec)
}

var sctpDecodeSpec = Spec{
	Name: "sctp_packet_decode",
	Description: "Decode a Stream Control Transmission Protocol (SCTP) packet per RFC " +
		"4960 (with the AUTH / ASCONF / RE-CONFIG / PAD / FORWARD-TSN chunk types " +
		"from RFCs 4895 / 5061 / 6525 / 4820 / 3758). SCTP is the third pillar " +
		"transport alongside TCP and UDP — often forgotten in security tooling, " +
		"but foundational for telco signalling (M2PA / M2UA / M3UA / SUA / IUA for " +
		"SIGTRAN; S1AP / X2AP / NGAP / XnAP for LTE+5G control plane; Diameter for " +
		"3GPP AAA), WebRTC data channels (SCTP-over-DTLS-over-UDP per RFC 8261), " +
		"and multipath HA pairs. Decodes:\n\n" +
		"- **12-byte common header** (RFC 4960 §3.1): Source Port + Destination " +
		"Port + 32-bit Verification Tag (zero on first INIT) + 32-bit CRC32c " +
		"Checksum (surfaced as hex; not re-computed).\n" +
		"- **Chunk walker** — repeated 4-byte header (Type + Flags + Length) + " +
		"body (Length - 4 bytes) + optional trailing pad bytes to reach a 4-byte " +
		"boundary. The 4-byte alignment is critical because chunk Lengths are " +
		"typically odd (DATA payloads aren't 32-bit aligned).\n" +
		"- **~20-entry chunk type name table** (RFC 4960 §3.2 + IANA SCTP chunk-" +
		"types registry): DATA (0) / INIT (1) / INIT_ACK (2) / SACK (3) / " +
		"HEARTBEAT (4) / HEARTBEAT_ACK (5) / ABORT (6) / SHUTDOWN (7) / " +
		"SHUTDOWN_ACK (8) / ERROR (9) / COOKIE_ECHO (10) / COOKIE_ACK (11) / ECNE " +
		"(12) / CWR (13) / SHUTDOWN_COMPLETE (14) / AUTH (15) / ASCONF_ACK (128) " +
		"/ RE-CONFIG (129) / PAD (130) / ASCONF (132) / FORWARD-TSN (192).\n" +
		"- **DATA chunk body** (Type 0): TSN + Stream Identifier + Stream Sequence " +
		"Number + **Payload Protocol Identifier (PPID)** with a ~25-entry name " +
		"table covering the most common upper-layer protocols (M2UA / M3UA / SUA " +
		"/ IUA / M2PA / Diameter / S1AP / NGAP / X2AP / XnAP / BICC / etc.) + " +
		"user data (capped to 64 bytes hex preview). Flag bits in the 1-byte " +
		"Flags after Type: U = Unordered, B = Beginning fragment, E = Ending " +
		"fragment, I = SACK Immediately.\n" +
		"- **INIT / INIT_ACK chunk body** (Types 1 + 2): Initiate Tag + Advertised " +
		"Receiver Window Credit (a_rwnd) + Number of Outbound Streams + Number of " +
		"Inbound Streams + Initial TSN + variable-length parameters (TLV walked " +
		"for IPv4 Address / IPv6 Address / Cookie Preservative / Hostname / " +
		"Supported Address Types / State Cookie).\n" +
		"- **SACK chunk body** (Type 3): Cumulative TSN Ack + a_rwnd + Number of " +
		"Gap Ack Blocks + Number of Duplicate TSNs + Gap Ack Blocks (each 4 " +
		"bytes: Start + End uint16 BE relative to Cumulative TSN Ack) + Duplicate " +
		"TSN list.\n" +
		"- **HEARTBEAT / HEARTBEAT_ACK chunk body** (Types 4 + 5) — Heartbeat " +
		"Info Parameter (Type 1 + Length + opaque Info; surfaced as hex for " +
		"request/reply correlation).\n" +
		"- **ABORT / ERROR chunk bodies** (Types 6 + 9) — Error Cause TLVs (cause " +
		"code with **13-entry name table** per IANA SCTP Cause-Codes registry).\n\n" +
		"Pure offline parser — operators paste SCTP bytes (IP protocol number 132) " +
		"from a `tcpdump -X ip proto 132` line or a Wireshark Follow-SCTP-Stream " +
		"view and get the documented header + chunk-by-chunk breakdown.\n\n" +
		"Out of scope (deferred): IP framing (feed SCTP bytes after IPv4/IPv6 " +
		"header strip — SCTP runs over IP protocol 132); CRC32c checksum " +
		"verification (surfaced as hex but not re-computed); upper-layer dissection " +
		"(once the PPID is decoded the operator feeds the DATA payload into the " +
		"existing application-layer Specs — Diameter would warrant a future Spec; " +
		"SIP / RTP / DNS / etc. are already covered); SCTP-over-UDP (RFC 6951) and " +
		"SCTP-over-DTLS (RFC 8261) framing — both wrap the same SCTP common header; " +
		"feed bytes starting at the SCTP common header; association state-machine " +
		"reasoning (4-way handshake INIT/INIT_ACK/COOKIE_ECHO/COOKIE_ACK, multi-" +
		"homing, graceful shutdown — higher-level analysis).\n\n" +
		"Source: docs/catalog/gap-analysis.md (third-pillar IP transport — " +
		"foundational for telco signalling + WebRTC data channels + multi-homed HA " +
		"pairs; the long-standing decoder catalog gap). Wrap-vs-native: native — " +
		"RFC 4960 is fully public; SCTP has a tight 12-byte common header followed " +
		"by one or more TLV chunks; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"SCTP packet bytes (after IPv4/IPv6 header strip; IP protocol number 132). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   sctpDecodeHandler,
}

func sctpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("sctp_packet_decode: 'hex' is required")
	}
	res, err := sctp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("sctp_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
