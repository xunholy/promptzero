// dccp.go — host-side DCCP packet decoder Spec.
// Wraps the internal/dccp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/dccp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dccpDecodeSpec)
}

var dccpDecodeSpec = Spec{
	Name: "dccp_packet_decode",
	Description: "Decode a DCCP (Datagram Congestion Control Protocol) packet per RFC " +
		"4340. DCCP is the niche fourth IP transport — alongside TCP (reliable " +
		"streams), UDP (unreliable datagrams), and SCTP (reliable streams + " +
		"multihoming) — designed for applications that want UDP-style unreliable " +
		"delivery *plus* TCP-style congestion control. Intended for real-time " +
		"media (voice, video), interactive games, and any traffic where dropping " +
		"a packet is preferable to retransmitting a stale one. Operationally, " +
		"DCCP saw limited deployment but remains the IP protocol number 33 wire " +
		"format that operators occasionally see in WebRTC SCTP-over-DTLS-over-UDP " +
		"fallbacks, embedded game-server protocols at smaller publishers, and " +
		"IETF reference implementations studying congestion-control variants. " +
		"Decodes:\n\n" +
		"- **Generic header** (RFC 4340 §5.1, 12 or 16 bytes depending on X bit): " +
		"Source Port + Destination Port + Data Offset (in 4-byte words) + 4-bit " +
		"CCVal (Congestion Control Value; per-CCID semantics) + 4-bit CsCov " +
		"(Checksum Coverage; 0 = full, N = first N×4 bytes of app data) + " +
		"Checksum + 3-bit Reserved + 4-bit Type + 1-bit **X** (Extended Sequence " +
		"Numbers — 0 = short 24-bit, 1 = extended 48-bit).\n" +
		"- **10-entry packet type name table** (RFC 4340 §5.1): 0 DCCP-Request / " +
		"1 DCCP-Response / 2 DCCP-Data / 3 DCCP-Ack / 4 DCCP-DataAck / 5 " +
		"DCCP-CloseReq / 6 DCCP-Close / 7 DCCP-Reset / 8 DCCP-Sync / 9 " +
		"DCCP-SyncAck.\n" +
		"- **Short vs extended header dispatch**: X=0 → 12-byte header with bytes " +
		"9-11 = 24-bit Sequence Number; X=1 → 16-byte header with byte 9 reserved " +
		"+ bytes 10-15 = 48-bit Sequence Number.\n" +
		"- **Request / Response body** (Types 0 + 1): 4-byte Service Code (per-" +
		"application identifier the receiver uses to demultiplex incoming " +
		"connections — analogous to UDP/TCP destination port + application). " +
		"Response additionally has an 8-byte Acknowledgement Subheader.\n" +
		"- **Ack-family bodies** (Types 3, 4, 5, 8, 9): 8-byte Acknowledgement " +
		"Subheader — 16-bit Reserved + 48-bit Acknowledgement Number.\n" +
		"- **Reset body** (Type 7): 8-byte Acknowledgement Subheader + 1-byte " +
		"**Reset Code** + 1-byte Data1 + 1-byte Data2 + 1-byte Data3. **12-entry " +
		"Reset Code name table** (RFC 4340 §5.6): 0 Unspecified / 1 Closed / 2 " +
		"Aborted / 3 No Connection / 4 Packet Error / 5 Option Error / 6 " +
		"Mandatory Error / 7 Connection Refused / 8 Bad Service Code / 9 Too " +
		"Busy / 10 Bad Init Cookie / 11 Aggression Penalty.\n" +
		"- **Data / Close / CloseReq** bodies have no additional fields beyond " +
		"the generic header.\n\n" +
		"Pure offline parser — operators paste DCCP bytes (IP protocol 33) from a " +
		"`tcpdump -X ip proto 33` line or a Wireshark Follow-IP-Stream view and " +
		"get the documented header + per-type body breakdown.\n\n" +
		"Out of scope (deferred): IP framing (feed DCCP bytes after the IPv4/" +
		"IPv6 header strip — DCCP runs as IP protocol 33); Options walker (DCCP " +
		"has a rich set of Options — Mandatory, NDP Count, Ack Vector, Elapsed " +
		"Time, Timestamp, Timestamp Echo, Slow Receiver, CCID-specific — that " +
		"live after the per-type body up to Data Offset; surfaced as raw hex; " +
		"per-option decoders are future work); per-CCID semantics (DCCP supports " +
		"pluggable Congestion Control IDs — CCID 2 = TCP-like, CCID 3 = TCP-" +
		"Friendly Rate Control, CCID 4 = TFRC for Small Packets; the CCVal " +
		"nibble surfaces as raw; per-CCID decoders are out of scope); checksum " +
		"verification (Internet-checksum over the IP pseudo-header + DCCP header " +
		"+ CsCov bytes is surfaced as hex but not re-computed); DCCP state-" +
		"machine reasoning (connection setup, teardown, Sync recovery, CCID " +
		"negotiation — higher-level analysis).\n\n" +
		"Source: docs/catalog/gap-analysis.md (fourth-pillar IP transport; " +
		"completes the TCP + UDP + SCTP + DCCP transport-layer decoder quartet; " +
		"niche but well-defined). Wrap-vs-native: native — RFC 4340 is fully " +
		"public; DCCP has a tight 12-or-16-byte fixed header followed by a per-" +
		"type body; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"DCCP packet bytes (after IPv4/IPv6 header strip; IP protocol 33). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dccpDecodeHandler,
}

func dccpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("dccp_packet_decode: 'hex' is required")
	}
	res, err := dccp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("dccp_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
