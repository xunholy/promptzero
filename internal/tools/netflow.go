// netflow.go — host-side NetFlow v5 packet decoder Spec.
// Wraps the internal/netflow walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/netflow"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(netflowV5DecodeSpec)
}

var netflowV5DecodeSpec = Spec{
	Name: "netflow_v5_decode",
	Description: "Decode a NetFlow v5 export packet per Cisco's public NetFlow v5 " +
		"specification (1996). NetFlow v5 is the dominant flow-export format on " +
		"enterprise + ISP networks for two decades, still emitted by every Cisco / " +
		"Juniper / Arista router that runs classic NetFlow. NetFlow records " +
		"summarise unidirectional IP flows — every (SrcIP, DstIP, SrcPort, " +
		"DstPort, Proto) tuple seen by a routing-plane sampler is exported to a " +
		"collector for traffic accounting, capacity planning, anomaly detection, " +
		"and SIEM correlation. Decodes:\n\n" +
		"- **24-byte header**:\n" +
		"  - bytes 0-1: Version (uint16 BE; must be 5).\n" +
		"  - bytes 2-3: Count (uint16 BE; number of flow records 1-30; the upper " +
		"bound is set by MTU — 30 × 48 + 24 = 1464 < 1500).\n" +
		"  - bytes 4-7: SysUptime (uint32 BE; milliseconds since exporter boot).\n" +
		"  - bytes 8-11: Unix Secs (uint32 BE; epoch seconds of current export).\n" +
		"  - bytes 12-15: Unix Nsecs (uint32 BE).\n" +
		"  - bytes 16-19: **Flow Sequence** (uint32 BE; per-source monotonic " +
		"counter — gaps signal collector data loss).\n" +
		"  - byte 20: Engine Type (typically 0 RP, 1 LC).\n" +
		"  - byte 21: Engine ID (slot/engine ID for multi-engine routers).\n" +
		"  - bytes 22-23: **Sampling Interval** — top 2 bits = **sampling mode** " +
		"(0 unsampled, 1 1-in-N deterministic, 2 1-in-N random); bottom 14 bits = " +
		"interval N.\n" +
		"- **48-byte flow record** (repeated Count times):\n" +
		"  - SrcAddr / DstAddr / NextHop (IPv4 + IPv4 + IPv4).\n" +
		"  - Input / Output (SNMP ifIndex).\n" +
		"  - dPkts (packets in flow) + dOctets (bytes in flow).\n" +
		"  - First / Last (SysUptime ms at flow start / end; duration derived).\n" +
		"  - SrcPort / DstPort.\n" +
		"  - **TCP Flags** — cumulative OR of all TCP flags seen during the flow, " +
		"decoded into 8 named bits per RFC 793 + RFC 3168: FIN / SYN / RST / PSH " +
		"/ ACK / URG / ECE / CWR.\n" +
		"  - **Protocol** — IP protocol number resolved via 13-entry IANA name " +
		"table: HOPOPT / ICMP / IGMP / TCP / UDP / IPv6 / GRE / ESP / AH / " +
		"ICMPv6 / OSPF / PIM / VRRP / SCTP. Uncatalogued values surfaced with " +
		"raw number.\n" +
		"  - ToS (IP type-of-service byte).\n" +
		"  - SrcAS / DstAS (ASN — populated when exporter has BGP-table " +
		"awareness).\n" +
		"  - SrcMask / DstMask (prefix lengths; surfaced as canonical CIDR " +
		"prefixes alongside the host addresses).\n\n" +
		"Pure offline parser — operators paste NetFlow bytes (UDP destination " +
		"port 2055 / 9555 / 9995) from a `tcpdump -X udp port 2055` line or a " +
		"Wireshark Follow-UDP-Stream view and get the documented header + per-" +
		"record breakdown.\n\n" +
		"Out of scope (deferred): UDP framing (feed bytes after the UDP header " +
		"strip — NetFlow v5 ships on UDP, conventionally to ports 2055 / 9555 " +
		"/ 9995); NetFlow v9 (RFC 3954 — template-based; different envelope, " +
		"warrants its own Spec); IPFIX (RFC 7011 — IETF standardisation of v9; " +
		"also warrants its own Spec); sFlow (InMon packet-sampling protocol — " +
		"different model entirely, per-packet sample not per-flow summary); " +
		"flow-record aggregation / windowing (collector-side work; this Spec " +
		"just decodes the wire).\n\n" +
		"Source: docs/catalog/gap-analysis.md (universal flow-export protocol — " +
		"every NOC sees flows; high SIEM + capacity-planning + anomaly-detection " +
		"value). Wrap-vs-native: native — NetFlow v5 wire format is fully public; " +
		"24-byte header + uniform 48-byte record array; no crypto, no compression, " +
		"no variable-length fields.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"NetFlow v5 packet bytes (after UDP header strip; UDP destination port 2055 / 9555 / 9995). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   netflowV5DecodeHandler,
}

func netflowV5DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("netflow_v5_decode: 'hex' is required")
	}
	res, err := netflow.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("netflow_v5_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
