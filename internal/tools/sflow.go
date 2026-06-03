// sflow.go — host-side sFlow v5 datagram decoder Spec.
// Wraps the internal/sflow walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/sflow"
)

func init() { //nolint:gochecknoinits
	Register(sflowV5DecodeSpec)
}

var sflowV5DecodeSpec = Spec{
	Name: "sflow_v5_decode",
	Description: "Decode an sFlow v5 datagram per the InMon publicly-published sFlow v5 " +
		"specification (sflow.org). sFlow is the packet-sampling counterpart to " +
		"NetFlow (covered by `netflow_v5_decode`): instead of summarising per-flow " +
		"state, sFlow exports a configurable 1-in-N sample of the packets transiting " +
		"a device, plus periodic interface counters. Operationally, sFlow is the " +
		"dominant monitoring telemetry on every modern datacenter switch — Arista, " +
		"Cisco Nexus, HP, Juniper QFX, Mellanox, Cumulus — because it scales linearly " +
		"with link speed regardless of flow churn. DDoS-detection, capacity planning, " +
		"and security-NDR platforms all consume sFlow. Decodes:\n\n" +
		"- **Datagram common header** (28 or 40 bytes; Version=5 + Agent Address " +
		"Type [1 IPv4 / 2 IPv6] + Agent Address + Sub-Agent ID + Sequence Number " +
		"+ System Uptime ms + Sample Count).\n" +
		"- **Sample walker** — 8-byte header (Sample Type uint32 BE split into top " +
		"12 bits Enterprise + bottom 20 bits Format + Sample Length uint32 BE) + " +
		"per-format body. **4-entry standard sample format table**: 1 Flow Sample, " +
		"2 Counter Sample, 3 Expanded Flow Sample, 4 Expanded Counter Sample.\n" +
		"- **Flow Sample body** (Format 1): Sequence + Source ID (8-bit Source " +
		"Class + 24-bit Source Index — Class names: ifIndex / smonVlanDataSource / " +
		"entPhysicalEntry) + **Sampling Rate** (1-in-N) + Sample Pool + Drops + " +
		"Input/Output ifIndex (high 2 bits of Output encode special semantics — " +
		"Discarded / Multiple destinations / Unknown — surfaced as a Note) + " +
		"flow_records walker.\n" +
		"- **Flow Record types** (most common): 1 Raw Packet Header (Header " +
		"Protocol with **17-entry name table** — Ethernet / IPv4 / IPv6 / MPLS / " +
		"802.11 / etc. — + Frame Length on wire + Stripped octets + Sampled " +
		"Header Length + Header Bytes hex preview; when the header protocol is " +
		"Ethernet or IPv4/IPv6 the sampled L3 packet is **decoded in place** — the " +
		"sampled flow's addresses / protocol / ports — possibly partial since the " +
		"capture is truncated, with a non-IP header left as hex); 2 Ethernet Frame Data (length " +
		"+ src/dst MAC + EtherType); 3 IPv4 Data (length + IP protocol + src/dst " +
		"+ src/dst port + TCP flags + ToS); 4 IPv6 Data.\n" +
		"- **Counter Sample body** (Format 2): Sequence + Source ID + counter_" +
		"records walker.\n" +
		"- **Counter Record type 1 (Generic Interface Counters)** — full 88-byte " +
		"body with all 19 ifEntry-equivalent fields: ifIndex / ifType / ifSpeed " +
		"(uint64) / ifDirection / ifStatus / ifInOctets (uint64) / ifInUcastPkts / " +
		"ifInMulticastPkts / ifInBroadcastPkts / ifInDiscards / ifInErrors / " +
		"ifInUnknownProtos / ifOutOctets (uint64) / ifOutUcastPkts / " +
		"ifOutMulticastPkts / ifOutBroadcastPkts / ifOutDiscards / ifOutErrors / " +
		"ifPromiscuousMode.\n\n" +
		"Pure offline parser — operators paste sFlow bytes (UDP destination port " +
		"6343) from a `tcpdump -X udp port 6343` line or a Wireshark Follow-UDP-" +
		"Stream view and get the documented header + sample breakdown.\n\n" +
		"Out of scope (deferred): UDP framing (feed sFlow bytes after the UDP " +
		"header strip — sFlow runs on UDP destination port 6343); sFlow v4 and " +
		"earlier (wire format changed significantly; v5 has been the standard " +
		"since 2003); per-Counter-Record dissection beyond Generic Interface " +
		"Counters (Ethernet / Token Ring / 802.11 / VG / VLAN / Processor / Radio " +
		"counters — surfaced as raw hex; a future iteration could add them); Raw " +
		"Packet Header non-IP inner dissection (a non-IP EtherType or non-Ethernet/" +
		"non-IP header protocol is left as hex; only IP payloads are decoded in " +
		"place); sFlow agent " +
		"state-machine reasoning (sampling-rate drift, polling-interval skew — " +
		"higher-level analysis).\n\n" +
		"Source: docs/catalog/gap-analysis.md (packet-sampling counterpart to " +
		"NetFlow; dominant on datacenter switches; consumed by every modern " +
		"DDoS-detection + capacity-planning + security-NDR platform). Wrap-vs-" +
		"native: native — the sFlow v5 spec is fully public; XDR-encoded wire " +
		"format with a 32-byte header + uniform (sample type + length + body) " +
		"records; no crypto, no compression.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"sFlow v5 datagram bytes (after UDP header strip; UDP destination port 6343). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."},
			"max_header_bytes":{"type":"integer","description":"Cap the per-Raw-Packet-Header hex preview (default 128). Zero shows the full sampled header."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   sflowV5DecodeHandler,
}

func sflowV5DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("sflow_v5_decode: 'hex' is required")
	}
	opts := sflow.DefaultDecodeOpts()
	if v, ok := p["max_header_bytes"]; ok {
		if n, ok := intArg(v); ok {
			opts.MaxHeaderBytes = n
		}
	}
	res, err := sflow.Decode(raw, opts)
	if err != nil {
		return "", fmt.Errorf("sflow_v5_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
