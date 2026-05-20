// netflow9.go — host-side NetFlow v9 packet decoder Spec.
// Wraps the internal/netflow9 walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/netflow9"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(netflowV9DecodeSpec)
}

var netflowV9DecodeSpec = Spec{
	Name: "netflow_v9_decode",
	Description: "Decode a NetFlow v9 packet per RFC 3954. NetFlow v9 is the template-" +
		"based flow-export format that superseded NetFlow v5 (1996; covered by " +
		"`netflow_v5_decode`) and bridged to IPFIX (RFC 7011); it's the dominant " +
		"NetFlow version on modern (post-2010) Cisco / Juniper / Arista enterprise " +
		"+ carrier gear. NetFlow v9's killer feature is template-based " +
		"extensibility: instead of a hardcoded 48-byte record like v5, exporters " +
		"define Templates that name the fields and their widths, then send Data " +
		"FlowSets that reference a Template ID and contain back-to-back records in " +
		"that template's shape. Decodes:\n\n" +
		"- **20-byte header** (RFC 3954 §5.1): Version (must be 9) + **Count** " +
		"(number of FlowSets) + SysUptime ms + Unix Seconds (surfaced as RFC 3339 " +
		"ISO) + **Sequence Number** (per-source monotonic — gaps signal collector " +
		"data loss) + **Source ID** (unique exporter+observation-point ID).\n" +
		"- **FlowSet walker** — repeated 4-byte header (FlowSet ID + Length, " +
		"Length including this 4-byte header) + body. **3-kind name table**: " +
		"FlowSet ID 0 Template FlowSet / 1 Options Template FlowSet / ≥ 256 Data " +
		"FlowSet (the FlowSet ID matches the Template ID of an earlier Template " +
		"FlowSet).\n" +
		"- **Template FlowSet** (FlowSet ID = 0; RFC 3954 §5.2): Template ID + " +
		"Field Count + N × 4-byte Field Specifier (Field Type + Field Length). " +
		"Field Type resolved via a **~40-entry name table** covering the most " +
		"common IANA NetFlow IPFIX Information Element IDs: IN_BYTES / IN_PKTS / " +
		"FLOWS / PROTOCOL / SRC_TOS / TCP_FLAGS / L4_SRC_PORT / IPV4_SRC_ADDR / " +
		"SRC_MASK / INPUT_SNMP / L4_DST_PORT / IPV4_DST_ADDR / DST_MASK / " +
		"OUTPUT_SNMP / IPV4_NEXT_HOP / SRC_AS / DST_AS / BGP_IPV4_NEXT_HOP / " +
		"MUL_DST_PKTS / MUL_DST_BYTES / LAST_SWITCHED / FIRST_SWITCHED / " +
		"OUT_BYTES / OUT_PKTS / IPV6_SRC_ADDR / IPV6_DST_ADDR / IPV6_SRC_MASK / " +
		"IPV6_DST_MASK / IPV6_FLOW_LABEL / ICMP_TYPE / MUL_IGMP_TYPE / " +
		"SAMPLING_INTERVAL / SAMPLING_ALGORITHM / FLOW_ACTIVE_TIMEOUT / " +
		"FLOW_INACTIVE_TIMEOUT / ENGINE_TYPE / ENGINE_ID / TOTAL_BYTES_EXP / " +
		"TOTAL_PKTS_EXP / TOTAL_FLOWS_EXP / SRC_MAC / DST_MAC / SRC_VLAN / " +
		"DST_VLAN / IP_PROTOCOL_VERSION / DIRECTION / IPV6_NEXT_HOP / " +
		"BGP_IPV6_NEXT_HOP / FLOW_END_REASON. Per-template `record_size_bytes` " +
		"derived from the sum of Field Lengths.\n" +
		"- **Options Template FlowSet** (FlowSet ID = 1; RFC 3954 §6) — same " +
		"shape as Template FlowSet plus scope and option distinction (surfaced " +
		"structurally; option semantics deferred).\n" +
		"- **Data FlowSet** (FlowSet ID ≥ 256; RFC 3954 §5.3) — the FlowSet ID " +
		"matches the Template ID of an earlier Template FlowSet. Records are " +
		"back-to-back in the template's field layout (no per-record header). " +
		"Without the matching template the decoder surfaces the body as raw hex " +
		"annotated with the referencing Template ID.\n\n" +
		"Pure offline parser — operators paste NetFlow bytes (UDP destination " +
		"port 2055 / 9555 / 9995) from a `tcpdump -X udp port 2055` line or a " +
		"Wireshark Follow-UDP-Stream view and get the documented header + per-" +
		"FlowSet breakdown.\n\n" +
		"Out of scope (deferred): UDP framing (feed NetFlow bytes after the UDP " +
		"header strip — NetFlow ships on UDP, conventionally to destination ports " +
		"2055 / 9555 / 9995); NetFlow v5 (use `netflow_v5_decode`); IPFIX (RFC " +
		"7011 — different envelope, warrants its own Spec); sFlow (use " +
		"`sflow_v5_decode`); stateful template cache across packets (single-" +
		"packet decode only; Data FlowSets without an in-packet template are " +
		"surfaced as raw hex annotated with their referencing Template ID); per-" +
		"field type-aware decoding of Data FlowSets (would require a full IANA " +
		"IE-id type table + per-IE decoder; deferred).\n\n" +
		"Source: docs/catalog/gap-analysis.md (template-based flow-export format " +
		"on every modern Cisco / Juniper / Arista enterprise + carrier gear; " +
		"completes the netflow_v5_decode + netflow_v9_decode + sflow_v5_decode " +
		"flow-telemetry trio). Wrap-vs-native: native — RFC 3954 is fully public; " +
		"NetFlow v9 has a tight 20-byte header followed by N FlowSets with a 4-" +
		"byte header each; no crypto, no compression.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"NetFlow v9 packet bytes (after UDP header strip; UDP destination port 2055 / 9555 / 9995). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   netflowV9DecodeHandler,
}

func netflowV9DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("netflow_v9_decode: 'hex' is required")
	}
	res, err := netflow9.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("netflow_v9_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
