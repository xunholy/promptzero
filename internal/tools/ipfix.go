// ipfix.go — host-side IPFIX message decoder Spec.
// Wraps the internal/ipfix walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ipfix"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ipfixDecodeSpec)
}

var ipfixDecodeSpec = Spec{
	Name: "ipfix_decode",
	Description: "Decode an IPFIX (IP Flow Information eXport) message per RFC 7011. " +
		"IPFIX is the IETF standardization of NetFlow v9 (covered by " +
		"`netflow_v9_decode`); the two protocols share the same template-based " +
		"philosophy, IANA Information Element registry, and Data Set layout, but " +
		"differ in three notable ways: (1) 16-byte header vs v9's 20 (drops Source " +
		"ID, adds explicit Length, renames per-exporter identifier to Observation " +
		"Domain ID); (2) Enterprise-bit-extended Field Specifiers (high bit of " +
		"Field Type signals presence of a 4-byte Enterprise Number after the " +
		"(15-bit Field Type, Length) pair); (3) Set IDs reserved 0-3 (2 Template, " +
		"3 Options Template, 256+ Data). IPFIX is used by Linux iptables/nftables " +
		"flow exporters, Cisco ASR/NCS, Juniper modern routers, ntopng, akvorado, " +
		"GoFlow2, pmacct, and every modern flow collector. Completes the netflow_" +
		"v5_decode + netflow_v9_decode + ipfix_decode + sflow_v5_decode flow-" +
		"telemetry quartet. Decodes:\n\n" +
		"- **16-byte header** (RFC 7011 §3.1): Version (must be 10) + Message " +
		"Length + Export Time (surfaced as RFC 3339 ISO) + **Sequence Number** " +
		"(per-Observation-Domain monotonic — gaps signal data loss) + " +
		"**Observation Domain ID** (unique per exporter + observation point).\n" +
		"- **Set walker** — repeated 4-byte header (Set ID + Set Length) + body. " +
		"**3-kind name table**: Set ID 2 Template Set / 3 Options Template Set / " +
		"≥ 256 Data Set (the Set ID matches the Template ID of an earlier " +
		"Template Set).\n" +
		"- **Template Set** (Set ID = 2; RFC 7011 §3.4.1): Template ID + Field " +
		"Count + N × Field Specifier. **Field Specifier format dispatched by " +
		"high bit of Field Type**: standard IE (high bit 0) = 2-byte Field Type " +
		"+ 2-byte Field Length; enterprise IE (high bit 1) = 2-byte Field Type " +
		"(low 15 bits) + 2-byte Field Length + 4-byte Enterprise Number (IANA " +
		"PEN). Field Type resolved via a **~45-entry name table** covering the " +
		"most common IANA IPFIX Information Element IDs: octetDeltaCount / " +
		"packetDeltaCount / deltaFlowCount / protocolIdentifier / " +
		"ipClassOfService / tcpControlBits / sourceTransportPort / " +
		"sourceIPv4Address / sourceIPv4PrefixLength / ingressInterface / " +
		"destinationTransportPort / destinationIPv4Address / " +
		"destinationIPv4PrefixLength / egressInterface / ipNextHopIPv4Address / " +
		"bgpSourceAsNumber / bgpDestinationAsNumber / bgpNextHopIPv4Address / " +
		"flowEndSysUpTime / flowStartSysUpTime / octetTotalCount / " +
		"packetTotalCount / sourceIPv6Address / destinationIPv6Address / " +
		"sourceIPv6PrefixLength / destinationIPv6PrefixLength / flowLabelIPv6 / " +
		"icmpTypeCodeIPv4 / igmpType / samplingInterval / flowActiveTimeout / " +
		"flowIdleTimeout / exportedOctetTotalCount / exportedMessageTotalCount " +
		"/ exportedFlowRecordTotalCount / minimumTTL / maximumTTL / " +
		"sourceMacAddress / postDestinationMacAddress / vlanId / postVlanId / " +
		"ipVersion / flowDirection / ipNextHopIPv6Address / bgpNextHopIPv6Address " +
		"/ destinationMacAddress / postSourceMacAddress / flowEndReason / " +
		"observationPointId / icmpTypeCodeIPv6 / flowStartSeconds / " +
		"flowEndSeconds / flowStartMilliseconds / flowEndMilliseconds / " +
		"ingressVRFID / egressVRFID. Per-template `record_size_bytes` derived " +
		"from sum of Field Lengths.\n" +
		"- **Options Template Set** (Set ID = 3; RFC 7011 §3.4.2): Template ID " +
		"+ Field Count + **Scope Field Count** + first ScopeFieldCount specifiers " +
		"are scope fields (e.g. meteringProcessId), remaining are option fields " +
		"(e.g. samplingProbability).\n" +
		"- **Data Set** (Set ID ≥ 256; RFC 7011 §3.4.3) — records back-to-back " +
		"in the matching Template's field layout. Surfaced as raw hex annotated " +
		"with the referencing Template ID.\n\n" +
		"Pure offline parser — operators paste IPFIX bytes (UDP / TCP / SCTP " +
		"destination port 4739 — IANA-assigned, often also 2055 / 9555 / 9995 " +
		"for legacy compatibility) from a `tcpdump -X udp port 4739` line or a " +
		"Wireshark Follow-UDP-Stream view and get the documented header + per-" +
		"Set breakdown.\n\n" +
		"Out of scope (deferred): UDP / TCP / SCTP framing (feed IPFIX bytes " +
		"after the transport header strip — IPFIX runs on UDP / TCP / SCTP " +
		"destination port 4739); NetFlow v9 (use `netflow_v9_decode`); NetFlow " +
		"v5 (use `netflow_v5_decode`); sFlow v5 (use `sflow_v5_decode`); " +
		"stateful template cache across messages (single-message decode only; " +
		"Data Sets without an in-message template are surfaced as raw hex " +
		"annotated with their referencing Template ID); per-field type-aware " +
		"decoding of Data Sets (would require a full IANA IE-id type table + " +
		"per-IE decoder; deferred); Structured Data (RFC 6313 — basicList / " +
		"subTemplateList / subTemplateMultiList) and Variable-Length Encoding " +
		"(surfaced as raw hex within Data Sets).\n\n" +
		"Source: docs/catalog/gap-analysis.md (IETF standardization of NetFlow " +
		"v9; foundational flow-export format on every modern flow collector + " +
		"Linux iptables/nftables exporter; completes the v5 + v9 + IPFIX + " +
		"sFlow flow-telemetry quartet). Wrap-vs-native: native — RFC 7011 is " +
		"fully public; IPFIX has a tight 16-byte header followed by N Sets " +
		"with a 4-byte header each; Enterprise-bit-extended Field Specifiers " +
		"are 8 bytes vs 4 for standard; no crypto, no compression.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"IPFIX message bytes (after transport header strip; UDP/TCP/SCTP destination port 4739). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ipfixDecodeHandler,
}

func ipfixDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ipfix_decode: 'hex' is required")
	}
	res, err := ipfix.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ipfix_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
