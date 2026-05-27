// eigrp.go — host-side EIGRP wire-protocol decoder Spec.
// Wraps the internal/eigrp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/eigrp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(eigrpDecodeSpec)
}

var eigrpDecodeSpec = Spec{
	Name: "eigrp_decode",
	Description: "Decode an EIGRP (Enhanced Interior Gateway Routing Protocol) " +
		"packet per RFC 7868 (informational; Cisco proprietary until 2016). " +
		"EIGRP uses IP protocol number 88 — it runs directly over IP, not " +
		"TCP or UDP. Multicast to 224.0.0.10 (all EIGRP routers). Runs on " +
		"every Cisco enterprise campus / WAN deployment.\n\n" +
		"EIGRP is a **high-value enterprise routing target** — authentication " +
		"is OFF by default. Any device that sends a Hello with the correct " +
		"Autonomous System number immediately becomes an EIGRP neighbour and " +
		"can inject arbitrary routes, enabling traffic interception (MITM) or " +
		"black-hole attacks without needing any authentication material.\n\n" +
		"The wire format leaks: **Autonomous System number** — the primary " +
		"trust boundary; knowing the AS from a captured Hello allows immediate " +
		"neighbour spoofing; **K-values (metric weights)** — K1 (bandwidth) " +
		"K2 (load) K3 (delay) K4 (reliability) K5 (MTU weight); K1=1 K2=0 " +
		"K3=1 K4=0 K5=0 is the classic IOS default; non-default values " +
		"fingerprint IOS version or policy; **hold time** — adjacency timeout " +
		"in seconds; short values signal fast-convergence tuning; **software " +
		"version** — IOS major.minor + EIGRP major.minor from the Software " +
		"Version TLV (0x0004) carried in every Hello; enables exact IOS " +
		"release fingerprinting for CVE matching; **internal route topology** " +
		"— Internal Route TLVs (0x0102) in Update packets expose next_hop / " +
		"delay / bandwidth / prefix_length / destination subnet; reveals " +
		"complete internal network topology; **external redistribution** — " +
		"External Route TLVs (0x0103) expose redistribution sources (OSPF, " +
		"BGP, static, connected) with originating router and AS; **auth type** " +
		"— Auth TLV (0x0002) discloses MD5 (type 2, offline-crackable via " +
		"hashcat) or SHA-256 named-mode (type 3, IOS 15.1+ modern); absent " +
		"Auth TLV = NO AUTHENTICATION — neighbour spoofing is trivial.\n\n" +
		"Decodes:\n\n" +
		"- **20-byte EIGRP header**: version + opcode (7-entry name table: " +
		"1 Update / 3 Query / 4 Reply / 5 Hello / 6 IPX-SAP / 10 SIA-Query " +
		"/ 11 SIA-Reply) + checksum + flags (init / conditional_receive / " +
		"restart / end_of_table) + sequence + acknowledge + virtual_router_id " +
		"+ autonomous_system.\n" +
		"- **TLV walker**: type (2 BE) + length (2 BE) + value for all TLVs; " +
		"surfaces tlv_count and tlv_types list.\n" +
		"- **Parameters TLV (0x0001)**: K1-K5 metric weights + hold_time.\n" +
		"- **Auth TLV (0x0002)**: auth_type with name (MD5 / SHA-256), has_auth.\n" +
		"- **Software Version TLV (0x0004)**: IOS major.minor + EIGRP major.minor.\n" +
		"- **Internal Route TLV (0x0102)**: next_hop (dotted-quad), delay, " +
		"bandwidth, prefix_length, destination. First route prefix only.\n" +
		"- **Classification flags**: is_hello / is_update / is_query.\n\n" +
		"Pure offline parser — paste EIGRP packet bytes (IP protocol 88 " +
		"payload; stripped of IPv4 header) from tcpdump `proto eigrp` or " +
		"Wireshark EIGRP dissector and get the documented header + per-type " +
		"body breakdown.\n\n" +
		"Out of scope: External Route TLVs (0x0103) deep parse; IPv6 route " +
		"TLVs (0x0402 / 0x0403); Multi-Protocol TLVs (0x0602); Sequence " +
		"(0x0003) + Next Multicast Sequence (0x0005) + Stub Routing (0x0006) " +
		"TLVs; checksum verification; authentication material extraction " +
		"(auth_type only — NEVER surfaces auth_data); IP framing (feed bytes " +
		"after IPv4 header strip).\n\n" +
		"Source: gap analysis (enterprise IGP routing protocol — pairs with " +
		"ospf_packet_decode and bgp_message_decode for the complete enterprise " +
		"routing picture; EIGRP route injection is the canonical Cisco-shop " +
		"MITM primitive). Wrap-vs-native: native — RFC 7868 is public; " +
		"20-byte binary header + TLV chain; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"EIGRP packet bytes as hex (the IP protocol 88 payload after IPv4 header strip; multicast 224.0.0.10). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   eigrpDecodeHandler,
}

func eigrpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("eigrp_decode: 'hex' is required")
	}
	res, err := eigrp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("eigrp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
