// bfd.go — host-side BFD Control packet decoder Spec.
// Wraps the internal/bfd walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/bfd"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bfdControlDecodeSpec)
}

var bfdControlDecodeSpec = Spec{
	Name: "bfd_control_decode",
	Description: "Decode a BFD (Bidirectional Forwarding Detection) Control packet per " +
		"RFC 5880. BFD is the sub-second link-failure detection protocol that pairs " +
		"with OSPF / BGP / static routes to give routing protocols 100ms convergence " +
		"in datacenter and ISP backbone deployments — every modern service-provider " +
		"network and every cloud-native overlay runs BFD on its critical paths. " +
		"Pairs with `ospf_packet_decode` + `bgp_message_decode` for the complete " +
		"routing + liveness picture. Decodes:\n\n" +
		"- **24-byte mandatory header** (RFC 5880 §4.1):\n" +
		"  - byte 0: Version (3 bits; 1) + **Diagnostic** (5 bits) with **9-entry " +
		"name table**: 0 No Diagnostic, 1 Control Detection Time Expired, 2 Echo " +
		"Function Failed, 3 Neighbor Signaled Session Down, 4 Forwarding Plane Reset, " +
		"5 Path Down, 6 Concatenated Path Down, 7 Administratively Down, 8 Reverse " +
		"Concatenated Path Down.\n" +
		"  - byte 1: **State** (2 bits) with **4-entry name table** (0 AdminDown, " +
		"1 Down, 2 Init, 3 Up) + **6 flag bits**: P (Poll), F (Final), C (Control " +
		"Plane Independent), A (Authentication Present), D (Demand Mode), M " +
		"(Multipoint, reserved).\n" +
		"  - byte 2: Detect Mult — consecutive missed control packets before declaring " +
		"the session down. Detect time = DetectMult × peer's TX Interval.\n" +
		"  - byte 3: Length — total BFD packet length in bytes.\n" +
		"  - bytes 4-7: My Discriminator (uint32 BE) — sender's opaque session ID.\n" +
		"  - bytes 8-11: Your Discriminator (uint32 BE) — last received peer's " +
		"Discriminator (0 until established).\n" +
		"  - bytes 12-15: **Desired Min TX Interval** (uint32 BE microseconds, " +
		"converted to ms).\n" +
		"  - bytes 16-19: **Required Min RX Interval** (uint32 BE microseconds, " +
		"converted to ms).\n" +
		"  - bytes 20-23: **Required Min Echo RX Interval** (uint32 BE microseconds, " +
		"converted to ms; 0 disables Echo).\n" +
		"- **Authentication Section** (when A flag set): Auth Type (1 byte; " +
		"**5-entry name table**: 1 Simple Password, 2 Keyed MD5, 3 Meticulous Keyed " +
		"MD5, 4 Keyed SHA1, 5 Meticulous Keyed SHA1) + Auth Len + Auth Key ID + Auth " +
		"Data. Simple Password surfaces decoded text; MD5/SHA1 variants surface the " +
		"Sequence Number + digest hex.\n" +
		"- **Conformance check** — Version != 1 surfaces a Note; Length != actual " +
		"buffer length surfaces a Note; Detect Mult == 0 surfaces a Note (must be " +
		"≥ 1 per RFC 5880 §4.1).\n\n" +
		"Pure offline parser — operators paste BFD bytes (UDP dest port 3784 for " +
		"single-hop or 4784 for multi-hop per RFC 5882) from a `tcpdump -X udp port " +
		"3784` line, a Wireshark Follow-UDP-Stream view, a Quagga / FRR / BIRD / " +
		"Juniper / Cisco debug log, or any BFD-speaking router's tcpdump and get the " +
		"documented header + optional auth section.\n\n" +
		"Out of scope (deferred): UDP / IP framing (feed UDP-payload bytes); BFD " +
		"Echo packets (opaque user-defined format; receiver loops them back without " +
		"inspection); S-BFD (Seamless BFD, RFC 7880 — different stateless approach; " +
		"future Spec); cryptographic verification (Auth Type 2-5 recognised but " +
		"digest verification belongs in a separate Spec); BFD-on-MPLS / BFD-for-" +
		"VxLAN / BFD-for-Geneve (same BFD wire format but different encapsulations).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational link-failure-detection " +
		"protocol — universal in modern datacenter and ISP backbones). Wrap-vs-" +
		"native: native — RFC 5880 is fully public; wire format is a tight 24-byte " +
		"mandatory header with an optional variable-length Authentication Section; " +
		"no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"BFD Control packet bytes (UDP payload after the outer IP+UDP header strip; UDP dest port 3784 single-hop or 4784 multi-hop). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bfdControlDecodeHandler,
}

func bfdControlDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("bfd_control_decode: 'hex' is required")
	}
	res, err := bfd.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("bfd_control_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
