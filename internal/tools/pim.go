// pim.go — host-side PIMv2 packet decoder Spec.
// Wraps the internal/pim walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pim"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pimDecodeSpec)
}

var pimDecodeSpec = Spec{
	Name: "pim_decode",
	Description: "Decode a Protocol Independent Multicast version 2 (PIM-SM v2) packet " +
		"per RFC 7761. PIM is the de-facto router↔router multicast routing protocol " +
		"in every enterprise + ISP + cloud fabric that carries multicast traffic; " +
		"the Dense-Mode + BIDIR variants share the same packet envelope and the " +
		"same type space. Pairs with `igmp_decode` (which decodes host↔router " +
		"multicast group-management on the same networks) for the complete IPv4 " +
		"multicast signalling picture. Decodes:\n\n" +
		"- **4-byte common header**: byte 0 = Version (4 bits; always 2) + Type " +
		"(4 bits); byte 1 = Reserved; bytes 2-3 = Checksum (uint16 BE, hex-formatted).\n" +
		"- **11-entry Type name table**: 0 Hello, 1 Register, 2 Register-Stop, 3 " +
		"Join/Prune, 4 Bootstrap, 5 Assert, 6 Graft (PIM-DM only), 7 Graft-Ack " +
		"(PIM-DM only), 8 Candidate-RP-Advertisement, 9 State Refresh (PIM-DM " +
		"only), 10 DF Election (PIM-BIDIR).\n" +
		"- **Hello body** (Type 0): TLV option walker with **5-entry option type " +
		"table**: 1 Holdtime (uint16 seconds; 0xFFFF = never timeout), 2 LAN Prune " +
		"Delay (uint16 propagation_delay + T-bit + uint16 override_interval), 19 " +
		"DR Priority (uint32 — higher wins), 20 Generation ID (uint32 — changes on " +
		"neighbor reset), 24 Address List (encoded-address list of secondary LAN " +
		"addresses).\n" +
		"- **Register body** (Type 1): 4-byte flags (B = Border-bit, N = " +
		"Null-Register-bit) + encapsulated multicast IP datagram (raw hex; first-" +
		"nibble heuristic for inner IPv4 vs IPv6).\n" +
		"- **Register-Stop body** (Type 2): Encoded Group Address + Encoded " +
		"Unicast Source Address.\n" +
		"- **Join/Prune body** (Type 3): Encoded Unicast Upstream Neighbor + " +
		"Reserved + Num Groups + Hold Time + N × Group records (Encoded Group + " +
		"Num Joined Sources + Num Pruned Sources + Joined Source list + Pruned " +
		"Source list).\n" +
		"- **Bootstrap body** (Type 4): Fragment Tag + Hash Mask Len + BSR Priority " +
		"+ Encoded Unicast BSR Address + per-group RP-Set remainder (surfaced as " +
		"hex; the per-group walker is deferred).\n" +
		"- **Assert body** (Type 5): Encoded Group + Encoded Unicast Source + 1-bit " +
		"R (RPT bit) + 31-bit Metric Preference + 32-bit Metric. Used for " +
		"tie-breaking when multiple PIM routers see the same multicast forwarder " +
		"candidate on a LAN.\n" +
		"- **Encoded Address parsing** (RFC 7761 §4.9.1): Encoded Unicast (AF + " +
		"Encoding Type + Address); Encoded Group (… + B-bit + Z-bit + Mask Len + " +
		"Address); Encoded Source (… + S/W/R bits + Mask Len + Address). Address " +
		"Family 1 = IPv4 (4 bytes), 2 = IPv6 (16 bytes).\n\n" +
		"Pure offline parser — operators paste PIM bytes (IP protocol number 103, " +
		"multicast to 224.0.0.13 for Hello / Bootstrap / Assert / Join-Prune, " +
		"unicast to RPs for Register) from a `tcpdump -X proto 103` line, a " +
		"Wireshark Follow-IP-Stream view, or any PIM-speaking router's tcpdump and " +
		"get the documented header + per-type body breakdown.\n\n" +
		"Out of scope (deferred): IP framing (feed bytes after IPv4/IPv6 header " +
		"strip — PIM runs over IP protocol 103); PIMv1 (the pre-RFC 2117 'DVMRP-" +
		"like' form is obsolete — no production deployments since the late 1990s); " +
		"multicast routing-table reasoning (RPF check, (*,G) and (S,G) tree state " +
		"— higher-level analysis); PIM checksum verification (the IPv4 " +
		"pseudo-header dependency would require the operator to provide the IP " +
		"src/dst); detailed Bootstrap per-group RP-Set walk (the BSR address is " +
		"decoded; per-group RP records are surfaced as a hex remainder).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational IPv4 multicast routing " +
		"protocol — universal in switched + routed multicast fabrics; natural " +
		"router-side pair to igmp_decode's host-side coverage). Wrap-vs-native: " +
		"native — RFC 7761 is fully public; wire format is a tight 4-byte common " +
		"header with per-type bodies built from well-defined Encoded Address " +
		"formats; no crypto, no compression.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"PIMv2 packet bytes (after IPv4/IPv6 header strip; IP protocol number 103). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pimDecodeHandler,
}

func pimDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("pim_decode: 'hex' is required")
	}
	res, err := pim.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("pim_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
