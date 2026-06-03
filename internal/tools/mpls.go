// mpls.go — host-side MPLS label stack decoder Spec.
// Wraps the internal/mpls walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/mpls"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(mplsDecodeSpec)
}

var mplsDecodeSpec = Spec{
	Name: "mpls_decode",
	Description: "Decode an MPLS label stack per RFC 3032 (stack encoding) + RFC 5462 " +
		"(TC field rename from EXP). MPLS is the foundational label-switching protocol " +
		"of every ISP backbone, every L3VPN (MPLS-VPN), every EVPN/VPLS service, every " +
		"MPLS-TE traffic-engineering tunnel, every carrier-Ethernet pseudowire. Pairs " +
		"with `vlan_decode` / `vxlan_decode` / `gre_decode` / `geneve_decode` for the " +
		"complete encapsulation-protocol picture. Decodes:\n\n" +
		"- **4-byte-per-label entry**:\n" +
		"  - **Label** (20 bits, big-endian) — the actual MPLS label value\n" +
		"  - **TC** (Traffic Class, 3 bits) — formerly EXP (Experimental, RFC 5462 " +
		"renamed); QoS class indicator\n" +
		"  - **S** (Bottom of Stack, 1 bit) — 1 = this is the innermost label\n" +
		"  - **TTL** (Time to Live, 8 bits)\n" +
		"- **Stack walker** — iterates 4-byte entries until S=1 is reached, then " +
		"surfaces the remaining bytes as the payload. Surfaces an error if the buffer " +
		"is exhausted before any label sets S=1.\n" +
		"- **Reserved label name table** (RFC 3032 + extensions) — 8 documented:\n" +
		"  - 0 IPv4 Explicit NULL (RFC 3032 §2.1)\n" +
		"  - 1 Router Alert (RFC 3032 — must NEVER be at bottom of stack)\n" +
		"  - 2 IPv6 Explicit NULL (RFC 3032 §2.1)\n" +
		"  - 3 Implicit NULL (signalling only, never on wire)\n" +
		"  - 7 Entropy Label Indicator (ELI, RFC 6790)\n" +
		"  - 13 Generic Associated Channel Label (GAL, RFC 5586)\n" +
		"  - 14 OAM Alert Label (RFC 3429)\n" +
		"  - 15 Extension Label (RFC 7274)\n" +
		"- **Inner payload decode** — after the bottom-of-stack label, the payload " +
		"protocol isn't explicitly encoded. The decoder applies the canonical " +
		"convention (first nibble 4 → IPv4; 6 → IPv6; bottom label 0 → IPv4 Explicit " +
		"NULL; bottom label 2 → IPv6; first nibble 0 → EoMPLS / pseudowire control " +
		"word; otherwise likely Ethernet) and, when the payload is IP, **decodes the " +
		"inner packet in place** (the label-switched flow's addresses / protocol / " +
		"ports; a payload that doesn't parse as IP is reported with an error, raw hex " +
		"preserved). EoMPLS / pseudowire payloads stay raw hex.\n" +
		"- **Conformance check** — Router Alert label (1) at the bottom of stack " +
		"surfaces a Note flagging the RFC 3032 §2.1 violation.\n\n" +
		"Pure offline parser — operators paste MPLS frame bytes (after the EtherType " +
		"0x8847 unicast / 0x8848 multicast strip, or after the outer IP+UDP for MPLS-" +
		"over-UDP per RFC 7510, or after the outer GRE for MPLS-in-GRE) from a " +
		"`tcpdump -X ether proto 0x8847` line, a Wireshark Follow-Frame view, a Cisco " +
		"IOS `show mpls forwarding-table` capture, or any MPLS-emitting tool and get " +
		"the documented label stack plus inner-payload heuristic.\n\n" +
		"Out of scope (deferred): Ethernet framing (feed the MPLS bytes after the " +
		"EtherType strip); non-IP inner payloads (EoMPLS / pseudowire Ethernet — left " +
		"for a future Ethernet decoder); MPLS Control Word (RFC 4385) and Pseudowire Type dispatch " +
		"(detected as leading-0-nibble payload but the operator decides what " +
		"pseudowire type it is); LDP / RSVP-TE / BGP-LU label-distribution protocols " +
		"(these are control-plane — separate Spec).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational service-provider label-" +
		"switching protocol — every ISP backbone, L3VPN, EVPN, MPLS-TE deployment). " +
		"Wrap-vs-native: native — RFC 3032 / 5462 / 5586 / 6790 / 7274 are all fully " +
		"public; wire format is a tight 4-byte-per-entry bit-packed field; no crypto, " +
		"no compression, no varints.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"MPLS label-stack bytes as hex (after the EtherType 0x8847 / 0x8848 strip, or after the outer IP+UDP / GRE / etc.). At least one 4-byte label entry plus optional payload. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   mplsDecodeHandler,
}

func mplsDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("mpls_decode: 'hex' is required")
	}
	res, err := mpls.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("mpls_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
