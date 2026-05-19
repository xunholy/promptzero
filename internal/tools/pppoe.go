// pppoe.go — host-side PPPoE Discovery + Session decoder Spec.
// Wraps the internal/pppoe walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pppoe"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pppoeDecodeSpec)
}

var pppoeDecodeSpec = Spec{
	Name: "pppoe_decode",
	Description: "Decode a Point-to-Point Protocol over Ethernet (PPPoE) packet per " +
		"RFC 2516 — both the Discovery phase (PADI / PADO / PADR / PADS / PADT) and " +
		"the Session phase (PPP-in-PPPoE payload). PPPoE is the encapsulation every " +
		"DSL/FTTH BNG deployment uses to give residential subscribers a PPP session " +
		"on top of an Ethernet access network — BT / Deutsche Telekom / Orange / " +
		"AT&T / KPN / virtually every European + APAC fixed-line incumbent runs it. " +
		"Decodes:\n\n" +
		"- **6-byte header**:\n" +
		"  - byte 0: Version (4 bits) + Type (4 bits). Both MUST be 1 per RFC 2516 " +
		"(byte 0 = 0x11). Other values surface a conformance Note.\n" +
		"  - byte 1: **Code** with **6-entry name table**: 0x00 Session, 0x09 PADI, " +
		"0x07 PADO, 0x19 PADR, 0x65 PADS, 0xA7 PADT.\n" +
		"  - bytes 2-3: **Session ID** (uint16 BE; 0x0000 during Discovery, then " +
		"assigned by the AC in PADS).\n" +
		"  - bytes 4-5: **Length** (uint16 BE; length of the payload after the " +
		"6-byte header).\n" +
		"- **Discovery TLV walker** (Codes 0x09 / 0x07 / 0x19 / 0x65 / 0xA7): each " +
		"TLV is Tag Type (2 bytes BE) + Tag Length (2 bytes BE) + Tag Value. Walker " +
		"iterates until End-Of-List (0x0000). **10-entry Tag Type name table** (RFC " +
		"2516 §4): 0x0000 End-Of-List, 0x0101 Service-Name (UTF-8), 0x0102 AC-Name " +
		"(Access Concentrator name, UTF-8), 0x0103 Host-Uniq (client cookie), 0x0104 " +
		"AC-Cookie (AC-chosen DoS-mitigation cookie), 0x0105 Vendor-Specific, 0x0110 " +
		"Relay-Session-ID, 0x0201 Service-Name-Error, 0x0202 AC-System-Error, 0x0203 " +
		"Generic-Error. Text tags surface decoded UTF-8 alongside raw hex.\n" +
		"- **Session-stage payload** (Code 0x00): the first 2 bytes are the PPP " +
		"Protocol Identifier (uint16 BE per RFC 1661). **9-entry PPP Protocol name " +
		"table**: 0x0021 IPv4, 0x0057 IPv6, 0x8021 IPCP, 0x8057 IPv6CP, 0xC021 LCP, " +
		"0xC023 PAP, 0xC223 CHAP, 0xC227 EAP-over-PPP (deprecated), 0xC229 EAP.\n" +
		"- **Conformance checks**:\n" +
		"  - Version != 1 or Type != 1 surfaces a Note.\n" +
		"  - PADI / PADO / PADR with non-zero Session ID surface a Note (only PADS " +
		"can assign a Session ID; PADT requires a known session).\n" +
		"  - Length field mismatch (declared vs buffer remaining) surfaces a Note.\n\n" +
		"Pure offline parser — operators paste post-Ethernet bytes (EtherType 0x8863 " +
		"for Discovery or 0x8864 for Session) from a `tcpdump -X ether proto 0x8863` " +
		"line, a Wireshark Follow-Frame view, or any PPPoE-emitting tool and get the " +
		"documented header + per-phase body. Pairs with `ip_packet_decode` for the " +
		"inner IPv4 / IPv6 subscriber payload after the PPP Protocol ID strip.\n\n" +
		"Out of scope (deferred): Ethernet framing (feed bytes after EtherType " +
		"0x8863 / 0x8864 strip); PPP frame deep dissection (LCP CONFIG-REQ option " +
		"TLVs, PAP / CHAP / EAP exchanges, IPCP option TLVs — Protocol ID is " +
		"recognised but the body is raw hex); PPPoE Tag Value deep dissection beyond " +
		"UTF-8 / hex (Vendor-Specific body, Service-Name semantics — operator's " +
		"analysis).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational fixed-line broadband " +
		"protocol — universal in DSL/FTTH BNG deployments). Wrap-vs-native: native " +
		"— RFC 2516 is fully public; wire format is a tight 6-byte header + TLV " +
		"stream or PPP frame; no crypto, no compression, no varints.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"PPPoE packet bytes (after the EtherType 0x8863 Discovery / 0x8864 Session strip). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pppoeDecodeHandler,
}

func pppoeDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("pppoe_decode: 'hex' is required")
	}
	res, err := pppoe.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("pppoe_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
