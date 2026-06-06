// pfcp_decode.go — host-side PFCP (Packet Forwarding Control Protocol)
// decoder Spec, delegating to internal/pfcp.
//
// Wrap-vs-native: native — the PFCP header is a fixed bitfield + a TLV IE
// list (3GPP TS 29.244, the 5G N4 / 4G CUPS interface); byte-field
// extraction + a TLV walk. Joins the cellular set (gtp/gtpv2/gsmtap/
// diameter). Surfaces the N4 session-manipulation attack surface.
// Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pfcp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pfcpDecodeSpec)
}

var pfcpDecodeSpec = Spec{
	Name: "pfcp_decode",
	Description: "Decode **PFCP** (Packet Forwarding Control Protocol, 3GPP TS 29.244) — the control protocol of " +
		"the **5G N4 interface (SMF↔UPF)** and the 4G CUPS Sxa/Sxb/Sxc interfaces, by which the control " +
		"plane programs the user-plane function's packet-forwarding rules (PDRs / FARs / QERs / URRs) over " +
		"UDP 8805. PFCP is a recognised **5G-core-security** target: an attacker who can reach N4 can forge " +
		"PFCP **Session Modification / Deletion** messages to tear down or redirect a subscriber's bearer " +
		"(a DoS or on-path attack). Decoding a captured PFCP exchange surfaces the message type, the session " +
		"endpoint identifier (**SEID**) and the rule IEs being programmed. Joins the cellular decoder set " +
		"(`gtp_decode`, `gtpv2_decode`, `gsmtap_decode`, `diameter_decode`).\n\n" +
		"Decodes the header (version, the message-priority / SEID flags, the **message type** named from the " +
		"TS 29.244 table — Heartbeat, Association Setup, Session Establishment / Modification / Deletion / " +
		"Report, etc. — the length, the optional 64-bit **SEID**, and the sequence number) and the body as a " +
		"list of **Information Elements** (each TLV's 2-octet type — named from the full TS 29.244 IE table " +
		"— length and value); the **Cause** IE is decoded to its code.\n\n" +
		"No confidently-wrong output: grouped IEs (those that nest further IEs) and non-Cause IE values are " +
		"surfaced as raw hex — the IE value formats are numerous and release-specific, so only the structure " +
		"+ Cause are decoded. No network, no device, transmits nothing, so it is Low risk. ':' / '-' / '_' / " +
		"whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (5G-core N4 session-manipulation recon). Wrap-vs-native: " +
		"native — byte-field extraction + a TLV walk, stdlib only, no new go.mod dep; the message-type / IE " +
		"name tables are code-generated from scapy. Verified field-for-field against scapy's PFCP layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"A PFCP message as hex (the payload of UDP 8805). ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pfcpDecodeHandler,
}

func pfcpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("pfcp_decode: 'hex' is required")
	}
	res, err := pfcp.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("pfcp_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
