// skinny_decode.go — host-side Skinny / SCCP (Cisco IP-phone signalling)
// decoder Spec, delegating to internal/skinny.
//
// Wrap-vs-native: native — a Skinny message is a little-endian length +
// reserved + message ID + body; a framed walk + an ID lookup. The
// VoIP-recon companion to sip/rtp/rtcp. Surfaces the call flow + the
// dialed digits (KeypadButton). Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/skinny"
)

func init() { //nolint:gochecknoinits
	Register(skinnyDecodeSpec)
}

var skinnyDecodeSpec = Spec{
	Name: "skinny_decode",
	Description: "Decode **Skinny / SCCP** (Skinny Client Control Protocol) — the Cisco-proprietary signalling " +
		"between a Cisco IP phone and a CallManager / CUCM (TCP 2000). A **VoIP-reconnaissance** target: SCCP " +
		"is unencrypted in many deployments, so a captured exchange reveals the **call flow** (register, " +
		"off-hook, dial, ring, connect, hang-up) and — via the **KeypadButton** messages — the actual digits " +
		"the user dials, i.e. the numbers being called. Joins the project's VoIP / signalling decoders " +
		"(`sip`, `rtp`, `rtcp`).\n\n" +
		"Decodes the self-delimiting Skinny stream: for each message the **length**, the **message ID** and " +
		"its **name** (from the full 132-entry SCCP message table), and — for KeypadButton — the **dialed " +
		"digit** (0-9, * and #). Multiple concatenated messages decode to a list.\n\n" +
		"No confidently-wrong output: only the KeypadButton body (the dialed digit) is decoded — Skinny has " +
		"~130 message types with varied, version-specific bodies, so every other body is surfaced as raw hex " +
		"with the message named. No network, no device, transmits nothing, so it is Low risk. ':' / '-' / " +
		"'_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (Cisco VoIP / UC call-flow + dialed-number recon). " +
		"Wrap-vs-native: native — a framed little-endian walk + an ID lookup, stdlib only, no new go.mod " +
		"dep; the message-name table is code-generated from scapy.contrib.skinny. Verified field-for-field " +
		"against scapy's Skinny layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"One or more concatenated Skinny/SCCP messages as hex (the TCP-2000 payload). ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   skinnyDecodeHandler,
}

func skinnyDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("skinny_decode: 'hex' is required")
	}
	res, err := skinny.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("skinny_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
