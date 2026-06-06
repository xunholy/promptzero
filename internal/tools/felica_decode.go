// felica_decode.go — host-side FeliCa (NFC-F / NFC Forum Type 3, JIS X
// 6319-4) command/response decoder Spec, delegating to internal/felica.
//
// Wrap-vs-native: native — a length-prefixed, fixed-layout frame: LEN + a
// 1-byte code + (for all but Polling) an 8-byte IDm + per-code fixed fields;
// a byte-slice walk + a code lookup, stdlib only. The NFC-F member of the
// project's NFC family — surfaces the card IDm / PMm / System Code and read
// block data from a captured FeliCa frame. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/felica"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(felicaDecodeSpec)
}

var felicaDecodeSpec = Spec{
	Name: "nfc_felica_decode",
	Description: "Decode a **FeliCa (NFC-F / NFC Forum Type 3, JIS X 6319-4)** command or response frame. FeliCa " +
		"is the Sony contactless protocol behind the huge **transit and payment** deployments of East Asia " +
		"(Suica / PASMO, Octopus, EZ-Link, nanaco, Edy, WAON) and the NFC Forum Type 3 Tag — the Flipper Zero " +
		"and Proxmark read it, and it is the **NFC-F member** of the project's NFC family alongside the type " +
		"2 / 4A / 4B / V decoders. A captured FeliCa frame is **NFC reconnaissance**: the polling response " +
		"carries the card's **IDm** (Manufacture ID — the unique identifier used for anti-collision and access " +
		"logging), its **PMm** (Manufacture Parameter — IC type + timing) and the **System Code** that names " +
		"the on-card application system (transit / payment / NDEF / FeliCa Lite-S); a Read Without Encryption " +
		"response carries the requested **block data** — the recon headline for FeliCa.\n\n" +
		"Decodes the frame: LEN, the command/response code + name (Polling, Request Service, Read/Write Without " +
		"Encryption, Request System Code, Authentication, …), the IDm (+ its 2-byte manufacturer code), the " +
		"PMm (+ IC code), the polling System Code, the read status flags + block data, and the Request System " +
		"Code list.\n\n" +
		"No confidently-wrong output: the frame layout and code table follow the authoritative Sony FeliCa " +
		"Card User's Manual / JIS X 6319-4 — there is no scapy model for FeliCa, so verification is by the " +
		"deterministic, byte-checkable structural walk against spec-built vectors (the same approach as " +
		"`goose_decode` / `sampled_values_decode`). Only the standardised deterministic fields are decoded; a " +
		"handful of **well-known System Codes are named** and any other System Code, IC code or unhandled " +
		"command body is surfaced as **raw hex** (the per-vendor value spaces are not enumerated); a declared " +
		"LEN that disagrees with the buffer, or a body too short for the code's fixed fields, is reported, not " +
		"guessed. The Polling command (which has no IDm) is special-cased. No network, no device, transmits " +
		"nothing, so it is Low risk. The input is the FeliCa frame starting at the LEN byte. ':' / '-' / '_' / " +
		"whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (NFC-F / FeliCa transit + payment recon; the NFC-F gap in the " +
		"NFC family). Wrap-vs-native: native — a byte-slice walk + a code lookup, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The FeliCa (NFC-F) frame starting at the LEN byte as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   felicaDecodeHandler,
}

func felicaDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("nfc_felica_decode: 'hex' is required")
	}
	res, err := felica.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("nfc_felica_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
