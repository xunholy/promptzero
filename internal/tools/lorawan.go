// lorawan.go — host-side LoRaWAN PHYPayload dissector Spec,
// delegating to the internal/lorawan package for the walker
// proper.
//
// Wrap-vs-native judgement: LoRaWAN is a fully open
// specification (LoRa Alliance 1.0.x / 1.1). The walker is
// bit-level decoding over a ~12-300 byte frame with documented
// MAC-header and FHDR structures. Wrapping a FAP for this would
// require an SD-card install + a firmware-fork dependency for a
// pure parser. Native delivers offline analysis — operators
// paste a captured PHYPayload (from a Flipper LoRa sub-board, a
// CatSniffer, or any LoRa SDR) and inspect every MAC-layer
// field without an antenna attached.
//
// Pairs with bruce_lora_scan (which surfaces LoRa capability
// from a Bruce-equipped Flipper) — this Spec is the offline-
// analyst entry point for captured frames.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/lorawan"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(lorawanDecodeSpec)
}

var lorawanDecodeSpec = Spec{
	Name: "lorawan_decode",
	Description: "Decode a LoRaWAN PHYPayload frame (LoRa Alliance 1.0.x / 1.1) into structured " +
		"MAC-layer fields:\n\n" +
		"- **MHDR**: MType (Join Request / Accept, Confirmed / Unconfirmed Data Up / Down, " +
		"Rejoin Request, Proprietary) + Major version + uplink/downlink classification.\n" +
		"- **Data frames** (MType 2-5): FHDR (4-byte DevAddr in little-endian-on-wire / " +
		"big-endian-rendered form, FCtrl bitfield, 2-byte FCnt little-endian, 0-15-byte " +
		"FOpts MAC commands), FPort byte, FRMPayload (encrypted application payload — " +
		"surfaced as hex; decryption needs AppSKey out-of-band).\n" +
		"- **FCtrl bitfield**: differs uplink (ADR / ADRACKReq / ACK / ClassB / FOptsLen) vs " +
		"downlink (ADR / RFU / ACK / FPending / FOptsLen); the decoder picks the right " +
		"interpretation from the MType.\n" +
		"- **Join Request** (MType 0): 8-byte JoinEUI + 8-byte DevEUI (both little-endian on " +
		"wire, rendered as big-endian hex to match device-label form) + 2-byte DevNonce.\n" +
		"- **Join Accept** (MType 1): assumed decrypted by the operator (AppKey decryption " +
		"happens out-of-band). Decodes AppNonce + NetID + DevAddr + DLSettings + RxDelay + " +
		"optional 16-byte CFList.\n" +
		"- **MIC**: 4-byte Message Integrity Code at frame end (validation needs " +
		"NwkSKey / NwkSEncKey out-of-band).\n\n" +
		"Pure offline parser — no Flipper / SDR required. Pairs with bruce_lora_scan " +
		"(device-side scan). Accepts ':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (Sub-GHz decode space adjacent to honourable " +
		"mention bruce_lora_scan → LoRaWAN replay). Wrap-vs-native: native — LoRaWAN is a " +
		"fully open spec at lora-alliance.org, the walker is ~350 lines of bit-twiddling.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded LoRaWAN PHYPayload (MHDR + MACPayload + 4-byte MIC). ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   lorawanDecodeHandler,
}

func lorawanDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("lorawan_decode: 'hex' is required")
	}
	res, err := lorawan.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("lorawan_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
