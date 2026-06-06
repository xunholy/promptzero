// tcl_decode.go — host-side ISO 14443-4 T=CL block-protocol decoder Spec,
// delegating to internal/tcl.
//
// Wrap-vs-native: native — the PCB is a single byte of bit-fields + an
// optional CID byte + (I-blocks) an optional NAD byte + the INF field; a bit
// read + two optional byte reads, stdlib only. The T=CL transport member of
// the project's NFC family — surfaces the block type (I/R/S), chaining /
// ACK-NAK / WTX-DESELECT, CID/NAD, and the INF (APDU fragment). Offline read,
// no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/tcl"
)

func init() { //nolint:gochecknoinits
	Register(tclDecodeSpec)
}

var tclDecodeSpec = Spec{
	Name: "nfc_tcl_decode",
	Description: "Decode an **ISO/IEC 14443-4 T=CL** block — the half-duplex block transmission protocol that " +
		"carries APDUs between a contactless reader (PCD) and a Type-4 proximity card (PICC) after activation. " +
		"It is the transport layer of the project's NFC stack: ATQA + SAK identify the card " +
		"(`nfc_iso14443a_identify`), the ATS advertises its capabilities (same tool), **T=CL frames the " +
		"exchange (this tool)**, and the APDUs inside are decoded by the ISO 7816 APDU tools. Every T=CL frame " +
		"starts with a **Protocol Control Byte (PCB)** selecting one of three block types: an **I-block** " +
		"(information — carries an APDU, possibly chained), an **R-block** (receive-ready — ACK / NAK for " +
		"chaining flow control) or an **S-block** (supervisory — WTX waiting-time-extension or DESELECT). " +
		"Decoding the PCB of a captured T=CL exchange reveals the block type, the block number / chaining " +
		"state, the CID (card identifier) and NAD (node address) usage, the R-block ACK/NAK and the S-block " +
		"WTX/DESELECT, and lifts out the **INF field** (the APDU fragment) for handoff to the APDU decoder — " +
		"useful when analysing an NFC reader/card capture.\n\n" +
		"No confidently-wrong output: the PCB coding follows ISO 14443-4 §7.1 and was reconciled against the " +
		"canonical PCB values used by Proxmark / libnfc (I-block 0x02 / chaining 0x12, R(ACK) 0xA2 / R(NAK) " +
		"0xB2, S(DESELECT) 0xC2 / S(WTX) 0xF2, CID bit 0x08); the block type is taken from the top two bits " +
		"(00 = I, 10 = R, 11 = S; 01 is RFU and reported as such). Only the standardised PCB + CID + NAD + " +
		"S(WTX) parameter are decoded — the **INF field (the APDU fragment or proprietary payload) is surfaced " +
		"as raw hex** for handoff to the APDU decoder, never reinterpreted here; a PCB with wrong fixed bits, " +
		"or a frame truncated before a promised CID / NAD byte, is reported, not guessed. No network, no " +
		"device, transmits nothing, so it is Low risk. The input is the T=CL block starting at the PCB. ':' / " +
		"'-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (NFC T=CL transport; completes the 14443 stack identify → ATS → " +
		"T=CL → APDU). Wrap-vs-native: native — a bit read + two optional byte reads, stdlib only, no new " +
		"go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The ISO 14443-4 T=CL block starting at the PCB as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   tclDecodeHandler,
}

func tclDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("nfc_tcl_decode: 'hex' is required")
	}
	res, err := tcl.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("nfc_tcl_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
