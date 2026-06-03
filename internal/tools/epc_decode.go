// epc_decode.go — host-side GS1 EPC (UHF RAIN RFID) binary dissector Spec,
// delegating to internal/epc.
//
// Wrap-vs-native: native — fixed bit-field extraction with a partition table
// and a GS1 mod-10 check digit, no dependency. The SGTIN-96 layout, partition
// table, and SGTIN→GTIN reconstruction are from the GS1 EPC Tag Data Standard,
// verified against its canonical worked example. Offline read of an
// operator-supplied EPC — no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/epc"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(epcDecodeSpec)
}

var epcDecodeSpec = Spec{
	Name: "epc_decode",
	Description: "Decode a GS1 **Electronic Product Code (EPC)** — the binary identifier on UHF **RAIN RFID** " +
		"(EPC Gen2 / ISO 18000-63) tags used pervasively in retail item-level tagging and supply-chain " +
		"logistics. This is the **UHF** complement to the toolkit's HF (ISO 14443/15693/NDEF) and LF " +
		"(EM4100 / HID / FDX-B / T5577) decoders.\n\n" +
		"Field: **hex** — the 96-bit EPC (24 hex digits; ':' / '-' / whitespace and an optional 0x prefix " +
		"tolerated). **SGTIN-96** (header 0x30, the dominant retail item-level scheme) is fully decoded: " +
		"filter, partition, company prefix, item reference, serial number, the canonical EPC tag URI " +
		"(`urn:epc:tag:sgtin-96:…`) and pure-identity URI (`urn:epc:id:sgtin:…`), and the reconstructed " +
		"**GTIN-14** (with a recomputed GS1 mod-10 check digit). The other 96-bit schemes (SSCC / SGLN / " +
		"GRAI / GIAI / GID, headers 0x31-0x35) are identified by name.\n\n" +
		"Reading a UHF tag needs a RAIN reader (hardware, out of scope) but the captured EPC decodes entirely " +
		"offline here. Offline, deterministic, transmits nothing -> Low risk. No confidently-wrong output: " +
		"the non-SGTIN schemes are recognised but not field-decoded (raw, with a note) rather than guessed; " +
		"unknown headers and 198-bit variants are reported unsupported. Verified against the GS1 EPC Tag Data " +
		"Standard canonical example. Wrap-vs-native: native — fixed bit-field extraction.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"96-bit EPC, 24 hex digits (optional 0x prefix; ':' / '-' / whitespace tolerated)."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   epcDecodeHandler,
}

func epcDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("epc_decode: 'hex' is required")
	}
	res, err := epc.DecodeHex(raw)
	if err != nil {
		return "", fmt.Errorf("epc_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
