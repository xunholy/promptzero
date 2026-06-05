// wmbus.go — host-side Wireless M-Bus (868 MHz smart-meter radio)
// frame decoder Spec, delegating to the internal/wmbus package.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/wmbus"
)

func init() { //nolint:gochecknoinits
	Register(wmbusDecodeSpec)
}

var wmbusDecodeSpec = Spec{
	Name: "wmbus_decode",
	Description: "Decode a Wireless M-Bus (wM-Bus, EN 13757-4) radio frame — the 868 MHz " +
		"over-the-air framing that smart water / heat / gas / electricity meters broadcast and " +
		"that a Flipper Sub-GHz (or SDR) capture lifts off the air. The wired-M-Bus decoder " +
		"(mbus_decode) handles the shared application layer; this adds the radio-specific frame: " +
		"the length / control fields, the manufacturer + meter address, and the per-block CRC-16 " +
		"the wired bus does not use. Reading these telegrams **enumerates the meters in radio " +
		"range** and validates frame integrity — the passive-recon start of a smart-meter RF " +
		"assessment. Decodes (Format A):\n\n" +
		"- The **L (length)** field and the Format-A block layout, with **every block's CRC-16** " +
		"(EN 13757 polynomial 0x3D65) recomputed and reported valid / invalid.\n" +
		"- **Block 1**: the **C (control)** field (+ name: SND-NR spontaneous / SND-IR install " +
		"request / …), the **manufacturer** (the 3-letter FLAG code from the M field), and the " +
		"**address** — the BCD **meter ID**, the version, and the **device/medium type** (+ name: " +
		"water / gas / heat / electricity / cold water / …).\n" +
		"- The **transport-layer (TPL) header** after the CI field (short 0x7A / long 0x72 / none " +
		"0x78): the access number, status byte, and — the headline — the **encryption mode** from " +
		"the config word (plaintext vs **AES-128-CBC** mode 5/7, with the encrypted-block count and " +
		"the bidirectional / accessibility / synchronous flags). Whether the meter's data is " +
		"readable or AES-encrypted is the first thing a smart-meter assessment needs to know.\n" +
		"- The **de-chunked application payload** (the data blocks with their CRCs stripped and " +
		"concatenated) and its leading CI field — ready to paste into `mbus_decode` for the full " +
		"Variable-Data-Structure (consumption) read.\n\n" +
		"Paste the line-decoded frame bytes as hex (the 3-of-6 / Manchester line coding is " +
		"upstream — feed the decoded bytes). ':' / '-' / '_' / whitespace separators and a '0x' " +
		"prefix tolerated. Verified against a CRC-valid Format-A frame and a real meter header " +
		"block (CRC 0x3363).\n\n" +
		"Out of scope (deferred): Format B framing (single trailing CRC instead of per-block — " +
		"detected by CRC mismatch and noted); the 3-of-6 / Manchester line coding (upstream); AES " +
		"decryption of an encrypted payload (needs the meter key, not in the frame — the mode is " +
		"reported); and the application-layer DIF/VIF consumption decode (mbus_decode's job — the " +
		"de-chunked payload is surfaced for it).\n\n" +
		"Source: docs/catalog/gap-analysis.md (sub-GHz smart-metering decode space; the wM-Bus " +
		"radio framing explicitly deferred by internal/mbus). Wrap-vs-native: native — the wM-Bus " +
		"radio frame is a fixed public EN 13757-4 structure decoded by byte-field extraction plus " +
		"one standard CRC-16; reimplemented from the standard, not wrapped.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Line-decoded wM-Bus radio frame as hex (starts with the L length field). ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wmbusDecodeHandler,
}

func wmbusDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("wmbus_decode: 'hex' is required")
	}
	res, err := wmbus.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("wmbus_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
