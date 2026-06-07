// jablotron_decode.go — host-side Jablotron 125 kHz LF access-control decoder
// Spec, delegating to internal/jablotron.
//
// Wrap-vs-native: native — fixed bit/byte extraction in a 64-bit block + an
// additive-XOR checksum + a BCD render; stdlib only. The offline LF-credential
// decoder for Jablotron, complementing em4100_decode / fdxb_decode /
// ioprox_decode and the PACS/Wiegand decoder. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/jablotron"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(jablotronDecodeSpec)
}

var jablotronDecodeSpec = Spec{
	Name: "jablotron_decode",
	Description: "Decode a **Jablotron** 125 kHz LF access-control credential from its decoded 64-bit (8-byte) " +
		"data block. Jablotron is the credential format used by Jablotron readers / fobs, widely deployed across " +
		"**Czech / Slovak / wider-EU** access control and intercom systems. This is the offline complement to the " +
		"project's other LF-RFID decoders (`em4100_decode`, `fdxb_decode`, `ioprox_decode`) and the PACS / " +
		"Wiegand decoder (which cover HID Prox / Indala / AWID / ioProx but **not** Jablotron) — continuing the " +
		"LF reader-cloning recon set.\n\n" +
		"Recovers the **40-bit card data**, renders the **printed card number** (BCD), and validates the 8-bit " +
		"**checksum**. Input is the *decoded* 64-bit block — the bytes a demodulator such as Proxmark3's `lf " +
		"jablotron demod` or a Flipper Zero LF read emits (MSB-first). The on-air ASK demodulation is the " +
		"reader's concern and out of scope; this decodes the data block, so the output is deterministic.\n\n" +
		"Layout: a 16-bit 0xFFFF preamble, 40-bit card data (bits 16-55), 8-bit checksum (bits 56-63). The " +
		"checksum is (sum of the five card bytes mod 256) XOR 0x3A. The printed card number reads each card byte " +
		"as two BCD digits, the five concatenated as a base-100 decimal.\n\n" +
		"No confidently-wrong output: the bit layout, the checksum and the BCD card-number render are taken from " +
		"— and agree byte-for-byte between — **two independent reference implementations** (the Proxmark3 client " +
		"`cmdlfjablotron.c` and the Flipper Zero firmware `protocol_jablotron.c`). The 0xFFFF preamble is a hard " +
		"structural gate — a block without it is **rejected** as not-a-Jablotron-frame rather than mis-decoded; " +
		"the checksum is surfaced as `crc_valid` (a structurally-valid block that fails the checksum is reported, " +
		"never asserted as a real credential); and when the card data is not valid BCD the printed-number field " +
		"is flagged and the raw 40-bit value is relied upon. No network, no device, transmits nothing, so it is " +
		"Low risk. The input is the 8-byte Jablotron block. ':' / '-' / '_' / whitespace separators and a '0x' " +
		"prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (LF access-control reader-cloning; Jablotron complements the HID / " +
		"Indala / AWID / ioProx coverage). Wrap-vs-native: native — fixed bit extraction + a checksum + a BCD " +
		"render, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The decoded 64-bit (8-byte) Jablotron block (from a Proxmark/Flipper LF read), MSB-first, as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   jablotronDecodeHandler,
}

func jablotronDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("jablotron_decode: 'hex' is required")
	}
	res, err := jablotron.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("jablotron_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
