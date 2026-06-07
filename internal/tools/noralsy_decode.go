// noralsy_decode.go — host-side Noralsy 125 kHz LF access-control decoder Spec,
// delegating to internal/noralsy.
//
// Wrap-vs-native: native — fixed bit extraction in a 96-bit block + two
// nibble-XOR checksums; stdlib only. The offline LF-credential decoder for
// Noralsy, complementing em4100_decode / fdxb_decode / ioprox_decode /
// jablotron_decode / viking_decode and the PACS/Wiegand decoder. Offline read,
// no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/noralsy"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(noralsyDecodeSpec)
}

var noralsyDecodeSpec = Spec{
	Name: "noralsy_decode",
	Description: "Decode a **Noralsy** 125 kHz LF access-control credential from its decoded 96-bit (12-byte) " +
		"data block. Noralsy is the credential format used by Noralsy readers / fobs, common in **French** (and " +
		"wider European) residential access control and intercom systems. This is the offline complement to the " +
		"project's other LF-RFID decoders (`em4100_decode`, `fdxb_decode`, `ioprox_decode`, `jablotron_decode`, " +
		"`viking_decode`) and the PACS / Wiegand decoder — continuing the LF reader-cloning recon set.\n\n" +
		"Recovers the **card ID** and the **manufacture year** and validates the two nibble **checksums**. Input " +
		"is the *decoded* 96-bit block — the bytes a demodulator such as Proxmark3's `lf noralsy demod` or a " +
		"Flipper Zero LF read emits (MSB-first). The on-air ASK demodulation is the reader's concern and out of " +
		"scope; this decodes the data block, so the output is deterministic.\n\n" +
		"Layout: a 32-bit 0xBB0214FF preamble word, the card ID (a 28-bit value packed across bits 32-43 / 56-63 " +
		"/ 64-71), an 8-bit BCD year (bits 44-51), and two 4-bit nibble-XOR checksums (chk1 over bits 32-71, chk2 " +
		"over bits 0-75).\n\n" +
		"No confidently-wrong output: the bit layout, the (non-contiguous) card-ID assembly, the year field and " +
		"the two nibble checksums are taken from — and agree byte-for-byte between — **two independent reference " +
		"implementations** (the Proxmark3 client `cmdlfnoralsy.c` and the Flipper Zero firmware " +
		"`protocol_noralsy.c`). The 32-bit 0xBB0214FF preamble is a hard structural gate — a block without it is " +
		"**rejected** rather than mis-decoded; the two checksums are surfaced as `chk1_valid` / `chk2_valid` (a " +
		"frame whose checksums fail is reported, never asserted as a real credential). The two references " +
		"**disagree only on card-ID presentation** (Proxmark BCD-decimal vs Flipper hex), so **both** are " +
		"surfaced (`card_id_bcd` + `card_id_hex`, with a not-BCD flag) rather than asserting one; and the " +
		"19xx/20xx century split is a documented heuristic, noted as such. No network, no device, transmits " +
		"nothing, so it is Low risk. The input is the 12-byte Noralsy block. ':' / '-' / '_' / whitespace " +
		"separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (LF access-control reader-cloning; Noralsy complements the HID / " +
		"Indala / AWID / ioProx / Jablotron / Viking coverage). Wrap-vs-native: native — fixed bit extraction + " +
		"two nibble checksums, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The decoded 96-bit (12-byte) Noralsy block (from a Proxmark/Flipper LF read), MSB-first, as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   noralsyDecodeHandler,
}

func noralsyDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("noralsy_decode: 'hex' is required")
	}
	res, err := noralsy.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("noralsy_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
