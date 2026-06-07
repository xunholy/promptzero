// viking_decode.go — host-side Viking 125 kHz LF access-control decoder Spec,
// delegating to internal/viking.
//
// Wrap-vs-native: native — fixed bit/byte extraction in a 64-bit block + an XOR
// checksum; stdlib only. The offline LF-credential decoder for Viking,
// complementing em4100_decode / fdxb_decode / ioprox_decode / jablotron_decode
// and the PACS/Wiegand decoder. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/viking"
)

func init() { //nolint:gochecknoinits
	Register(vikingDecodeSpec)
}

var vikingDecodeSpec = Spec{
	Name: "viking_decode",
	Description: "Decode a **Viking** 125 kHz LF access-control credential from its decoded 64-bit (8-byte) data " +
		"block. Viking is the credential format used by Viking / 'Viking Acs' LF readers and fobs. This is the " +
		"offline complement to the project's other LF-RFID decoders (`em4100_decode`, `fdxb_decode`, " +
		"`ioprox_decode`, `jablotron_decode`) and the PACS / Wiegand decoder (which cover HID Prox / Indala / " +
		"AWID / ioProx / Jablotron but **not** Viking) — continuing the LF reader-cloning recon set.\n\n" +
		"Recovers the **32-bit card ID** and validates the 8-bit **checksum**. Input is the *decoded* 64-bit " +
		"block — the bytes a demodulator such as Proxmark3's `lf viking demod` or a Flipper Zero LF read emits " +
		"(MSB-first). The on-air ASK demodulation is the reader's concern and out of scope; this decodes the data " +
		"block, so the output is deterministic.\n\n" +
		"Layout: a 24-bit 0xF20000 preamble, 32-bit card ID (bits 24-55), 8-bit checksum (bits 56-63). The " +
		"checksum is defined so the XOR of all eight bytes equals 0xA8.\n\n" +
		"No confidently-wrong output: the bit layout and the checksum are taken from — and agree byte-for-byte " +
		"between — **two independent reference implementations** (the Proxmark3 client `cmdlfviking.c` and the " +
		"Flipper Zero firmware `protocol_viking.c`). The 0xF20000 preamble is a hard structural gate — a block " +
		"without it is **rejected** as not-a-Viking-frame rather than mis-decoded; the checksum is surfaced as " +
		"`crc_valid` (a structurally-valid block that fails it is reported, never asserted as a real credential). " +
		"No network, no device, transmits nothing, so it is Low risk. The input is the 8-byte Viking block. " +
		"':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (LF access-control reader-cloning; Viking complements the HID / " +
		"Indala / AWID / ioProx / Jablotron coverage). Wrap-vs-native: native — fixed bit extraction + an XOR " +
		"checksum, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The decoded 64-bit (8-byte) Viking block (from a Proxmark/Flipper LF read), MSB-first, as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   vikingDecodeHandler,
}

func vikingDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("viking_decode: 'hex' is required")
	}
	res, err := viking.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("viking_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
