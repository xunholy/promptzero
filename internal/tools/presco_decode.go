// presco_decode.go — host-side Presco 125 kHz LF access-control decoder Spec,
// delegating to internal/presco.
//
// Wrap-vs-native: native — a fixed structural gate + a 32-bit field read in a
// 128-bit block; stdlib only. The offline LF-credential decoder for Presco,
// complementing em4100_decode / fdxb_decode / ioprox_decode / jablotron_decode
// / viking_decode / noralsy_decode and the PACS/Wiegand decoder. Offline read,
// no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/presco"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(prescoDecodeSpec)
}

var prescoDecodeSpec = Spec{
	Name: "presco_decode",
	Description: "Decode a **Presco** 125 kHz LF access-control credential from its decoded 128-bit (16-byte) " +
		"data block. Presco is the credential format used by Presco readers (gate / garage / building access). " +
		"This is the offline complement to the project's other LF-RFID decoders (`em4100_decode`, `fdxb_decode`, " +
		"`ioprox_decode`, `jablotron_decode`, `viking_decode`, `noralsy_decode`) and the PACS / Wiegand decoder " +
		"— continuing the LF reader-cloning recon set.\n\n" +
		"Recovers the **32-bit full code** and the Proxmark-style **site code** / **user code** derived from it. " +
		"Input is the *decoded* 128-bit block — the bytes a demodulator such as Proxmark3's `lf presco demod` " +
		"emits (MSB-first). The on-air ASK demodulation is the reader's concern and out of scope; this decodes " +
		"the data block, so the output is deterministic.\n\n" +
		"Layout: a 32-bit 0x10D00000 preamble, two zero words, then the 32-bit full code (bits 96-127). Site " +
		"code = (full >> 24) & 0xFF, user code = full & 0xFFFF.\n\n" +
		"No confidently-wrong output: the layout is taken from the Proxmark3 client `cmdlfpresco.c` — both its " +
		"encoder (`getPrescoBits`) and decoder (`detectPresco`), which are inverse and so internally cross-check. " +
		"Presco is a **single-reference** format here (the Flipper Zero mainline firmware does not implement it) " +
		"and carries **no checksum**, so integrity rests on the 96-bit structural gate (preamble 0x10D00000 + " +
		"two zero words, a ~1-in-2^96 marker): a block that fails the gate is **rejected** as not-a-Presco-frame " +
		"rather than mis-decoded. The 32-bit full code is the unambiguous primary value (literally the final word " +
		"after the gate); the site / user codes are surfaced as the Proxmark derivation of it. No network, no " +
		"device, transmits nothing, so it is Low risk. The input is the 16-byte Presco block. ':' / '-' / '_' / " +
		"whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (LF access-control reader-cloning; Presco complements the HID / " +
		"Indala / AWID / ioProx / Jablotron / Viking / Noralsy coverage). Wrap-vs-native: native — a structural " +
		"gate + a 32-bit field read, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The decoded 128-bit (16-byte) Presco block (from a Proxmark LF read), MSB-first, as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   prescoDecodeHandler,
}

func prescoDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("presco_decode: 'hex' is required")
	}
	res, err := presco.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("presco_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
