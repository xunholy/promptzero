// ioprox_decode.go — host-side IO Prox (Kantech XSF) 125 kHz LF access-control
// decoder Spec, delegating to internal/ioprox.
//
// Wrap-vs-native: native — fixed bit extraction at known offsets in a 64-bit
// block + an 8-bit additive checksum; stdlib only. The offline LF-credential
// decoder for Kantech ioProx, complementing em4100_decode / fdxb_decode and the
// PACS/Wiegand decoder. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ioprox"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ioproxDecodeSpec)
}

var ioproxDecodeSpec = Spec{
	Name: "ioprox_decode",
	Description: "Decode an **IO Prox (Kantech XSF)** 125 kHz LF access-control credential from its decoded " +
		"64-bit (8-byte) data block. IO Prox is the credential format used by **Kantech ioProx** readers — " +
		"widely deployed across North American commercial / institutional access control. This is the offline " +
		"complement to the project's other LF-RFID decoders (`em4100_decode`, `fdxb_decode`) and the PACS / " +
		"Wiegand decoder (which cover HID Prox / Indala / AWID but **not** ioProx) — closing a real " +
		"reader-cloning recon gap.\n\n" +
		"Recovers the **facility code**, the **version** byte, the **16-bit card number**, and validates the " +
		"8-bit **checksum**. Input is the *decoded* 64-bit block — the 'Raw' bytes a demodulator such as " +
		"Proxmark3's `lf io demod` or a Flipper Zero LF read emits (MSB-first). The on-air FSK demodulation is " +
		"the reader's concern and out of scope; this decodes the data block, so the output is deterministic.\n\n" +
		"No confidently-wrong output: the bit layout and the checksum algorithm are taken from — and agree " +
		"byte-for-byte between — **two independent reference implementations** (the Proxmark3 client and the " +
		"Flipper Zero firmware). The structural frame (nine zero preamble bits, the 0xF0 marker, the six " +
		"separator bits) is a hard gate — a block whose marker or separators do not match is **rejected** as " +
		"not-an-ioProx-frame rather than mis-decoded; and the checksum is surfaced as `crc_valid` — a block that " +
		"parses structurally but fails the checksum is reported as such, never asserted as a real credential. No " +
		"network, no device, transmits nothing, so it is Low risk. The input is the 8-byte IO Prox block. " +
		"':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (LF access-control reader-cloning; ioProx complements the HID / " +
		"Indala / AWID PACS coverage). Wrap-vs-native: native — fixed bit extraction + an 8-bit checksum, stdlib " +
		"only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The decoded 64-bit (8-byte) IO Prox block (the 'Raw' value from a Proxmark/Flipper LF read), MSB-first, as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ioproxDecodeHandler,
}

func ioproxDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("ioprox_decode: 'hex' is required")
	}
	res, err := ioprox.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("ioprox_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
