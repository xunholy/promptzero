// fdxb_decode.go — host-side ISO 11784/11785 FDX-B animal-transponder
// dissector Spec, delegating to internal/fdxb.
//
// Wrap-vs-native: native — fixed LSB-first bit/byte extraction plus a CRC-16,
// no dependency. The field layout and CRC-16 parameters are taken from the
// Proxmark3 reference (crc16_fdxb / cmdlffdxb.c) and verified byte-for-byte
// against two real decoded tags. Offline read of operator-supplied bytes —
// no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/fdxb"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(fdxbDecodeSpec)
}

var fdxbDecodeSpec = Spec{
	Name: "fdxb_decode",
	Description: "Decode an ISO 11784/11785 **FDX-B** data block — the 134.2 kHz LF transponder format used " +
		"by **animal / pet microchips** (and many asset / biothermo transponders). Recovers the country " +
		"code, the 38-bit national identification number, the application flags, and validates the CRC-16. " +
		"The LF complement to the project's EM4100 / HID-Prox / PACS decoders (the project read/emulated " +
		"FDX-B on hardware but could not decode the data block offline).\n\n" +
		"Field: **hex** — the de-stuffed FDX-B data block (the bytes a demodulator such as Proxmark3's " +
		"`lf fdxb` emits; ':' / '-' / whitespace ignored). At least the 8-byte ID block; >=10 bytes to also " +
		"validate the CRC-16; 13 bytes to also surface the 24-bit extended data block. Decodes the national " +
		"code + country code (both LSB-first), the data-block-status and animal-application flags, and the " +
		"CRC-16 (CCITT 0x1021, computed over the 8-byte ID block).\n\n" +
		"The on-air framing (11-bit preamble + the control bit after every 8 data bits) is the demodulator's " +
		"job and is out of scope — this decodes the data block, so the output is deterministic. The CRC-16 is " +
		"the integrity gate: a frame whose CRC fails is reported as such, never asserted as a real tag; a " +
		"country code in the 900-999 manufacturer/test range is noted rather than mapped to a country. " +
		"Offline, transmits nothing -> Low risk. Wrap-vs-native: native (verified vs the Proxmark3 reference).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"De-stuffed FDX-B data block, hex (>=8 bytes ID; >=10 to validate CRC; 13 for extended). ':' / '-' / whitespace tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   fdxbDecodeHandler,
}

func fdxbDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("fdxb_decode: 'hex' is required")
	}
	res, err := fdxb.DecodeHex(raw)
	if err != nil {
		return "", fmt.Errorf("fdxb_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
