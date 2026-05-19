// pacs.go — host-side HID Prox PACS payload decoder Spec.
// Wraps the internal/pacs walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pacs"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(rfidPACSDecodeSpec)
}

var rfidPACSDecodeSpec = Spec{
	Name: "rfid_pacs_decode",
	Description: "Decode a Physical Access Control System (PACS) credential payload — " +
		"the upper-layer encoding that sits on top of the Wiegand bit-stream produced " +
		"by an HID Prox / iCLASS / EM-style reader. PACS payloads are what every " +
		"corporate badge system uses: HID H10301 (the canonical 26-bit, ubiquitous in " +
		"office buildings worldwide), Corporate 1000 (Fortune-500 deployments), and " +
		"the wider-FC variants for organisations that have grown past the 8-bit " +
		"facility-code limit. Natural sibling to `wiegand_decode` (which extracts the " +
		"raw bit-stream from the data-0 / data-1 lines) and `em4100_decode` (which " +
		"decodes the LF baseband). Decodes:\n\n" +
		"- **Input** — accepts either a bit string (`'0'`/`'1'` only) of one of the " +
		"recognised widths, OR a hex string + explicit `bit_length`. Hex is " +
		"left-aligned into a bit buffer of exactly the declared width, MSB first; " +
		"unused trailing bits in the last byte are discarded.\n" +
		"- **HID H10301 26-bit** (canonical) — `P + 8 FC + 16 CN + P`. Bit 0 is even " +
		"parity over bits 1-12; bit 25 is odd parity over bits 13-24.\n" +
		"- **HID H10306 34-bit** (extended FC) — `P + 16 FC + 16 CN + P`. Bit 0 is " +
		"even parity over bits 1-16; bit 33 is odd parity over bits 17-32.\n" +
		"- **HID H10304 37-bit** (wide CN) — `P + 16 FC + 19 CN + P`. Bit 0 is even " +
		"parity over bits 1-18; bit 36 is odd parity over bits 18-35.\n" +
		"- **HID H10302 37-bit** (no facility code) — `P + 35 CN + P`. Same parity " +
		"layout as H10304 but the entire 35-bit middle is one big card number.\n" +
		"- **HID Corporate 1000 35-bit** (proprietary) — `P + P + 12 FC + 20 CN + P`. " +
		"Two leading parity bits + one trailing parity bit, with a complex even/odd " +
		"computation across the data bits.\n" +
		"- **HID Corporate 1000 48-bit** (extended Corporate 1000) — `P + P + 22 FC + " +
		"23 CN + P`.\n" +
		"- **Multi-format dispatch** — when the input length is unambiguous (26, 34, " +
		"35, 48 bits), one candidate is returned. When the length matches multiple " +
		"formats (37-bit could be H10304 OR H10302), both candidates are returned and " +
		"the caller picks by parity validity or by facility-code sanity (a Corporate " +
		"1000 FC of `999999` is suspicious; a H10301 FC of `5` is normal).\n" +
		"- **Parity computation and validation** — each candidate's parity bits are " +
		"computed and compared against the wire values. The candidate is NOT suppressed " +
		"on parity failure — the FC/CN bit-pattern is still useful for debugging — " +
		"but `parity_valid` is flagged false with a per-bit explanation.\n\n" +
		"Pure offline parser — operators paste a bit string from `wiegand_decode`'s " +
		"output, a Proxmark3 `lf hid demod` line, a Flipper Zero `LF RFID` saved-card " +
		"hex dump (with bit count), or any reader-side capture and inspect every " +
		"documented field. Pairs with `wiegand_decode` for the complete read-loop " +
		"(reader Data-0/Data-1 lines → bit-stream → PACS payload → cardholder).\n\n" +
		"Out of scope (deferred): the reader-layer Wiegand bit-stream extraction " +
		"(already in `wiegand_decode`); iCLASS Standard or Elite 3DES key " +
		"diversification and MAC validation (a future Spec); DESFire AID / EV1 " +
		"application records (already in `desfire_decode`); LF baseband Manchester / " +
		"biphase modulation (already in `em4100_decode`); cardholder-database lookup " +
		"(operator's job — the PACS database is external).\n\n" +
		"Source: docs/catalog/gap-analysis.md top-30 #19. Wrap-vs-native: native — " +
		"the HID format catalogue is fully public via HID OEM spec sheets, the " +
		"Proxmark3 Iceman codebase, and decades of community reverse-engineering. " +
		"Each format is a small fixed-width bit-field layout with one or more " +
		"parity bits — pure bit-twiddling, no crypto, no state.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"bits":{"type":"string","description":"Bit string ('0'/'1' only) of the PACS payload. Mutually exclusive with hex+bit_length."},
			"hex":{"type":"string","description":"Hex bytes containing the PACS payload, left-aligned. Use together with bit_length to disambiguate trailing pad bits."},
			"bit_length":{"type":"integer","description":"Explicit total bit count when using hex input (e.g. 26 for H10301). Required when 'hex' is set."}
		}
	}`),
	Required:  nil,
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   rfidPACSDecodeHandler,
}

func rfidPACSDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	bits := strings.TrimSpace(str(p, "bits"))
	hexStr := strings.TrimSpace(str(p, "hex"))
	bitLen := intOr(p, "bit_length", 0)

	var res *pacs.Result
	var err error
	switch {
	case bits != "":
		res, err = pacs.DecodeBits(bits)
	case hexStr != "":
		if bitLen <= 0 {
			return "", fmt.Errorf("rfid_pacs_decode: 'bit_length' is required when " +
				"using 'hex' input")
		}
		res, err = pacs.DecodeHex(hexStr, bitLen)
	default:
		return "", fmt.Errorf("rfid_pacs_decode: provide 'bits' or 'hex'+'bit_length'")
	}
	if err != nil {
		return "", fmt.Errorf("rfid_pacs_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
