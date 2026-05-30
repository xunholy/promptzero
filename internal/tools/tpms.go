// tpms.go — host-side TPMS Sub-GHz bit-stream decoder Spec,
// delegating to the internal/tpms package for the Manchester
// line-decode + frame analysis proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/tpms"
)

func init() { //nolint:gochecknoinits
	Register(tpmsDecodeSpec)
}

var tpmsDecodeSpec = Spec{
	Name: "subghz_tpms_decode",
	Description: "Decode a TPMS (Tire Pressure Monitoring System) Sub-GHz bit-stream into the " +
		"format-independent fields a pentester can trust: the Manchester line-decoded payload " +
		"bytes, the 32-bit sensor ID, and CRC-8 validity. TPMS sensors beacon on 315 MHz (North " +
		"America) and 433.92 MHz (Europe/Asia) and are a prime Flipper Sub-GHz target — each sensor " +
		"transmits a unique ID with no authentication, so a capture lets you fingerprint and track a " +
		"specific vehicle. Input is a string of '0'/'1' characters from an FSK/OOK demodulator " +
		"(rtl_433, a Flipper Sub-GHz capture pre-extracted to bits, or Universal Radio Hacker), " +
		"exactly like subghz_pocsag_decode. Decodes:\n\n" +
		"- **Manchester line decoding** under both conventions (IEEE 802.3: data 0 = \"10\", " +
		"data 1 = \"01\"; G.E. Thomas: the inverse) at both bit alignments, auto-selecting the " +
		"alignment that decodes cleanly (a wrong alignment trips illegal \"00\"/\"11\" pairs almost " +
		"immediately). A leading alternating preamble decodes to a clean run and is tolerated.\n" +
		"- **Convention disambiguation via CRC-8**: a valid Manchester stream decodes cleanly under " +
		"BOTH conventions (one yields the data, the other its bitwise complement), so the convention " +
		"is resolved by which decode's trailing byte validates as a CRC-8 (probing the 0x07 / 0x2F / " +
		"0x13 polynomials TPMS sensors commonly use). When no CRC matches, the result is flagged as " +
		"convention-ambiguous.\n" +
		"- **Sensor ID**: the first four payload bytes, which across virtually every TPMS family " +
		"(Schrader, Toyota, Ford, Renault, Citroën, GM, Hyundai, …) is the unique per-sensor " +
		"identifier — the field-independent signal used to track a vehicle — surfaced as hex and " +
		"decimal.\n" +
		"- **Decoded payload** as hex, with the chosen line coding, bit alignment, and decoded bit " +
		"count.\n\n" +
		"Pure offline parser — no Flipper / SDR required at decode time. Companion to " +
		"subghz_pocsag_decode for the Sub-GHz bit-stream decode family.\n\n" +
		"Out of scope (deliberately): manufacturer-specific pressure / temperature / status field " +
		"interpretation — the byte offsets and scaling differ per family and cannot be verified " +
		"without per-model captures, so the raw decoded bytes are surfaced for the operator to apply " +
		"the relevant rtl_433 model layout (encoding an unverified scaling would risk a " +
		"confidently-wrong reading, worse than none for a security tool); FSK/OOK demodulation (bring " +
		"a pre-demodulated bit-stream); and the differential-Manchester / biphase-mark variants used " +
		"by a minority of sensors.\n\n" +
		"Source: docs/catalog/gap-analysis.md §3 rank 6 (TPMS, pairs with the weather-station " +
		"decode path). Wrap-vs-native: native — Manchester decoding is a public deterministic " +
		"transform; no hardware needed at decode time.\n\n" +
		"Accepts ':' '-' '_' / whitespace separators in the bit-stream.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"bits":{"type":"string","description":"Bit-stream of '0'/'1' characters from an FSK/OOK demodulator (rtl_433, a Flipper Sub-GHz capture pre-extracted to bits, or URH). Manchester-decoded under both conventions/alignments; CRC-8 disambiguates the convention. ':' '-' '_' / whitespace separators tolerated."}
		},
		"required":["bits"]
	}`),
	Required:  []string{"bits"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   tpmsDecodeHandler,
}

func tpmsDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "bits")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("subghz_tpms_decode: 'bits' is required")
	}
	res, err := tpms.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("subghz_tpms_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
