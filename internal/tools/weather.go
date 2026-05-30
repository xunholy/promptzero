// weather.go — host-side 433 MHz weather-station decoder Spec,
// delegating to the internal/weather package for the per-family
// layout + checksum maths proper.
//
// Wrap-vs-native judgement: native. Like subghz_pocsag_decode and
// subghz_tpms_decode, the reusable part is a public deterministic
// transform — rtl_433's long-stable LaCrosse/Acurite device layouts
// and their exact checksum algorithms. Operators bring a
// pre-demodulated 40-bit frame and decode offline; no SDR or Flipper
// attached at decode time. Companion to loader_weather_station (which
// runs the live Flipper-side FAP) — this Spec covers the offline
// analyst flow and, unlike the FAP, validates the checksum before
// reporting any reading.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/weather"
)

func init() { //nolint:gochecknoinits
	Register(weatherDecodeSpec)
}

var weatherDecodeSpec = Spec{
	Name: "subghz_weather_decode",
	Description: "Decode a 433 MHz weather-station sensor frame (the LaCrosse / Acurite families the " +
		"Flipper \"Weather Station\" FAP and rtl_433 cover) into the interpreted reading — sensor ID, " +
		"temperature (°C and °F), humidity, battery, and (LaCrosse) channel + test-button — for the " +
		"formats whose checksum validates. Input is a pre-demodulated 40-bit (5-byte) frame, exactly " +
		"like subghz_pocsag_decode / subghz_tpms_decode; bring it from rtl_433, a Flipper FSK/OOK " +
		"Sub-GHz capture pre-extracted to bits, or Universal Radio Hacker. Two input modes:\n\n" +
		" - `bytes`: the 5 frame bytes as hex (10 hex chars; ':' '-' '_' / whitespace tolerated).\n" +
		" - `bits`: a 40-character '0' / '1' bit-stream, MSB-first, separators tolerated.\n\n" +
		"**The checksum is the principled gate.** The covered families share an identical byte " +
		"envelope ([id][flags+temp_hi][temp_lo][humidity][checksum]) and differ only in temperature " +
		"scaling and checksum algorithm, so a reading is reported ONLY for a format whose checksum " +
		"validates over the frame — the checksum disambiguates which family (and so which scaling) " +
		"produced the bytes, exactly as the CRC-8 disambiguates the Manchester convention in " +
		"subghz_tpms_decode. When no known checksum matches, the raw bytes are surfaced with a note " +
		"rather than a guessed reading (a confidently-wrong temperature is worse than none).\n\n" +
		"Covered formats:\n" +
		" - **Acurite 609TXC** — 12-bit two's-complement temp ×10 °C; 8-bit sum checksum over " +
		"bytes 0-3.\n" +
		" - **LaCrosse TX141TH-Bv2 / TX141-Bv3** — (raw-500)×0.1 °C; lfsr_digest8_reflect(gen 0x31, " +
		"key 0xF4) over bytes 0-3, with channel + test-button flags.\n\n" +
		"Pure offline parser — no Flipper / SDR required at decode time. Companion to " +
		"loader_weather_station (live FAP) and sibling to subghz_tpms_decode / subghz_pocsag_decode " +
		"in the Sub-GHz decode family.\n\n" +
		"Out of scope (deliberately): FSK/OOK and PWM/Manchester demodulation (bring a pre-demodulated " +
		"frame); the variable-length Acurite 5n1 and Manchester Oregon Scientific v2.1/v3 families " +
		"(separate envelopes — the two fixed-40-bit families here are the common Flipper case).\n\n" +
		"Source: docs/catalog/gap-analysis.md §3 rank 5 (subghz_weather_decode, pairs with the TPMS " +
		"decode path). Wrap-vs-native: native — the layouts/checksums are a public deterministic " +
		"transform; no hardware needed at decode time.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"bytes":{"type":"string","description":"The 5 frame bytes as hex (10 hex chars). ':' '-' '_' / whitespace separators tolerated. Mutually exclusive with 'bits'."},
			"bits":{"type":"string","description":"A 40-character '0'/'1' bit-stream, MSB-first, from an FSK/OOK demodulator. Separators tolerated. Mutually exclusive with 'bytes'."}
		},
		"oneOf":[
			{"required":["bytes"]},
			{"required":["bits"]}
		]
	}`),
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   weatherDecodeHandler,
}

func weatherDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	bytesRaw := strings.TrimSpace(str(p, "bytes"))
	bitsRaw := strings.TrimSpace(str(p, "bits"))
	if bytesRaw == "" && bitsRaw == "" {
		return "", fmt.Errorf("subghz_weather_decode: one of 'bytes' or 'bits' is required")
	}
	if bytesRaw != "" && bitsRaw != "" {
		return "", fmt.Errorf("subghz_weather_decode: provide 'bytes' OR 'bits', not both")
	}
	var (
		res *weather.Result
		err error
	)
	if bytesRaw != "" {
		res, err = weather.DecodeHex(bytesRaw)
	} else {
		res, err = weather.DecodeBits(bitsRaw)
	}
	if err != nil {
		return "", fmt.Errorf("subghz_weather_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
