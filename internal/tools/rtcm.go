// rtcm.go — host-side RTCM 3.x differential-GNSS message decode Spec,
// delegating to internal/rtcm.
//
// Wrap-vs-native: native — RTCM3 framing is a fixed public wire format
// (0xD3 preamble + 10-bit length + payload + CRC-24Q) defined in RTCM
// 10403.x; frame parse + bit reader + CRC loop, stdlib only. The third
// protocol of the GNSS triad with gps_nmea_decode + ubx_decode.
// Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/rtcm"
)

func init() { //nolint:gochecknoinits
	Register(rtcmDecodeSpec)
}

var rtcmDecodeSpec = Spec{
	Name: "rtcm_decode",
	Description: "Decode **RTCM 3.x** differential-GNSS messages — the protocol a GNSS base station broadcasts " +
		"(over radio, NTRIP or serial) to feed real-time corrections to RTK rovers. The **third protocol of " +
		"the GNSS triad** alongside `gps_nmea_decode` (the text output) and `ubx_decode` (the u-blox binary " +
		"input): a u-blox / Septentrio / Trimble receiver in a base/rover RTK setup emits RTCM3.\n\n" +
		"**GNSS-integrity angle:** injecting forged RTCM corrections (a false 1005 reference-station position, " +
		"or fabricated observables) is a known way to pull an RTK rover off its true fix. Decoding a stream " +
		"surfaces the reference-station id, the broadcast base ECEF position, and which message types / " +
		"constellations a stream carries — flagging an anomalous or spoofed correction source.\n\n" +
		"Decodes and validates:\n" +
		"- **Transport frame** — the `0xD3` preamble, 10-bit length, and the **CRC-24Q** (poly 0x1864CFB, the " +
		"GNSS Qualcomm CRC) over the whole frame. A stream of back-to-back frames decodes to a list; leading " +
		"non-preamble bytes are skipped so a mid-stream capture still parses. A frame whose CRC fails is not " +
		"emitted (a bad CRC reads as a false preamble sync).\n" +
		"- **Message type** (DF002) with a name for the common types: 1001-1004 / 1009-1012 legacy RTK " +
		"observables, 1005/1006 station ARP, 1007/1008/1033 antenna & receiver descriptors, 1019/1020/" +
		"1042-1046 ephemerides, the 107x-112x MSM families per constellation (GPS / GLONASS / Galileo / SBAS " +
		"/ QZSS / BeiDou), and 1230 GLONASS code-phase biases. The **reference-station id** (DF003) is " +
		"surfaced for the types that carry it.\n" +
		"- **1005 / 1006 Stationary RTK Reference Station ARP** — the base-station antenna reference point as " +
		"ECEF X/Y/Z (metres), the GPS/GLONASS/Galileo service indicators, and (1006) the antenna height. " +
		"This is the message a spoofed-correction attack tampers with, so it is bodied out.\n\n" +
		"Paste the RTCM3 bytes as hex; ':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated. " +
		"Observable / ephemeris / MSM bodies are CRC-validated and type/station-named but their per-satellite " +
		"payload is surfaced as raw hex rather than guessed. No network, no device, transmits nothing, so it " +
		"is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (GPS/GNSS decode — the corrections leg of the triad). " +
		"Wrap-vs-native: native — fixed public wire format + CRC-24Q, stdlib only, no new go.mod dep. " +
		"Anchored to the pyrtcm reference library: a real 1005 frame (and a 1006 round-tripped through " +
		"pyrtcm) reproduce its decoded station-id / ECEF / antenna-height fields exactly.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"One or more RTCM3 frames as hex (0xD3 preamble + length + payload + CRC-24Q). ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   rtcmDecodeHandler,
}

func rtcmDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "hex"))
	if in == "" {
		return "", fmt.Errorf("rtcm_decode: 'hex' is required")
	}
	res, err := rtcm.Decode(in)
	if err != nil {
		return "", fmt.Errorf("rtcm_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
