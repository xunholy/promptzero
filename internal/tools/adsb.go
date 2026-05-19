// adsb.go — host-side Mode S / ADS-B 1090 MHz frame dissector
// Spec, delegating to the internal/adsb package for the walker
// proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/adsb"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(adsbModeSDecodeSpec)
}

var adsbModeSDecodeSpec = Spec{
	Name: "adsb_mode_s_decode",
	Description: "Decode a Mode S downlink frame captured at 1090 MHz — both short-form (56-bit) " +
		"surveillance replies and long-form (112-bit) extended squitter / ADS-B frames. Per ICAO " +
		"Annex 10 Vol IV + RTCA DO-260 + EUROCAE ED-102. Decodes:\n\n" +
		"- **Downlink Format (DF) detection** for all 32 slots: DF0/4/5/11 (short surveillance), " +
		"DF16/17/18 (extended squitter), DF19 (military ES), DF20/21 (Comm-B), DF24+ (Comm-D ELM).\n" +
		"- **Frame length validation**: short (7 bytes / 56 bits) for DF0/4/5/11; long (14 bytes " +
		"/ 112 bits) for the rest.\n" +
		"- **ICAO 24-bit aircraft address** extraction from DF11/17/18 (where the AA field is in " +
		"the clear).\n" +
		"- **Mode S CRC-24 validation** with generator polynomial 0xFFF409, init 0, no reflection. " +
		"Surfaces both the captured PI (parity interrogator) field and the computed expected value " +
		"so operators can diff a corrupt frame.\n" +
		"- **DF17 (ADS-B) Type Code dispatch** covering the operationally important sub-types:\n" +
		"  - TC 1-4: Aircraft Identification + 8-character callsign (6-bit AIS alphabet decode) " +
		"+ emitter-category lookup (Light / Small / Large / Heavy / Glider / UAV / Rotorcraft / " +
		"Surface vehicle / etc.).\n" +
		"  - TC 5-8: Surface Position with movement decode (piecewise speed table from DO-260B) " +
		"+ ground track + raw CPR (lat/lon, even/odd flag).\n" +
		"  - TC 9-18 / 20-22: Airborne Position with altitude decode from the 12-bit Q-bit field " +
		"(25-ft resolution; Gillham/Mode-C Q=0 frames flagged invalid) + raw CPR (lat/lon, " +
		"even/odd flag).\n" +
		"  - TC 19: Airborne Velocity (subtypes 1/2 ground speed + track; subtypes 3/4 airspeed " +
		"+ magnetic heading) + vertical rate with source flag (barometric vs GNSS).\n\n" +
		"CPR position resolution (full lat/lon) is deferred — the decoder exposes the raw 17-bit " +
		"CPR latitude/longitude and the odd/even frame flag, but pairing an even + odd frame for " +
		"a global solve (or applying a local reference position) is left to a higher-level Spec " +
		"so the receiver controls when stale references should be used.\n\n" +
		"Pure offline parser — operators paste a hex blob from dump1090 / readsb / any " +
		"1090 MHz SDR feed and inspect the frame fields without re-touching the air. Complements " +
		"the existing subghz_* coverage (UHF surveillance and decoders below 1 GHz) by extending " +
		"the airborne / aerospace decode space.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.\n\n" +
		"Scope: civil-aviation Mode S DFs. Comm-B BDS register decoding (DF20/21 payloads), DF18 " +
		"CF>=2 sub-formats (fine TIS-B / ADS-R), and live demodulation from raw I/Q samples are " +
		"out of scope.\n\n" +
		"Source: docs/catalog/gap-analysis.md (aerospace / airborne decode space — native fit " +
		"as a pure host-side parser).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded Mode S frame: 7 bytes (56 bits, short) for DF0/4/5/11 or 14 bytes (112 bits, long) for DF16/17/18/19/20/21/24+. ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   adsbModeSDecodeHandler,
}

func adsbModeSDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("adsb_mode_s_decode: 'hex' is required")
	}
	res, err := adsb.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("adsb_mode_s_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
