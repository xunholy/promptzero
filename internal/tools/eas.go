// eas.go — host-side EAS / SAME (emergency alert header) decoder Spec,
// delegating to the internal/eas package.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/eas"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(easSAMEDecodeSpec)
}

var easSAMEDecodeSpec = Spec{
	Name: "eas_same_decode",
	Description: "Decode an EAS / SAME (Specific Area Message Encoding) header — the AFSK digital " +
		"burst that prefixes every Emergency Alert System and NOAA Weather Radio alert (the " +
		"`ZCZC…` header at 520.83 baud, on 162.4-162.55 MHz weather radio and broadcast/cable " +
		"EAS). An SDR demodulator (multimon-ng, rtl_fm) recovers the raw header string; this " +
		"interprets its fields — who issued the alert, what kind, for which areas and when — the " +
		"useful part for RF monitoring / broadcast forensics. Per NWS NWSI 10-1712 / FCC 47 CFR " +
		"11.31. The format is `ZCZC-ORG-EEE-PSSCCC-PSSCCC…+TTTT-JJJHHMM-LLLLLLLL-`. Decodes:\n\n" +
		"- **Originator (ORG)**: PEP (National Public Warning System) / CIV (civil authorities) / " +
		"WXR (National Weather Service) / EAS (broadcast or cable participant) / EAN (legacy).\n" +
		"- **Event (EEE)**: the FCC/NWS event-code table — tests (RWT / RMT / NPT), weather " +
		"warnings (TOR tornado, SVR severe thunderstorm, FFW flash flood, HUW hurricane, TSW " +
		"tsunami, …), watches (TOA / SVA / …), statements (SVS / SPS / …) and civil/non-weather " +
		"events (CAE child-abduction / AMBER, CEM civil emergency, EVI evacuate, NUW nuclear, " +
		"…) — with the standard third-letter fallback for unrecognised codes (…W warning, …A " +
		"watch, …E emergency, …S statement, …T test).\n" +
		"- **Location codes (PSSCCC)**: the part-of-county digit, the state FIPS code (resolved " +
		"to the state/territory name) and the county FIPS code.\n" +
		"- **Valid/purge time (TTTT)**: the hhmm alert duration, and the **issue time " +
		"(JJJHHMM)**: ordinal day-of-year + UTC hh:mm.\n" +
		"- The 8-character **originator callsign**.\n\n" +
		"Paste the demodulated header line (leading preamble / surrounding text is tolerated — " +
		"parsing starts at `ZCZC`). Verified against the documented NWS worked example.\n\n" +
		"Out of scope (deferred): county-FIPS → county-name resolution (a ~3200-entry table — " +
		"the state name + raw 5-digit FIPS are surfaced); deriving a calendar date from the " +
		"ordinal day (the header carries no year); and the alert audio / EOM (NNNN) framing, " +
		"which is upstream of the header string.\n\n" +
		"Source: docs/catalog/gap-analysis.md (RF broadcast / SDR decode space). Wrap-vs-native: " +
		"native — a SAME header is a fixed public ASCII structure decoded by deterministic string " +
		"parsing plus three documented lookup tables; the field interpretation multimon-ng leaves " +
		"to the operator is implemented directly. Pairs with subghz_weather_decode / rds_decode " +
		"in the broadcast-RF decode space.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"header":{"type":"string","description":"The demodulated SAME header line, e.g. 'ZCZC-EAS-RWT-012057-012081+0030-2780415-WTSP/TV-'. Leading preamble / surrounding text tolerated."}
		},
		"required":["header"]
	}`),
	Required:  []string{"header"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   easSAMEDecodeHandler,
}

func easSAMEDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "header")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("eas_same_decode: 'header' is required")
	}
	res, err := eas.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("eas_same_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
