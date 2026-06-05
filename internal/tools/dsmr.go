// dsmr.go — host-side DSMR / P1 smart-meter telegram decoder Spec,
// delegating to the internal/dsmr package.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/dsmr"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dsmrP1DecodeSpec)
}

var dsmrP1DecodeSpec = Spec{
	Name: "dsmr_p1_decode",
	Description: "Decode a DSMR / P1 smart-meter telegram — the ASCII data stream a Dutch / " +
		"Belgian (and increasingly EU) smart electricity / gas meter pushes out of its P1 " +
		"customer port every second. Reading the P1 stream is the energy-side IoT " +
		"data-exfiltration / monitoring surface: per-tariff energy import & export, instantaneous " +
		"and per-phase power, per-phase voltage / current, gas volume, power-outage counters and " +
		"the meter's equipment IDs. Per the DSMR 5.0 P1 companion standard / IEC 62056-21. " +
		"Decodes:\n\n" +
		"- The **meter identifier** line (`/XXX5…`) and the **CRC-16** (CRC-16/ARC over `/`…`!` " +
		"inclusive), recomputed and reported valid / invalid — so a tampered or truncated " +
		"telegram is caught. CRLF line endings are normalised first, so a paste that lost the " +
		"`\\r` still validates.\n" +
		"- Every **OBIS object line** (`C-D:E.F.G(value*unit)`): the code, its documented meaning " +
		"(energy delivered / returned per tariff, instantaneous +P/-P power, per-phase " +
		"voltage / current / power, voltage-sag & swell counters, power-failure counts, the gas " +
		"M-Bus channel reading, equipment IDs, timestamp, active tariff, …) and the parsed value " +
		"+ unit. Unknown OBIS codes are surfaced with their raw value rather than guessed.\n\n" +
		"Paste the whole telegram (from the `/` identifier to the `!CRC`). Verified byte-for-byte " +
		"against the dsmr_parser reference telegram (CRC 0x6796).\n\n" +
		"Out of scope (deferred): full expansion of the power-failure event log (1-0:99.97.0) and " +
		"the timestamp DST flag (surfaced as raw values); decoding the hex-encoded equipment IDs " +
		"(surfaced verbatim).\n\n" +
		"Source: docs/catalog/gap-analysis.md (smart-metering / energy IoT decode space). " +
		"Wrap-vs-native: native — a P1 telegram is fully-public ASCII decoded by string parsing " +
		"plus one standard CRC-16 and a documented OBIS table; the field interpretation reference " +
		"parsers leave implicit is implemented directly. Pairs with mbus_decode for the wired " +
		"M-Bus meter side.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"telegram":{"type":"string","description":"The full DSMR P1 telegram, from the '/' identifier line through the OBIS lines to the '!CRC'. Any line-ending form is tolerated."}
		},
		"required":["telegram"]
	}`),
	Required:  []string{"telegram"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dsmrP1DecodeHandler,
}

func dsmrP1DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "telegram")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("dsmr_p1_decode: 'telegram' is required")
	}
	res, err := dsmr.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("dsmr_p1_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
