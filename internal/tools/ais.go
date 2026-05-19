// ais.go — host-side AIS NMEA marine vessel dissector Spec,
// delegating to the internal/ais package for the walker
// proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ais"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(aisNMEADecodeSpec)
}

var aisNMEADecodeSpec = Spec{
	Name: "ais_nmea_decode",
	Description: "Decode an AIS (Automatic Identification System) NMEA 0183 sentence — the " +
		"maritime counterpart of ADS-B, transmitted on 161.975 / 162.025 MHz from every " +
		"commercial vessel >300 GT under SOLAS Chapter V. Per ITU-R M.1371-5 + IEC 61162-1. " +
		"Decodes:\n\n" +
		"- **NMEA envelope**: !AIVDM / !AIVDO talker IDs, fragment count + index + sequence " +
		"ID + AIS channel (A/B), payload, padding bits, and the XOR checksum. Multi-" +
		"fragment messages (Type 5 is always 2 fragments) are reassembled when newline-" +
		"separated sentences are passed in one call.\n" +
		"- **6-bit ASCII payload unpack**: canonical AIS bit-soup decode (char - 48; if > " +
		"40 subtract another 8) walked 6 bits at a time with the trailing padding bits " +
		"stripped.\n" +
		"- **Type 1 / 2 / 3 Position Report Class A**: MMSI, Navigation Status (16-state " +
		"table — Under way using engine, At anchor, Not under command, Restricted " +
		"manoeuvrability, Constrained by draught, Moored, Aground, Engaged in fishing, " +
		"Under way sailing, etc.), Rate of Turn, Speed Over Ground, Position Accuracy, " +
		"Longitude / Latitude (signed 28-/27-bit at 1/10000 minute resolution), Course " +
		"Over Ground, True Heading, Timestamp, Manoeuvre Indicator, RAIM flag.\n" +
		"- **Type 4 Base Station Report**: shore-side AIS station UTC year / month / day / " +
		"hour / minute / second + position + EPFD type.\n" +
		"- **Type 5 Static and Voyage Related Data**: assembled from 2 fragments. AIS " +
		"version, IMO number, callsign, vessel name (20-char 6-bit ASCII), ship type " +
		"(full grouped table: WIG, Fishing, Sailing, High-speed craft, Pilot, SAR, Tug, " +
		"Pleasure craft, Passenger, Cargo, Tanker, etc.), dimensions to bow / stern / " +
		"port / starboard, EPFD type, ETA (month / day / hour / minute), draught, " +
		"destination, DTE flag.\n" +
		"- **Type 18 Standard Class B Position Report**: smaller-vessel position broadcast " +
		"with MMSI + Speed + Position + Course + Heading + Timestamp + CS / Display / " +
		"DSC / Band / Msg22 / Assigned / RAIM flags.\n" +
		"- **Type 24 Static Data Class B**: Part A (vessel name) and Part B (ship type, " +
		"vendor ID, callsign, dimensions for regular vessels; mothership MMSI for " +
		"auxiliary craft with MMSI prefix 98).\n\n" +
		"Pure offline parser — operators paste an AIS sentence captured by rtl_ais / " +
		"AIS-catcher / AISHub feed / dAISy / similar receiver and inspect every field " +
		"without re-connecting to the receiver. Complements adsb_mode_s_decode (aerospace " +
		"1090 MHz) by extending the OSINT-decode coverage to the maritime VHF AIS bands.\n\n" +
		"Out of scope (deferred to future iterations): Type 6/8 binary application " +
		"payloads (DAC/FI specific), Type 9 SAR aircraft, Type 11 UTC/Date response, Type " +
		"14 safety broadcast, Type 21 aid-to-navigation, Type 22 channel management, Type " +
		"25/26 single/multi-slot binary, Type 27 long-range. Live demodulation from raw " +
		"I/Q samples (sentences must arrive pre-decoded from an upstream demodulator).\n\n" +
		"Source: docs/catalog/gap-analysis.md (maritime decode space — companion to " +
		"adsb_mode_s_decode for the SDR OSINT stack). Wrap-vs-native: native — ITU-R " +
		"M.1371-5 and NMEA 0183 are fully public, payload is 6-bit ASCII bit-soup, no " +
		"cryptography.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"sentence":{"type":"string","description":"AIS NMEA sentence. Single-fragment messages are one !AIVDM/!AIVDO line; multi-fragment messages (Type 5) are newline-separated. Format: '!AIVDM,<count>,<index>,<seqID>,<channel>,<payload>,<padding>*<checksum>'."}
		},
		"required":["sentence"]
	}`),
	Required:  []string{"sentence"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   aisNMEADecodeHandler,
}

func aisNMEADecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "sentence")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ais_nmea_decode: 'sentence' is required")
	}
	res, err := ais.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ais_nmea_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
