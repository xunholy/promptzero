// zwave.go — host-side Z-Wave MAC-layer frame decoder Spec.
// Wraps the internal/zwave walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/zwave"
)

func init() { //nolint:gochecknoinits
	Register(zwaveDecodeSpec)
}

var zwaveDecodeSpec = Spec{
	Name: "zwave_decode",
	Description: "Decode a classic Z-Wave MAC-layer frame per Sigma Designs / Silicon " +
		"Labs SDS-12852 (Z-Wave Public API). Z-Wave is the dominant sub-GHz home-" +
		"automation mesh protocol — used by Yale / Schlage / Kwikset Z-Wave door " +
		"locks, Ring Z-Wave alarm, Aeotec / Fibaro sensors, GE Z-Wave dimmers, " +
		"the SmartThings hub, and roughly every 'smart home' controller that " +
		"isn't pure Wi-Fi / Zigbee / Matter. Runs at 868.42 MHz (EU) / 908.42 MHz " +
		"(US) / 919.82 MHz (AU) on ITU-T G.9959 FSK PHY. Interesting to a Flipper " +
		"Zero / SDR pentester because Yale + Kwikset Z-Wave locks respond to " +
		"authenticated commands (replayed commands attack the SECURITY S0/S2 key-" +
		"exchange stacks); mesh enumeration is trivial (HomeID + per-node NodeIDs " +
		"surface on every frame); battery-drain DoS targets battery-powered " +
		"sensors via flooded WAKE_UP frames; and DEF CON Wireless Village + Black " +
		"Hat IoT-track Z-Wave research has published wire captures this decoder " +
		"ingests. Decodes:\n\n" +
		"- **MAC-layer frame header** (SDS-12852 §3, 9 fixed bytes before the " +
		"payload): bytes 0-3 HomeID (uint32 BE; per-network identifier assigned " +
		"at inclusion time) + byte 4 SourceNodeID + bytes 5-6 Frame Control + " +
		"byte 7 Length (total frame bytes INCLUDING the trailing checksum) + " +
		"byte 8 DestinationNodeID (0xFF = broadcast).\n" +
		"- **Frame Control field** (2 bytes, big-endian): byte 5 bits 0-3 " +
		"Header Type / bit 4 Routed (multi-hop relayed) / bit 5 Ack Requested / " +
		"bit 6 Low Power (FLiRS-class devices) / bit 7 Speed Modified (non-" +
		"default PHY data rate); byte 6 bit 0 Beam Control (frame is a beam-" +
		"mode poll for sleeping devices) / bits 4-7 Sequence Number (4-bit per-" +
		"pair monotonic counter pairing Ack frames to their originating frames).\n" +
		"- **4-entry Header Type name table**: 1 Singlecast / 2 Multicast / 3 " +
		"Ack / 4 Explore.\n" +
		"- **Payload + Command Class header** (variable): byte 0 Command Class " +
		"(per Z-Wave Command Class Reference) + byte 1 Command (per-Command-" +
		"Class operation code) + bytes 2+ per-Command parameters.\n" +
		"- **30+ entry Command Class name table** (selected high-runners from " +
		"Silicon Labs INS13954): 0x20 BASIC / 0x25 SWITCH_BINARY / 0x26 " +
		"SWITCH_MULTILEVEL / 0x27 SWITCH_ALL / 0x28 SWITCH_TOGGLE_BINARY / " +
		"0x2B SCENE_ACTIVATION / 0x30 SENSOR_BINARY / 0x31 SENSOR_MULTILEVEL / " +
		"0x32 METER / 0x40 THERMOSTAT_MODE / 0x42 " +
		"THERMOSTAT_OPERATING_STATE / 0x43 THERMOSTAT_SETPOINT / 0x44 " +
		"THERMOSTAT_FAN_MODE / 0x60 MULTI_CHANNEL / 0x62 DOOR_LOCK (the canonical " +
		"Yale Z-Wave target) / 0x63 USER_CODE / 0x70 CONFIGURATION / 0x71 ALARM " +
		"(also NOTIFICATION) / 0x72 MANUFACTURER_SPECIFIC / 0x73 POWERLEVEL / " +
		"0x75 PROTECTION / 0x77 NODE_NAMING / 0x80 BATTERY / 0x81 CLOCK / 0x82 " +
		"HAIL / 0x84 WAKE_UP (the battery-drain DoS attack target) / 0x85 " +
		"ASSOCIATION / 0x86 VERSION / 0x87 INDICATOR / 0x8B TIME_PARAMETERS / " +
		"0x91 MANUFACTURER_PROPRIETARY / 0x98 SECURITY (S0; classic Z-Wave " +
		"AES-128 wrapper) / 0x9F SECURITY_2 (S2; Z-Wave Plus AES-CMAC + ECDH " +
		"wrapper).\n" +
		"- **Trailing checksum** — 1-byte XOR of every byte from HomeID through " +
		"the last payload byte, init 0xFF. Surfaced as hex but not re-computed.\n\n" +
		"Pure offline parser — operators paste Z-Wave bytes (starting at the " +
		"first HomeID byte, i.e. after the PHY preamble + SOF strip; Flipper " +
		"Zero / HackRF / RTL-SDR + zwave-libs is the typical capture chain) and " +
		"get the documented MAC header + Command Class breakdown.\n\n" +
		"Out of scope (deferred): PHY framing (Z-Wave runs on ITU-T G.9959 FSK " +
		"PHY at 868 / 908 / 920 MHz with Manchester / NRZ encoding plus a " +
		"4-byte preamble + 1-byte SOF; feed this decoder the post-PHY MAC frame " +
		"bytes); Z-Wave Long Range LR (the 700/800-series LR variant re-uses " +
		"much of the classic wire format but extends NodeIDs to 16 bits and uses " +
		"a different MAC layout); SECURITY (S0) / SECURITY_2 (S2) crypto (the " +
		"0x98 / 0x9F Command Classes are container Command Classes that wrap an " +
		"inner AES-CMAC-protected payload — surfaced as Command Class identifier " +
		"+ raw payload bytes; integrity tag verification + inner-command " +
		"decryption is higher-level work); routing-layer reasoning (multi-hop " +
		"Z-Wave frames carry repeater tables and routing source headers; " +
		"surfaces the Routed bit + Length but does not walk the per-hop fields); " +
		"multicast frame body (the Multicast Type-2 frame carries a NodeMask + " +
		"per-node grouping surfaced as raw payload; per-bit walker is future " +
		"work); mesh-state reasoning (inclusion / exclusion / wake-up FLiRS " +
		"state-machine, per-NodeID sleep tracking — higher-level analysis driven " +
		"by the controller log).\n\n" +
		"Source: docs/catalog/gap-analysis.md (sub-GHz IoT pentest dissector — " +
		"pairs with Flipper Zero RF capture; targets Yale / Kwikset Z-Wave lock " +
		"attacks, SmartThings hub enumeration, and DEF CON Wireless Village + " +
		"Black Hat IoT-track Z-Wave research). Wrap-vs-native: native — the " +
		"Sigma Designs SDS-12852 Z-Wave Public API document is publicly " +
		"available; the MAC-layer frame format is fixed and the Command Class " +
		"registry (Silicon Labs INS13954) maps the 256-entry Command Class space " +
		"against documented application-layer behaviours; no crypto at the parse " +
		"layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Z-Wave MAC-layer frame bytes starting at the first HomeID byte (after the PHY preamble + SOF strip). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   zwaveDecodeHandler,
}

func zwaveDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("zwave_decode: 'hex' is required")
	}
	res, err := zwave.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("zwave_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
