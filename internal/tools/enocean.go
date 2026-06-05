// enocean.go — host-side EnOcean ESP3 / ERP1 packet decoder Spec,
// delegating to the internal/enocean package.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/enocean"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(enoceanDecodeSpec)
}

var enoceanDecodeSpec = Spec{
	Name: "enocean_decode",
	Description: "Decode an EnOcean ESP3 packet and the ERP1 radio telegram it carries — the " +
		"self-powered 868 / 902 / 315 MHz building-automation protocol behind batteryless light " +
		"switches, occupancy / window-contact / temperature sensors and actuators. A USB gateway " +
		"(USB300 / USB400J) or an SDR emits ESP3 frames; decoding them yields the device identity " +
		"(32-bit sender ID), the telegram type, the radio signal strength and an integrity check " +
		"— the reconnaissance a building-automation RF pentest starts from (device enumeration, " +
		"replay-target identification). Per the EnOcean Serial Protocol 3 (ESP3) + ERP1 radio " +
		"spec. Decodes:\n\n" +
		"- **ESP3 framing**: 0x55 sync + 16-bit data length + 8-bit optional length + packet type " +
		"(+ name: RADIO_ERP1, RESPONSE, EVENT, COMMON_COMMAND, …) + a **header CRC-8** and a " +
		"**data CRC-8** (standard poly 0x07), both recomputed and reported valid / invalid.\n" +
		"- **RADIO_ERP1 telegram** (packet type 1): the **RORG** radio-telegram type with its " +
		"name — RPS (0xF6, rocker / PTM switch), 1BS (0xD5, e.g. window/door contact), 4BS " +
		"(0xA5, e.g. temperature / humidity sensor), VLD (0xD2, actuators / metering), MSC, UTE " +
		"(teach-in), secure (0x30/0x31/0x35) — the payload, the **32-bit sender ID** (the device " +
		"address), the status byte (+ repeater count), and the optional data: sub-telegram count, " +
		"destination ID, **RSSI in -dBm** (signal strength), and security level.\n\n" +
		"Paste the ESP3 packet as hex (':' / '-' / '_' / whitespace separators and a '0x' prefix " +
		"tolerated). Verified against a CRC-8-valid RADIO_ERP1 reference frame.\n\n" +
		"Out of scope (deferred): EEP (EnOcean Equipment Profile) payload decode — the meaning of " +
		"the data bytes (which rocker was pressed, contact open/closed, a 4BS sensor's reading) " +
		"depends on the device's FUNC/TYPE profile, which the telegram does NOT carry, so decoding " +
		"it would be a confidently-wrong guess; the raw payload + RORG are surfaced instead. " +
		"Over-the-air ERP1/ERP2 radio framing (a bare SDR capture before ESP3 wrapping) and AES " +
		"secure-telegram decryption are also deferred.\n\n" +
		"Source: docs/catalog/gap-analysis.md (sub-GHz building-automation decode space). " +
		"Wrap-vs-native: native — ESP3 is a fixed public framing decoded by byte-field extraction " +
		"plus one table-driven CRC-8; reimplemented from the spec, not wrapped. Pairs with the " +
		"subghz_* decoders for the wider 868/315 MHz attack surface.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"EnOcean ESP3 packet as hex (starts with the 0x55 sync byte). ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   enoceanDecodeHandler,
}

func enoceanDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("enocean_decode: 'hex' is required")
	}
	res, err := enocean.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("enocean_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
