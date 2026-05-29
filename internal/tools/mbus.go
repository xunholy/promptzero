// mbus.go — host-side M-Bus (Meter-Bus) telegram dissector Spec,
// delegating to the internal/mbus package for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/mbus"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(mbusDecodeSpec)
}

var mbusDecodeSpec = Spec{
	Name: "mbus_decode",
	Description: "Decode an M-Bus (Meter-Bus, EN 13757-2 link layer + EN 13757-3 " +
		"application layer) telegram — the European smart-metering protocol for " +
		"electricity, gas, water, heat, and warm-water meters. The wired M-Bus link / " +
		"application layers are shared with Wireless M-Bus (wM-Bus, 868 MHz), which a " +
		"Flipper Sub-GHz capture can lift off the air — paste the demodulated bytes here " +
		"to read the meter identity and command without a dedicated M-Bus master. " +
		"Decodes:\n\n" +
		"- **Link-layer frame classification**: single-character ACK (0xE5), short frame " +
		"(0x10 … 0x16), control frame (0x68 L L 0x68 … 0x16 with L==3), and long frame " +
		"(0x68 L L 0x68 … 0x16), with L-field consistency (the two length bytes must " +
		"match), total-length validation against the buffer, checksum verification " +
		"(arithmetic sum of C..end-of-user-data mod 256), and the 0x16 stop byte.\n" +
		"- **C-field (Control)**: function naming (SND_NKE initialise, SND_UD send-data, " +
		"REQ_UD1 / REQ_UD2 request class-1 / class-2 data, RSP_UD response) with the " +
		"FCB/FCV (master) and ACD/DFC (slave) variants, plus the master↔slave direction " +
		"bit.\n" +
		"- **A-field (Address)**: value + classification (unconfigured factory default / " +
		"primary address 1–250 / secondary-addressing 253 / broadcast-slaves-reply 254 / " +
		"broadcast-no-reply 255 / reserved).\n" +
		"- **CI-field (Control Information)**: application-selector naming (Application " +
		"reset, Data send, Selection of slaves, Set clock, variable-data responses with " +
		"long / short / no header, baud-rate set, etc.).\n" +
		"- **Variable Data Structure fixed header** (CI 0x72 long 12-byte / CI 0x7A short " +
		"4-byte): BCD identification (serial) number, FLAG-encoded 3-letter manufacturer " +
		"code, version, medium / device type with a name table (Electricity / Gas / " +
		"Water / Heat / Warm-water / Breaker / Valve / …), access number, status byte, " +
		"and signature — i.e. the meter's identity, which an attacker enumerates before " +
		"a spoof or replay.\n\n" +
		"Pure offline parser — operators paste a hex telegram from an M-Bus master log, " +
		"a serial capture, or a demodulated wM-Bus frame and inspect every link- and " +
		"application-layer field. Companion to knxnetip_decode, bacnet_ip_decode, and " +
		"modbus_decode for the full OT / building-automation + metering decode space.\n\n" +
		"Out of scope (deferred): DIF/VIF data-record decoding (the metering values " +
		"themselves — the raw data-record bytes are surfaced), wM-Bus radio framing " +
		"(mode S/T/C, 3-of-6 / Manchester line coding, block CRC — feed already-" +
		"demodulated application bytes), and encrypted application data (Mode 5 AES-CBC / " +
		"Mode 7/9/13 — the status/config field is surfaced, ciphertext not decrypted).\n\n" +
		"Source: docs/catalog/gap-analysis.md (OT / smart-metering decode space — M-Bus " +
		"is the dominant European meter bus and the wired sibling of Flipper-capturable " +
		"wM-Bus). Wrap-vs-native: native — EN 13757 is public and every framing is a " +
		"fixed byte-counted structure.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded M-Bus telegram: single-character ACK (E5), short frame (10 C A chk 16), control/long frame (68 L L 68 C A CI [data] chk 16). ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   mbusDecodeHandler,
}

func mbusDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("mbus_decode: 'hex' is required")
	}
	res, err := mbus.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("mbus_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
