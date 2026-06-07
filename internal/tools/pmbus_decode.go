// pmbus_decode.go — host-side PMBus (Power Management Bus) decoder Spec,
// delegating to internal/pmbus.
//
// Wrap-vs-native: native — a 1-byte command code + little-endian data (LINEAR11
// telemetry / STATUS bit-fields); a byte read + an opcode table + a couple of
// bit/float decodes, stdlib only. The power-rail decoder — surfaces the PMBus
// command, the security-relevant voltage-setting writes, and the decoded
// telemetry from a captured I2C/SMBus transaction. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pmbus"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pmbusDecodeSpec)
}

var pmbusDecodeSpec = Spec{
	Name: "pmbus_decode",
	Description: "Decode a **PMBus (Power Management Bus)** transaction — the SMBus/I2C command set that PSUs, " +
		"voltage regulators (VRMs), battery chargers and hot-swap controllers expose to set and read their " +
		"power rails. PMBus is a real, current **hardware-attack surface**: the 2023 **PMFault** research " +
		"showed that writing the PSU's **VOUT_COMMAND / OPERATION** over PMBus can **overvolt** a server's CPU " +
		"rail to induce faults — so a captured PMBus transaction (from an I2C/SMBus sniffer, cf. the project's " +
		"`i2c_scan`) is real recon. A PMBus message identifies the **command** — a voltage-setting OPERATION / " +
		"VOUT_COMMAND / VOUT_MARGIN (the attack-relevant writes, **flagged**), a READ_VIN / READ_IOUT / " +
		"READ_TEMPERATURE telemetry read (with the decoded physical value), a STATUS query (with the decoded " +
		"fault bits), a manufacturer-ID query — the headline for power-rail analysis. It joins the project's " +
		"hardware-bus tooling (`internal/jtag`, `internal/buspirate`, `internal/spiflash`).\n\n" +
		"No confidently-wrong output: the decoded command codes are the PMBus-specification standard set " +
		"(OPERATION, VOUT_COMMAND, the VOUT margins/limits, the READ_* telemetry, the STATUS_* registers, " +
		"PMBUS_REVISION, MFR_ID, …); a code outside the set is reported as **unknown / manufacturer-specific** " +
		"rather than guessed. The **LINEAR11** decode (deterministic two's-complement exponent × mantissa) is " +
		"applied only to the LINEAR11-defined commands (current / power / temperature / input-voltage reads); " +
		"**VOUT** values (ULINEAR16, scaled by the device's VOUT_MODE exponent which is not on the wire) are " +
		"surfaced raw with a note, and STATUS bit-fields are decoded from the spec. No network, no device, " +
		"transmits nothing, so it is Low risk. The input is the PMBus transaction (command code + " +
		"little-endian data). ':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (power-rail / PMBus PMFault recon; pairs with i2c_scan). " +
		"Wrap-vs-native: native — a byte read + an opcode table + bit/float decodes, stdlib only, no new " +
		"go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The PMBus transaction (command code + little-endian data, e.g. '88 30 F0' for READ_VIN = 12 V) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pmbusDecodeHandler,
}

func pmbusDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("pmbus_decode: 'hex' is required")
	}
	res, err := pmbus.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("pmbus_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
