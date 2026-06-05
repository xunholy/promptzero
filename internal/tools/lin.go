// lin.go — host-side LIN (Local Interconnect Network) automotive bus
// frame decoder Spec, delegating to the internal/lin package.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/lin"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(linFrameDecodeSpec)
}

var linFrameDecodeSpec = Spec{
	Name: "lin_frame_decode",
	Description: "Decode a LIN (Local Interconnect Network) bus frame — the low-cost single-wire " +
		"automotive sub-bus that hangs off CAN for body electronics: door / mirror / seat " +
		"modules, climate flaps, wiper and rain/light sensors, switch panels. LIN is a real " +
		"automotive reverse-engineering / pentest surface — cheap to tap and usually " +
		"unauthenticated — and is distinct from the CAN family the other automotive decoders " +
		"(canbus_fd_decode / isotp_decode / uds_decode / obd2_*) cover. Per LIN 2.x / ISO 17987. " +
		"Decodes:\n\n" +
		"- The **Protected Identifier (PID)**: the 6-bit frame ID, the two parity bits, and a " +
		"recompute of the parity (P0 = ID0^ID1^ID2^ID4, P1 = !(ID1^ID3^ID4^ID5)) reported valid " +
		"/ invalid — plus the frame class (signal-carrying / master-request or slave-response " +
		"diagnostic [ID 0x3C/0x3D] / user-defined / reserved).\n" +
		"- The **data bytes** (length = frame length − PID − checksum, 0-8 bytes).\n" +
		"- The **checksum**: both the classic (data-only — LIN 1.x and diagnostic frames) and the " +
		"enhanced (PID + data — LIN 2.x) inverted carry-folded sums are computed, and the frame's " +
		"checksum is reported as classic / enhanced / invalid.\n\n" +
		"Paste the captured frame as hex: an optional leading 0x55 sync byte, the PID, the data " +
		"bytes, then the checksum. ':' / '-' / '_' / whitespace separators and a '0x' prefix " +
		"tolerated. Verified against the standard LIN PID constants (0x3C→0x3C, 0x3D→0x7D, " +
		"0x00→0x80, 0x01→0xC1) and the carry-folded checksum.\n\n" +
		"Out of scope (deferred): the signal (LDF/DBC) interpretation of the data bytes (needs " +
		"the vehicle's LIN Description File — raw data surfaced); and the break field / bit-timing " +
		"(physical layer, upstream of the captured bytes).\n\n" +
		"Source: docs/catalog/gap-analysis.md (automotive decode space). Wrap-vs-native: native — " +
		"a LIN frame is a fixed public structure decoded by two parity XOR equations and one " +
		"carry-folded checksum; reimplemented from the standard, not wrapped. Pairs with the " +
		"CAN-family decoders for the full in-vehicle network picture.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"LIN frame as hex: optional 0x55 sync byte + PID + 0-8 data bytes + checksum. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   linFrameDecodeHandler,
}

func linFrameDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("lin_frame_decode: 'hex' is required")
	}
	res, err := lin.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("lin_frame_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
