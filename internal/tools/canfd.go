// canfd.go — host-side CAN / CAN-FD frame decoder Spec, delegating to
// the internal/canfd package for the candump-grammar + ISO 11898-1 +
// SAE J1939 decode proper.
//
// Wrap-vs-native judgement: native. The live canbus_* Specs drive an
// MCP2515 daughterboard to read frames off the bus; this decodes a
// frame already captured (candump -L, a SavvyCAN/Wireshark export, or
// a Flipper-side CAN sniff) with no hardware attached. The reusable
// part — the SocketCAN candump frame grammar, the CAN-FD DLC↔length
// table, and the SAE J1939-21 extended-ID decomposition — is a public
// deterministic transform, exactly like the offline Sub-GHz decoders.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/canfd"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(canbusFDDecodeSpec)
}

var canbusFDDecodeSpec = Spec{
	Name: "canbus_fd_decode",
	Description: "Decode a captured CAN or CAN-FD frame (SocketCAN candump text) into its structured " +
		"fields — the format-independent signal an automotive pentester reads off a bus capture " +
		"without the bus attached. Current-gen vehicles (Tesla, most EVs) and heavy/agricultural/marine " +
		"equipment (SAE J1939) run CAN-FD and 29-bit extended IDs that the classic canbus_* live Specs " +
		"capture but don't decompose. Input is a candump frame token; a full `candump -L` line " +
		"(\"(ts) iface FRAME\") is tolerated (the frame is the last token). Two frame grammars:\n\n" +
		" - **Classic CAN 2.0**: `ID#DATA` (≤8 data bytes; `ID#R` / `ID#Rn` for a remote frame).\n" +
		" - **CAN-FD**: `ID##FDATA` where the first nibble after `##` is the FD flags (bit 0 = BRS " +
		"bit-rate switch, bit 1 = ESI error-state indicator) and the rest is up to 64 data bytes.\n\n" +
		"Decodes:\n" +
		"- **Identifier**: standard (11-bit) vs extended (29-bit) — inferred from candump's zero-padded " +
		"width and the 11-bit range — as hex + decimal.\n" +
		"- **CAN-FD framing**: FDF/BRS/ESI flags and the ISO 11898-1:2015 DLC↔length mapping " +
		"(0-8, 12, 16, 20, 24, 32, 48, 64), flagging any payload that isn't a legal CAN-FD length.\n" +
		"- **SAE J1939** decomposition of 29-bit IDs: priority, EDP/DP, PDU format/specific, source " +
		"address, and the resolved PGN with PDU1 (destination-specific) vs PDU2 (broadcast) " +
		"classification — the dominant extended-ID bus.\n\n" +
		"Pure offline parser — no Flipper / MCP2515 required at decode time. Companion to the live " +
		"canbus_* Specs (init / sniff / inject / replay).\n\n" +
		"Out of scope (deliberately): signal-level decode (raw bytes → RPM / speed / …) needs a " +
		"per-vehicle DBC database and is unverifiable here, so the raw data bytes are surfaced for the " +
		"operator to apply their DBC (a confidently-wrong signal value is worse than none); and live " +
		"capture (use the canbus_* Specs).\n\n" +
		"Source: docs/catalog/gap-analysis.md §3 rank 17 (canbus_fd_sniff — offline-decode sibling). " +
		"Accepts ':' '-' '_' '.' / whitespace separators in the data field.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"frame":{"type":"string","description":"A SocketCAN candump frame: 'ID#DATA' (classic CAN 2.0) or 'ID##flags+DATA' (CAN-FD). A full 'candump -L' line is tolerated. ':' '-' '_' '.' / whitespace separators in the data field are accepted."}
		},
		"required":["frame"]
	}`),
	Required:  []string{"frame"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   canbusFDDecodeHandler,
}

func canbusFDDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "frame")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("canbus_fd_decode: 'frame' is required")
	}
	res, err := canfd.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("canbus_fd_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
