// canbus.go — automotive CAN bus Specs.
//
// Bridges to ElectronicCats/flipper-MCP2515-CANBUS — a Flipper .fap that
// loads a CAN bus controller via GPIO + an MCP2515 daughterboard. Once
// the .fap is loaded on the connected Flipper, it exposes a `canbus`
// subcommand on the Flipper CLI; PromptZero invokes it via the existing
// raw-CLI passthrough.
//
// PromptZero does NOT compile or load the .fap automatically — operators
// install it via the standard Flipper app catalogue or fap_build, then
// activate it on-device. Use `discover_apps` to confirm it's installed
// before invoking these Specs.
//
// Reference: https://github.com/ElectronicCats/flipper-MCP2515-CANBUS
//
// Companion projects worth considering during reads:
//
//   * hypery11/flipper-tesla-fsd (Apr 2026) — Tesla CAN-mod listing of
//     Tesla-specific CAN IDs and an OBD-II decode reference.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(canbusInitSpec)
	Register(canbusSniffStartSpec)
	Register(canbusSniffStopSpec)
	Register(canbusInjectSpec)
	Register(canbusReplaySpec)
	Register(canbusInfoSpec)
}

// --- canbus_init -------------------------------------------------------

var canbusInitSpec = Spec{
	Name: "canbus_init",
	Description: "Initialise the MCP2515 CAN controller at the given bitrate. Required before any other canbus_* Spec works. Bitrate is in kbps; common values: 125, 250, 500 (vehicle high-speed bus), 1000. Requires the Flipper to have ElectronicCats/flipper-MCP2515-CANBUS .fap installed and the MCP2515 hat connected via the GPIO header.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"bitrate_kbps":{"type":"integer","description":"CAN bus bit rate in kbps (e.g. 500 for OBD-II)"}
		},
		"required":["bitrate_kbps"]
	}`),
	Required:  []string{"bitrate_kbps"},
	Risk:      risk.Medium,
	Group:     GroupFlipperHW,
	AgentOnly: false,
	Handler:   canbusInitHandler,
}

func canbusInitHandler(_ context.Context, d *Deps, args map[string]any) (string, error) {
	if d == nil || d.Flipper == nil {
		return "", fmt.Errorf("canbus_init: Flipper not connected")
	}
	bitrate := intOr(args, "bitrate_kbps", 0)
	if bitrate <= 0 {
		return "", fmt.Errorf("canbus_init: bitrate_kbps must be > 0")
	}
	out, err := d.Flipper.RawCLI(fmt.Sprintf("canbus init %d", bitrate))
	return wrapCANResult(out, err)
}

// --- canbus_sniff_start / canbus_sniff_stop ----------------------------

var canbusSniffStartSpec = Spec{
	Name: "canbus_sniff_start",
	Description: "Begin sniffing CAN frames. Frames are written to /ext/canbus/sniff.log on the Flipper SD until canbus_sniff_stop is called. Optional id_filter limits the capture to a single arbitration ID; default is all IDs. Use storage_read to retrieve the log when finished.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"id_filter":{"type":"string","description":"11-bit or 29-bit hex CAN ID to filter on (e.g. 7DF). Empty = capture everything."},
			"output_path":{"type":"string","description":"Override the default /ext/canbus/sniff.log path."}
		}
	}`),
	Required:  nil,
	Risk:      risk.Medium,
	Group:     GroupFlipperHW,
	AgentOnly: false,
	Handler:   canbusSniffStartHandler,
}

func canbusSniffStartHandler(_ context.Context, d *Deps, args map[string]any) (string, error) {
	if d == nil || d.Flipper == nil {
		return "", fmt.Errorf("canbus_sniff_start: Flipper not connected")
	}
	cmd := "canbus sniff start"
	if f := str(args, "id_filter"); f != "" {
		cmd += " --id " + f
	}
	if p := str(args, "output_path"); p != "" {
		cmd += " --out " + p
	}
	out, err := d.Flipper.RawCLI(cmd)
	return wrapCANResult(out, err)
}

var canbusSniffStopSpec = Spec{
	Name: "canbus_sniff_stop",
	Description: "Stop the running CAN sniffer. Returns the path to the captured log on the Flipper SD.",
	Schema: json.RawMessage(`{"type":"object","properties":{}}`),
	Required:    nil,
	Risk:        risk.Low,
	Group:       GroupFlipperHW,
	AgentOnly:   false,
	Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
		if d == nil || d.Flipper == nil {
			return "", fmt.Errorf("canbus_sniff_stop: Flipper not connected")
		}
		out, err := d.Flipper.RawCLI("canbus sniff stop")
		return wrapCANResult(out, err)
	},
}

// --- canbus_inject -----------------------------------------------------

var canbusInjectSpec = Spec{
	Name: "canbus_inject",
	Description: "Transmit a single CAN frame onto the bus. Use ONLY in authorized engagements — injecting onto a live vehicle CAN bus can cause unsafe behaviour. arbitration_id_hex is the 11-bit (e.g. 7E0) or 29-bit ID; data_hex is up to 8 bytes payload (16 hex chars).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"arbitration_id_hex":{"type":"string","description":"CAN arbitration ID, hex"},
			"data_hex":{"type":"string","description":"Up to 8 bytes of frame data, hex (max 16 chars)"},
			"extended":{"type":"boolean","description":"True for 29-bit (CAN 2.0B) framing; default false (11-bit)"}
		},
		"required":["arbitration_id_hex","data_hex"]
	}`),
	Required:  []string{"arbitration_id_hex", "data_hex"},
	Risk:      risk.Critical,
	Group:     GroupFlipperHW,
	AgentOnly: false,
	Handler:   canbusInjectHandler,
}

func canbusInjectHandler(_ context.Context, d *Deps, args map[string]any) (string, error) {
	if d == nil || d.Flipper == nil {
		return "", fmt.Errorf("canbus_inject: Flipper not connected")
	}
	id := strings.TrimSpace(str(args, "arbitration_id_hex"))
	if id == "" {
		return "", fmt.Errorf("canbus_inject: arbitration_id_hex is required")
	}
	data := strings.TrimSpace(str(args, "data_hex"))
	if len(data) > 16 {
		return "", fmt.Errorf("canbus_inject: data_hex too long (max 16 chars / 8 bytes)")
	}
	cmd := fmt.Sprintf("canbus inject %s %s", id, data)
	if boolOr(args, "extended", false) {
		cmd += " --ext"
	}
	out, err := d.Flipper.RawCLI(cmd)
	return wrapCANResult(out, err)
}

// --- canbus_replay -----------------------------------------------------

var canbusReplaySpec = Spec{
	Name: "canbus_replay",
	Description: "Replay a captured CAN log file (path on the Flipper SD). Use to reproduce a previously-observed bus sequence — e.g. unlock-door message replay during authorized testing. Uses Critical risk because it writes to a live bus.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"path":{"type":"string","description":"Path to a sniff log on Flipper SD, e.g. /ext/canbus/sniff.log"},
			"loop":{"type":"boolean","description":"Replay continuously until stopped. Default false."}
		},
		"required":["path"]
	}`),
	Required:  []string{"path"},
	Risk:      risk.Critical,
	Group:     GroupFlipperHW,
	AgentOnly: false,
	Handler:   canbusReplayHandler,
}

func canbusReplayHandler(_ context.Context, d *Deps, args map[string]any) (string, error) {
	if d == nil || d.Flipper == nil {
		return "", fmt.Errorf("canbus_replay: Flipper not connected")
	}
	p := str(args, "path")
	if p == "" {
		return "", fmt.Errorf("canbus_replay: path is required")
	}
	cmd := "canbus replay " + p
	if boolOr(args, "loop", false) {
		cmd += " --loop"
	}
	out, err := d.Flipper.RawCLI(cmd)
	return wrapCANResult(out, err)
}

// --- canbus_info -------------------------------------------------------

var canbusInfoSpec = Spec{
	Name: "canbus_info",
	Description: "Report MCP2515 controller status, bitrate, error counters, and bus loading. Read-only; safe to call freely.",
	Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
	Required:    nil,
	Risk:        risk.Low,
	Group:       GroupFlipperHW,
	AgentOnly:   false,
	Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
		if d == nil || d.Flipper == nil {
			return "", fmt.Errorf("canbus_info: Flipper not connected")
		}
		out, err := d.Flipper.RawCLI("canbus info")
		return wrapCANResult(out, err)
	},
}

// wrapCANResult normalises (rawCLIOutput, error) into a JSON object so
// the agent's reflexion path sees a consistent shape across canbus_*
// invocations. Errors are surfaced both in the body and via the second
// return value so the agent's risk/retry layer behaves correctly.
func wrapCANResult(rawOut string, err error) (string, error) {
	out := map[string]any{
		"raw_output": rawOut,
	}
	if err != nil {
		out["error"] = err.Error()
		body, _ := json.Marshal(out)
		return string(body), err
	}
	out["status"] = "ok"
	body, _ := json.Marshal(out)
	return string(body), nil
}
