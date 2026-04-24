// Package mcp exposes PromptZero's tool surface over the Model Context
// Protocol (stdio transport). Started by `promptzero --mcp` and intended
// to be plugged into MCP clients like Claude Desktop or Claude Code as a
// local tool server.
//
// Every registered tool carries risk metadata derived from
// internal/risk.Classify, surfaced to the client as MCP annotations
// (readOnlyHint, destructiveHint, openWorldHint). Operators can use those
// hints to gate destructive calls in their MCP client.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/marauder"
	"github.com/xunholy/promptzero/internal/persona"
	"github.com/xunholy/promptzero/internal/risk"
	toolsreg "github.com/xunholy/promptzero/internal/tools"
	"github.com/xunholy/promptzero/internal/workflows"
)

// Server is the stdio MCP server wrapping a connected Flipper and
// optional Marauder sidecar.
type Server struct {
	flipper  *flipper.Flipper
	marauder *marauder.Marauder
	srv      *mcpserver.MCPServer
	tools    []string
	prompts  []string
}

type toolHandler func(ctx context.Context, args map[string]interface{}) (string, error)

// NewServer builds the MCP server and registers every tool compatible
// with the connected devices. The Marauder parameter may be nil; when
// absent, WiFi tools are not advertised.
func NewServer(f *flipper.Flipper, m *marauder.Marauder) *Server {
	s := &Server{flipper: f, marauder: m}

	s.srv = mcpserver.NewMCPServer(
		"promptzero",
		"1.0.0",
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithPromptCapabilities(false),
	)

	s.registerWorkflowTools()
	if m != nil {
		s.registerMarauderTools()
	}
	s.registerFromRegistry()
	s.registerPersonaPrompts()

	return s
}

// MCPServer returns the underlying mcp-go server. Exposed so tests can
// attach alternate transports (e.g. in-process pipes) without going
// through the stdio wiring.
func (s *Server) MCPServer() *mcpserver.MCPServer { return s.srv }

// ToolNames returns the list of registered tool names in registration
// order.
func (s *Server) ToolNames() []string {
	out := make([]string, len(s.tools))
	copy(out, s.tools)
	return out
}

// PromptNames returns the list of registered prompt names.
func (s *Server) PromptNames() []string {
	out := make([]string, len(s.prompts))
	copy(out, s.prompts)
	return out
}

// ServeStdio starts the server on the process's stdin/stdout pair. Blocks
// until the client disconnects or the process is signalled.
func (s *Server) ServeStdio() error {
	// MCP has no shell to prompt on; every tool executes immediately.
	// Surface that trust boundary on startup so it's never implicit.
	fmt.Fprintln(os.Stderr, "\x1b[33m●\x1b[0m MCP mode: all tools execute without confirmation — trust your MCP client")
	return mcpserver.ServeStdio(s.srv)
}

// add registers a tool against the underlying MCP server. The handler is
// wrapped with argument unmarshalling, required-field validation, and
// risk-based MCP annotations. Required field names are the subset of opts
// that callers must supply — they are validated in addition to any
// schema-level Required() markers already attached to opts.
func (s *Server) add(name, desc string, opts []mcp.ToolOption, required []string, handler toolHandler) {
	level := risk.Classify(name)

	readOnly := level == risk.Low
	destructive := level >= risk.High
	openWorld := level != risk.Low

	annotations := []mcp.ToolOption{
		mcp.WithDescription(desc),
		mcp.WithTitleAnnotation(fmt.Sprintf("%s (%s)", name, level.String())),
		mcp.WithReadOnlyHintAnnotation(readOnly),
		mcp.WithDestructiveHintAnnotation(destructive),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(openWorld),
	}
	allOpts := append(annotations, opts...)
	tool := mcp.NewTool(name, allOpts...)

	s.srv.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := decodeArgs(req)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
		}
		if missing := missingRequired(args, required); len(missing) > 0 {
			return mcp.NewToolResultError(
				fmt.Sprintf("missing required argument(s): %s", strings.Join(missing, ", ")),
			), nil
		}
		result, err := handler(ctx, args)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("error: %v", err)), nil
		}
		return mcp.NewToolResultText(result), nil
	})
	s.tools = append(s.tools, name)
}

func decodeArgs(req mcp.CallToolRequest) (map[string]interface{}, error) {
	args := map[string]interface{}{}
	if req.Params.Arguments == nil {
		return args, nil
	}
	data, err := json.Marshal(req.Params.Arguments)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &args); err != nil {
		return nil, err
	}
	return args, nil
}

func missingRequired(args map[string]interface{}, required []string) []string {
	var missing []string
	for _, name := range required {
		v, ok := args[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		switch t := v.(type) {
		case string:
			if strings.TrimSpace(t) == "" {
				missing = append(missing, name)
			}
		case nil:
			missing = append(missing, name)
		}
	}
	return missing
}

// --- Registration: workflows (Flipper-only composites) ---

func (s *Server) registerWorkflowTools() {
	deps := workflows.Deps{
		Flipper:  s.flipper,
		Marauder: s.marauder,
	}

	s.add("workflow_hw_recon_blackbox_device",
		"Recon an unknown PCB on the GPIO header: i2c_scan, onewire_search, GPIO sweep, bt_hci_info, device_info. Read-only.",
		[]mcp.ToolOption{mcp.WithArray("gpios", mcp.Description("Optional pin list override"))},
		nil,
		func(ctx context.Context, a map[string]interface{}) (string, error) {
			return workflows.HWReconBlackbox(ctx, deps, a)
		})

	s.add("workflow_garage_door_triage",
		"Scan common garage/gate/car-remote Sub-GHz frequencies and decode captures. Receive-only.",
		[]mcp.ToolOption{
			mcp.WithArray("frequencies", mcp.Description("Frequency list in Hz (default: 7 common bands)")),
			mcp.WithNumber("per_freq_seconds", mcp.Description("Seconds per frequency (default 5)")),
		},
		nil,
		func(ctx context.Context, a map[string]interface{}) (string, error) {
			return workflows.GarageDoorTriage(ctx, deps, a)
		})

	s.add("workflow_phys_pentest_badge_walk",
		"Continuous RFID + NFC + iButton census, dedup unique UIDs, write CSV to SD card.",
		[]mcp.ToolOption{
			mcp.WithNumber("duration_seconds", mcp.Description("Total walk duration (default 300)")),
			mcp.WithNumber("dedupe_window_seconds", mcp.Description("Dedupe window (default 0 = forever)")),
			mcp.WithString("csv_path", mcp.Description("Destination CSV path")),
		},
		nil,
		func(ctx context.Context, a map[string]interface{}) (string, error) {
			return workflows.PhysPentestBadgeWalk(ctx, deps, a)
		})
}

// --- Registration: Marauder tools ---

func (s *Server) registerMarauderTools() {
	m := s.marauder

	s.add("wifi_scan_ap", "Scan for WiFi access points.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Scan duration (default 15)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.ScanAP(durationParam(a, "duration_seconds", 15*time.Second))
		})
	s.add("wifi_scan_all", "Scan for both APs and client stations.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Scan duration (default 15)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.ScanAll(durationParam(a, "duration_seconds", 15*time.Second))
		})
	s.add("wifi_stop_scan", "Stop any running scan or attack.", nil, nil,
		func(_ context.Context, _ map[string]interface{}) (string, error) { return m.StopScan() })

	s.add("wifi_list_aps", "List discovered APs.", nil, nil,
		func(_ context.Context, _ map[string]interface{}) (string, error) { return m.ListAPs() })
	s.add("wifi_list_ssids", "List configured beacon-spam SSIDs.", nil, nil,
		func(_ context.Context, _ map[string]interface{}) (string, error) { return m.ListSSIDs() })
	s.add("wifi_list_stations", "List discovered client stations.", nil, nil,
		func(_ context.Context, _ map[string]interface{}) (string, error) { return m.ListStations() })

	s.add("wifi_clear_aps", "Clear discovered APs.", nil, nil,
		func(_ context.Context, _ map[string]interface{}) (string, error) { return m.ClearAPs() })
	s.add("wifi_clear_ssids", "Clear SSID list.", nil, nil,
		func(_ context.Context, _ map[string]interface{}) (string, error) { return m.ClearSSIDs() })
	s.add("wifi_clear_stations", "Clear discovered stations.", nil, nil,
		func(_ context.Context, _ map[string]interface{}) (string, error) { return m.ClearStations() })

	s.add("wifi_select_ap", "Select APs by index for an attack.",
		[]mcp.ToolOption{mcp.WithString("indices", mcp.Required(), mcp.Description("Comma-separated indices, or 'all'"))},
		[]string{"indices"},
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.SelectAP(sa(a, "indices"))
		})
	s.add("wifi_select_station", "Select stations by index.",
		[]mcp.ToolOption{mcp.WithString("indices", mcp.Required(), mcp.Description("Comma-separated indices, or 'all'"))},
		[]string{"indices"},
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.SelectStation(sa(a, "indices"))
		})
	s.add("wifi_select_ssid", "Select SSIDs by index.",
		[]mcp.ToolOption{mcp.WithString("indices", mcp.Required(), mcp.Description("Comma-separated indices, or 'all'"))},
		[]string{"indices"},
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.SelectSSID(sa(a, "indices"))
		})

	s.add("wifi_deauth", "Deauth attack on selected targets. Critical.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.DeauthAttack(durationParam(a, "duration_seconds", 30*time.Second))
		})
	s.add("wifi_deauth_station_list", "Deauth the currently-selected station list (populate via wifi_scan_all + wifi_select_station first).",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.DeauthToStationList(durationParam(a, "duration_seconds", 30*time.Second))
		})
	s.add("wifi_beacon_spam", "Broadcast fake SSIDs from the current list.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.BeaconSpamList(durationParam(a, "duration_seconds", 30*time.Second))
		})
	s.add("wifi_beacon_random", "Broadcast random SSIDs.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.BeaconSpamRandom(durationParam(a, "duration_seconds", 30*time.Second))
		})
	s.add("wifi_beacon_clone", "Clone nearby SSIDs and spam them.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.BeaconSpamClone(durationParam(a, "duration_seconds", 30*time.Second))
		})
	s.add("wifi_probe_flood", "Flood the area with probe requests.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.ProbeFlood(durationParam(a, "duration_seconds", 30*time.Second))
		})
	s.add("wifi_csa_attack", "CSA attack — force clients to switch channel. Critical.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.CSAAttack(durationParam(a, "duration_seconds", 30*time.Second))
		})
	s.add("wifi_sae_flood", "Flood APs with SAE auth frames. Critical.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.SAEFlood(durationParam(a, "duration_seconds", 30*time.Second))
		})

	s.add("wifi_sniff_pmkid", "Capture PMKID hashes (offline crack candidates).",
		[]mcp.ToolOption{
			mcp.WithNumber("channel", mcp.Description("Specific WiFi channel (0 = all)")),
			mcp.WithBoolean("deauth", mcp.Description("Trigger deauth frames to coerce handshakes")),
			mcp.WithBoolean("list_only", mcp.Description("Limit capture to the currently-loaded AP list")),
			mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 60)")),
		},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.SniffPMKID(int(na(a, "channel")), ba(a, "deauth"), ba(a, "list_only"), durationParam(a, "duration_seconds", 60*time.Second))
		})
	s.add("wifi_sniff_beacon", "Capture beacon frames.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.SniffBeacon(durationParam(a, "duration_seconds", 30*time.Second))
		})
	s.add("wifi_sniff_deauth", "Monitor for deauth frames in the area.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.SniffDeauth(durationParam(a, "duration_seconds", 30*time.Second))
		})
	s.add("wifi_sniff_probe", "Capture probe requests from nearby devices.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.SniffProbe(durationParam(a, "duration_seconds", 30*time.Second))
		})
	s.add("wifi_sniff_raw", "Capture all raw packets on the current channel.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.SniffRaw(durationParam(a, "duration_seconds", 30*time.Second))
		})

	s.add("wifi_ble_spam", "BLE advertisement spam. Critical.",
		[]mcp.ToolOption{
			mcp.WithString("mode", mcp.Required(), mcp.Description("apple, google, samsung, windows, flipper, all")),
			mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)")),
		},
		[]string{"mode"},
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.BLESpam(sa(a, "mode"), durationParam(a, "duration_seconds", 30*time.Second))
		})
	s.add("wifi_sniff_bt", "Sniff Bluetooth device advertisements.",
		[]mcp.ToolOption{
			mcp.WithString("target_type", mcp.Required(), mcp.Description("airtag, flipper, flock, meta")),
			mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)")),
		},
		[]string{"target_type"},
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.SniffBT(sa(a, "target_type"), durationParam(a, "duration_seconds", 30*time.Second))
		})
	s.add("wifi_sniff_skimmer", "Sniff for Bluetooth credit card skimmers.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.SniffSkimmer(durationParam(a, "duration_seconds", 30*time.Second))
		})

	s.add("wifi_evil_portal_start", "Start an evil captive portal.",
		[]mcp.ToolOption{mcp.WithString("filename", mcp.Description("HTML filename on SD card"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.EvilPortalStart(sa(a, "filename"))
		})
	s.add("wifi_evil_portal_stop", "Stop the evil portal.", nil, nil,
		func(_ context.Context, _ map[string]interface{}) (string, error) { return m.StopScan() })

	s.add("wifi_info", "Get Marauder devboard info.", nil, nil,
		func(_ context.Context, _ map[string]interface{}) (string, error) { return m.Info() })
	s.add("wifi_reboot", "Reboot the Marauder devboard. Critical.", nil, nil,
		func(_ context.Context, _ map[string]interface{}) (string, error) { return m.Reboot() })
	s.add("wifi_settings", "List Marauder device settings.", nil, nil,
		func(_ context.Context, _ map[string]interface{}) (string, error) { return m.Settings() })
	s.add("wifi_set_setting", "Update a Marauder device setting.",
		[]mcp.ToolOption{
			mcp.WithString("name", mcp.Required(), mcp.Description("Setting name")),
			mcp.WithString("value", mcp.Required(), mcp.Description("New value")),
		},
		[]string{"name", "value"},
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.SetSetting(sa(a, "name"), sa(a, "value"))
		})
	s.add("wifi_set_channel", "Set the active WiFi channel.",
		[]mcp.ToolOption{mcp.WithNumber("channel", mcp.Required(), mcp.Description("WiFi channel 1-14"))},
		[]string{"channel"},
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.SetChannel(int(na(a, "channel")))
		})

	// --- GPS (passive read-only) ---
	s.add("marauder_gps_data", "Return the last parsed GPS fix from the Marauder devboard.", nil, nil,
		func(_ context.Context, _ map[string]interface{}) (string, error) { return m.GPSData() })
	s.add("marauder_gps_field", "Return a single GPS datum.",
		[]mcp.ToolOption{
			mcp.WithString("field", mcp.Required(), mcp.Description("fix|sat|lon|lat|alt|date|accuracy|text|nmea")),
			mcp.WithString("nav_system", mcp.Description("Optional: native|all|gps|glonass|galileo|navic|qzss|beidou")),
		},
		[]string{"field"},
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.GPSField(sa(a, "field"), sa(a, "nav_system"))
		})
	s.add("marauder_nmea", "Stream raw NMEA sentences from the attached GPS module.",
		[]mcp.ToolOption{mcp.WithNumber("duration_seconds", mcp.Description("Capture duration (default 5)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.NMEA(durationParam(a, "duration_seconds", 5*time.Second))
		})

	// --- Device-local utilities ---
	s.add("marauder_packet_count", "Return the cumulative packet counters (per frame type).", nil, nil,
		func(_ context.Context, _ map[string]interface{}) (string, error) { return m.PacketCount() })
	s.add("marauder_storage_ls", "List contents of a directory on the Marauder SD card.",
		[]mcp.ToolOption{mcp.WithString("path", mcp.Description("Directory path (default /)"))},
		nil,
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.StorageLS(sa(a, "path"))
		})

	// --- LED control ---
	s.add("marauder_led_set", "Set the devboard LED to a fixed 24-bit RGB hex colour.",
		[]mcp.ToolOption{mcp.WithString("rgb_hex", mcp.Required(), mcp.Description("6-hex RGB e.g. ff0000"))},
		[]string{"rgb_hex"},
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.LEDSetHex(sa(a, "rgb_hex"))
		})
	s.add("marauder_led_rainbow", "Start the cycling rainbow LED pattern.", nil, nil,
		func(_ context.Context, _ map[string]interface{}) (string, error) { return m.LEDRainbow() })

	// --- Named-service portscan (requires Join) ---
	s.add("wifi_portscan_service", "Scan the host at the given IP index for a named service (ssh, http, ...). Requires a prior Join.",
		[]mcp.ToolOption{
			mcp.WithNumber("ip_index", mcp.Required(), mcp.Description("IP list index")),
			mcp.WithString("service", mcp.Required(), mcp.Description("Service token: ssh|http|https|ftp|smb|rdp|dns|smtp|pop3|imap|mysql|psql|mssql|redis|vnc")),
			mcp.WithNumber("duration_seconds", mcp.Description("Duration (default 30)")),
		},
		[]string{"ip_index", "service"},
		func(_ context.Context, a map[string]interface{}) (string, error) {
			return m.PortScanService(int(na(a, "ip_index")), sa(a, "service"), durationParam(a, "duration_seconds", 30*time.Second))
		})
}

// --- Registration: persona prompts ---

// registerPersonaPrompts advertises each built-in persona as an MCP prompt
// so MCP clients (Claude Desktop, Claude Code) can surface them in their
// slash-command picker. Returning the persona's system prompt as a user
// message lets the downstream model adopt the operator mode without
// PromptZero needing to stream the mode switch itself.
func (s *Server) registerPersonaPrompts() {
	reg := persona.NewRegistry()
	for _, name := range reg.Names() {
		pp, ok := reg.Get(name)
		if !ok {
			continue
		}
		captured := *pp
		promptName := "persona_" + captured.Name
		prompt := mcp.NewPrompt(promptName, mcp.WithPromptDescription(captured.Description))
		s.srv.AddPrompt(prompt, func(_ context.Context, _ mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{
				Description: captured.Description,
				Messages: []mcp.PromptMessage{{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent(captured.SystemPrompt),
				}},
			}, nil
		})
		s.prompts = append(s.prompts, promptName)
	}
}

// --- Registry adapter ---

// registerFromRegistry wires every non-AgentOnly Spec from the central
// tool registry into the MCP server. This is the adapter that bridges
// internal/tools into the MCP host. Called from NewServer after the
// legacy register* chain so that, during Waves 0-4, the registry-backed
// tools are registered without the legacy s.add() calls that were
// removed in the same wave commit.
func (s *Server) registerFromRegistry() {
	for _, spec := range toolsreg.All() {
		if spec.AgentOnly {
			continue
		}
		opts := optsFromSchema(spec.Schema, spec.Required)
		names := append([]string{spec.Name}, spec.Aliases...)
		for _, name := range names {
			specCopy := spec
			nameCopy := name
			s.add(nameCopy, specCopy.Description, opts, specCopy.Required,
				func(ctx context.Context, args map[string]interface{}) (string, error) {
					return specCopy.Handler(ctx, s.deps(), args)
				})
		}
	}
}

// deps returns a Deps bag populated with only the transports the MCP
// server has access to. The LLM-specific fields (Generator, Vision,
// Snapshot, etc.) are nil — only non-AgentOnly handlers are called
// through this path, so they must degrade gracefully on nil fields.
func (s *Server) deps() *toolsreg.Deps {
	return &toolsreg.Deps{
		Flipper:  s.flipper,
		Marauder: s.marauder,
	}
}

// optsFromSchema converts a JSON Schema object into mcp.ToolOption entries.
// Only top-level property types are handled: string, integer, number,
// boolean, array, object. Properties listed in required get mcp.Required().
func optsFromSchema(schema []byte, required []string) []mcp.ToolOption {
	if len(schema) == 0 {
		return nil
	}
	var s struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schema, &s); err != nil || len(s.Properties) == 0 {
		return nil
	}
	reqSet := make(map[string]bool, len(required))
	for _, r := range required {
		reqSet[r] = true
	}
	var opts []mcp.ToolOption
	for name, propRaw := range s.Properties {
		var prop struct {
			Type        string `json:"type"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(propRaw, &prop); err != nil {
			continue
		}
		var propOpts []mcp.PropertyOption
		propOpts = append(propOpts, mcp.Description(prop.Description))
		if reqSet[name] {
			propOpts = append(propOpts, mcp.Required())
		}
		switch prop.Type {
		case "string":
			opts = append(opts, mcp.WithString(name, propOpts...))
		case "integer", "number":
			opts = append(opts, mcp.WithNumber(name, propOpts...))
		case "boolean":
			opts = append(opts, mcp.WithBoolean(name, propOpts...))
		case "array":
			opts = append(opts, mcp.WithArray(name, propOpts...))
		case "object":
			opts = append(opts, mcp.WithObject(name, propOpts...))
		}
	}
	return opts
}

// --- Argument helpers ---

func sa(a map[string]interface{}, k string) string {
	if v, ok := a[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func na(a map[string]interface{}, k string) float64 {
	if v, ok := a[k]; ok {
		switch t := v.(type) {
		case float64:
			return t
		case int:
			return float64(t)
		case int64:
			return float64(t)
		}
	}
	return 0
}

func ba(a map[string]interface{}, k string) bool {
	if v, ok := a[k]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func durationParam(a map[string]interface{}, k string, def time.Duration) time.Duration {
	secs := na(a, k)
	if secs <= 0 {
		return def
	}
	return time.Duration(secs) * time.Second
}
