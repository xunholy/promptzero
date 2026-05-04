package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/attack"
	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/bruce"
	"github.com/xunholy/promptzero/internal/buspirate"
	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/cost"
	"github.com/xunholy/promptzero/internal/faultier"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/generate"
	"github.com/xunholy/promptzero/internal/marauder"
	"github.com/xunholy/promptzero/internal/mcp"
	"github.com/xunholy/promptzero/internal/mcpfed"
	"github.com/xunholy/promptzero/internal/mode"
	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/persona"
	"github.com/xunholy/promptzero/internal/provider"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/rules"
	"github.com/xunholy/promptzero/internal/snapshot"
	"github.com/xunholy/promptzero/internal/targetmem"
	"github.com/xunholy/promptzero/internal/voice"
	"github.com/xunholy/promptzero/internal/web"
	"github.com/xunholy/promptzero/internal/webhook"
)

// --- First-run & init -----------------------------------------------------

// isFirstRun reports whether this invocation has no config anywhere and no
// API key env var, so we should show the onboarding hint instead of
// attempting to connect.
func isFirstRun(cfgPath string) bool {
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return false
	}
	if _, err := os.Stat(cfgPath); err == nil {
		return false
	}
	if home, err := os.UserHomeDir(); err == nil {
		if _, err := os.Stat(filepath.Join(home, ".promptzero", "config.yaml")); err == nil {
			return false
		}
	}
	return true
}

func printFirstRunHint() {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  Welcome. A few steps to get started:")
	fmt.Fprintln(os.Stderr, "    1. Run `promptzero --init` to scaffold ~/.promptzero/config.yaml")
	fmt.Fprintln(os.Stderr, "    2. Set your Anthropic API key — either:")
	fmt.Fprintln(os.Stderr, "         export ANTHROPIC_API_KEY=sk-ant-\u2026")
	fmt.Fprintln(os.Stderr, "       or add `api_key: sk-ant-\u2026` to ~/.promptzero/config.yaml")
	fmt.Fprintln(os.Stderr, "    3. Plug in your Flipper Zero (USB Virtual COM Port mode)")
	fmt.Fprintln(os.Stderr, "    4. Relaunch `promptzero` and type /help for commands")
	fmt.Fprintln(os.Stderr)
}

// configTemplate is written by --init when no on-disk example is present.
// Kept in sync with config.example.yaml by hand; //go:embed can't reach
// the repo-root example from this package.
const configTemplate = `# promptzero configuration

# Anthropic API key (or set ANTHROPIC_API_KEY env var)
api_key: ""

# OpenAI API key for Whisper voice transcription (or set OPENAI_API_KEY env var)
openai_api_key: ""

# Claude model to use (opus 4.7 default; swap to claude-sonnet-4-6 for
# faster/cheaper turns or claude-haiku-4-5 for minimal cost)
model: "claude-opus-4-7"

# Flipper Zero serial connection
serial:
  port: "/dev/ttyACM0"    # Linux default; macOS: /dev/tty.usbmodemflip_*
  baud_rate: 230400

# ESP32 Marauder WiFi devboard (optional)
marauder:
  enabled: false
  port: "/dev/ttyUSB0"    # Used when bridge=false and transport!="ble" (separate USB cable)
  baud_rate: 115200

  # transport: "ble"      # Drive a standalone ESP32-Marauder devboard directly
  #                       # over BLE — bypasses the Flipper UART bridge.
  #                       # When set, "port" is reinterpreted as the BLE address
  #                       # (MAC/UUID/LocalName). Override with --marauder-ble.

  # Marauder stacked on Flipper GPIO header (single USB cable to Flipper).
  # When bridge=true, PromptZero launches the Flipper's USB-UART Bridge app
  # and pipes the host serial port through to the Marauder. While bridge
  # mode is active, all flipper_* tools are disabled (the CLI is gone by
  # firmware design).
  bridge: false
  # Override per firmware: Momentum / Unleashed / RogueMaster all ship the
  # app as "USB-UART Bridge" today; older OFW builds may expect a different
  # name. Quotes are part of the CLI verb — keep them.
  # bridge_command: 'loader open "USB-UART Bridge"'
  # bridge_settle: 750ms
  # bridge_port_reopen_timeout: 5s

  # Hybrid mode — Flipper over BLE, Marauder via the USB bridge:
  # Set serial.transport_url: "ble://AA:BB:CC:DD:EE:FF" AND
  # marauder.bridge: true AND marauder.port: "/dev/ttyACM0".
  # This keeps the Flipper CLI alive (over BLE) while the USB cable
  # carries Marauder traffic. Requires native Linux or macOS — WSL2
  # does not expose Bluetooth to the Linux guest.

# Web UI settings
web:
  port: 8080

# Device registry — map friendly names to signal files on the Flipper SD card
devices: {}
`

// runInit scaffolds ~/.promptzero/config.yaml from the on-disk example
// (preferred, so edits stay in sync) or the embedded template, then opens
// $EDITOR if set. Refuses to overwrite an existing config.
func runInit() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolving home dir: %w", err)
	}
	dir := filepath.Join(home, ".promptzero")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	target := filepath.Join(dir, "config.yaml")
	if _, err := os.Stat(target); err == nil {
		fmt.Fprintf(os.Stderr, "  %s%s already exists — refusing to overwrite%s\n", yellow, target, reset)
		return nil
	}
	data, err := os.ReadFile("config.example.yaml")
	if err != nil {
		data = []byte(configTemplate)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", target, err)
	}
	fmt.Fprintf(os.Stderr, "  %s●%s wrote %s\n", green, reset, target)
	if editor := os.Getenv("EDITOR"); editor != "" {
		// Split on whitespace so values like "code --wait" or "nvim -p" work.
		parts := append(strings.Fields(editor), target)
		cmd := exec.Command(parts[0], parts[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "  %s%s failed: %v%s\n", yellow, editor, err, reset)
		}
	}
	return nil
}

// --- Risk threshold resolution -------------------------------------------

// resolveConfirmRisk collapses the config value, the --confirm-risk flag,
// and --yolo into a (threshold, enabled) pair. Flags win over config.
// Returns a warning error (not fatal) when the user supplied an unknown
// level; the caller falls back to the default.
func resolveConfirmRisk(cfgValue, flagValue string, yolo bool) (risk.Level, bool, error) {
	raw := strings.ToLower(strings.TrimSpace(cfgValue))
	if flagValue != "" {
		raw = strings.ToLower(strings.TrimSpace(flagValue))
	}
	if yolo {
		raw = "none"
	}
	switch raw {
	case "":
		return risk.High, true, nil
	case "none":
		return risk.High, false, nil
	case "low":
		return risk.Low, true, nil
	case "medium":
		return risk.Medium, true, nil
	case "high":
		return risk.High, true, nil
	case "critical":
		return risk.Critical, true, nil
	default:
		return risk.High, true, fmt.Errorf("unknown confirm_risk %q, using high", raw)
	}
}

// --- Flag parsing --------------------------------------------------------

// runFlags holds the parsed command-line arguments for run(). Kept as a
// single struct so run() can pass the whole set to helpers without
// restating the column of scalars every time.
type runFlags struct {
	cfgPath              string
	portOverride         string
	transportOverride    string
	marauderPortOverride string
	marauderBLEAddr      string // --marauder-ble
	marauderBridge       bool   // --marauder-bridge
	marauderBridgeCmd    string // --marauder-bridge-command
	webMode              bool
	webPort              int
	voiceMode            bool
	wifiEnabled          bool
	mcpMode              bool
	showVersion          bool
	doInit               bool
	resumeID             string
	autoResume           bool
	genProvider          string
	ollamaURL            string
	ollamaModel          string
	connectTimeout       time.Duration
	pipelineProfile      string
	yoloMode             bool
	confirmRisk          string
	personaName          string
	modeName             string // --mode
	watchPaths           stringSlice
	bleDiscover          bool          // --ble-discover
	bleDiscoverDuration  time.Duration // --ble-discover-duration
}

// parseFlags binds all CLI flags and calls flag.Parse. Returns the
// populated struct.
func parseFlags() *runFlags {
	f := &runFlags{}
	flag.StringVar(&f.cfgPath, "config", "config.yaml", "Path to config file")
	flag.StringVar(&f.portOverride, "port", "", "Flipper serial port (overrides config; e.g. /dev/ttyACM0 (Linux), /dev/tty.usbmodemflip_* (macOS), COM3 (Windows))")
	flag.StringVar(&f.transportOverride, "transport", "", "Flipper transport URL (overrides --port + config). Schemes: serial:// (USB), mock:// (tests), ble://<addr> where <addr> is a hardware MAC on Linux/Windows, a CoreBluetooth UUID on macOS (run --ble-discover to find it), or a device LocalName like \"Unholy\". Not supported in WSL2.")
	flag.BoolVar(&f.webMode, "web", false, "Start web UI mode")
	flag.IntVar(&f.webPort, "web-port", 0, "Web server port (overrides config)")
	flag.BoolVar(&f.voiceMode, "voice", false, "Enable voice input (requires sox + OPENAI_API_KEY)")
	flag.BoolVar(&f.wifiEnabled, "wifi", false, "Connect to ESP32 Marauder WiFi devboard")
	flag.StringVar(&f.marauderPortOverride, "marauder-port", "", "Marauder serial port (overrides config; e.g. /dev/ttyUSB0 for CP210x-bridged Marauders, /dev/ttyACM1 for ESP32-S2 native USB)")
	flag.StringVar(&f.marauderBLEAddr, "marauder-ble", "",
		"Connect directly to a standalone ESP32-Marauder devboard over BLE (skips the Flipper UART bridge entirely). Address is a hardware MAC on Linux/Windows, a CoreBluetooth UUID on macOS (run --ble-discover to find it), or a device LocalName like \"Marauder\". Mutually exclusive with --marauder-bridge. Not supported in WSL2.")
	flag.BoolVar(&f.marauderBridge, "marauder-bridge", false,
		"Drive the Marauder via the Flipper's USB-UART bridge (Marauder stacked on GPIO header — single USB cable). Disables flipper_* tools while active.")
	flag.StringVar(&f.marauderBridgeCmd, "marauder-bridge-command", "",
		"Override the Flipper CLI command that launches the UART bridge app (default: loader open \"USB-UART Bridge\").")
	flag.BoolVar(&f.mcpMode, "mcp", false, "Run as MCP server (stdin/stdout)")
	flag.BoolVar(&f.doInit, "init", false, "Scaffold ~/.promptzero/config.yaml and exit")
	flag.StringVar(&f.resumeID, "resume", "", "Resume a saved session by id")
	flag.BoolVar(&f.autoResume, "auto-resume", false, "Auto-resume the most recent session if it's less than 24h old")
	flag.StringVar(&f.genProvider, "gen-provider", "claude", "LLM provider for payload generation: claude|ollama|openrouter (default claude; ollama requires --ollama-url + --ollama-model)")
	flag.StringVar(&f.ollamaURL, "ollama-url", "http://localhost:11434", "Ollama server URL (default: http://localhost:11434)")
	flag.StringVar(&f.ollamaModel, "ollama-model", "llama3.1", "Ollama model for generation (default: llama3.1)")
	flag.DurationVar(&f.connectTimeout, "connect-timeout", 10*time.Second, "Max time to wait for Flipper CLI prompt (default 10s; increase for flaky cables)")
	flag.StringVar(&f.pipelineProfile, "pipeline", "", "Command pipeline profile: fast | balanced | resilient (default balanced; overrides flipper.pipeline in config). 'balanced' preserves legacy retry/timeout values; 'fast' shortens deadlines; 'resilient' lengthens them for flaky cables.")
	flag.BoolVar(&f.yoloMode, "yolo", false, "Skip risk confirmations (shorthand for --confirm-risk=none)")
	flag.StringVar(&f.confirmRisk, "confirm-risk", "", "Confirmation threshold: none|low|medium|high|critical (default: high)")
	flag.StringVar(&f.personaName, "persona", "", "Operator persona (default: value from config or 'default')")
	flag.StringVar(&f.modeName, "mode", "",
		"Operation mode: standard|recon|intel|stealth|assault (default: standard — all groups allowed). "+
			"Recon = read-only, no RF transmit; Intel = Recon plus host-side analysis; "+
			"Stealth = minimal RF (Flipper CLI/storage/IR only); Assault = same surface as Standard with an explicit-intent banner.")
	flag.Var(&f.watchPaths, "watch", "Watch a directory for FS events; repeat to watch several")
	flag.BoolVar(&f.showVersion, "version", false, "Show version")
	flag.BoolVar(&f.bleDiscover, "ble-discover", false, "Scan for nearby BLE peripherals and print their addresses + names + RSSI (use this to find the right ble:// identifier on macOS where hardware MACs are hidden), then exit.")
	flag.DurationVar(&f.bleDiscoverDuration, "ble-discover-duration", 8*time.Second, "Length of the --ble-discover scan (default 8s).")
	flag.Parse()
	return f
}

// --- Config + connect ---------------------------------------------------

// applyConfigOverrides layers CLI flags and env overrides onto the loaded
// config. --transport beats both --port and the config serial block;
// an empty override leaves the config value in place.
func applyConfigOverrides(cfg *config.Config, f *runFlags) {
	if f.webPort > 0 {
		cfg.Web.Port = f.webPort
	}
	if f.portOverride != "" {
		cfg.Serial.Port = f.portOverride
	}
	if f.transportOverride != "" {
		cfg.Serial.TransportURL = f.transportOverride
	}
	if f.marauderPortOverride != "" {
		cfg.Marauder.Port = f.marauderPortOverride
	}
	if f.marauderBLEAddr != "" {
		// --marauder-ble overrides both the transport mode and the address.
		// The BLE address rides in cfg.Marauder.Port for the connect path
		// to consume (same field repurposed; serial paths don't fire when
		// Transport=="ble").
		cfg.Marauder.Transport = "ble"
		cfg.Marauder.Port = f.marauderBLEAddr
		cfg.Marauder.Enabled = true
	}
	if f.marauderBridge {
		cfg.Marauder.Bridge = true
		// Bridge mode implies Marauder is wanted; --wifi can also be
		// omitted with this flag set.
		cfg.Marauder.Enabled = true
	}
	if f.marauderBridgeCmd != "" {
		cfg.Marauder.BridgeCommand = f.marauderBridgeCmd
	}
	if f.pipelineProfile != "" {
		// Flag wins over config so an operator can override a pinned
		// profile from a one-off command line without editing the file.
		cfg.Flipper.Pipeline = f.pipelineProfile
	}
	if lvl := os.Getenv("PROMPTZERO_LOG_LEVEL"); lvl != "" {
		cfg.Observability.LogLevel = lvl
	}
}

// warnMultiFlipper emits a warning when several ACM-class serial devices
// are present and the user didn't pin a specific one via --port. Skipped
// when a non-default transport is in use (mock://, ble://) because the
// user has explicitly opted out of ACM discovery.
func warnMultiFlipper(cfg *config.Config, portOverride string) {
	if portOverride != "" || cfg.Serial.TransportURL != "" {
		return
	}
	if !strings.HasPrefix(cfg.Serial.Port, "/dev/ttyACM") {
		return
	}
	matches, _ := filepath.Glob("/dev/ttyACM*")
	if len(matches) > 1 {
		statusWarn(fmt.Sprintf("Multiple Flipper-class serial devices detected (%s) — using configured port; use --port to target a specific device.",
			strings.Join(matches, ", ")))
	}
}

// connectFlipper resolves the transport URL, connects with the given
// timeout (cancellable via the shared signal handler), and prints the
// connected banner. Returns the client and a cleanup closure the caller
// defers.
func connectFlipper(ctx context.Context, sh *signalHandler, cfg *config.Config, connectTimeout time.Duration) (*flipper.Flipper, func(), error) {
	transportURL := cfg.Serial.TransportURL
	if transportURL == "" {
		transportURL = fmt.Sprintf("serial://%s?baud=%d", cfg.Serial.Port, cfg.Serial.BaudRate)
	}
	statusInfo(fmt.Sprintf("Connecting to Flipper Zero on %s%s%s... %s(timeout %s, press Ctrl+C to cancel)%s",
		bold, transportURL, reset, dim, connectTimeout, reset))

	start := time.Now()
	connectCtx, releaseConnect := sh.withCancel(ctx)
	flip, report, err := flipper.ConnectURL(connectCtx, transportURL, connectTimeout)
	releaseConnect()
	if err != nil {
		printConnectionReportVerbose(report)
		if errors.Is(err, context.Canceled) {
			statusWarn("Flipper connection cancelled")
			return nil, func() {}, err
		}
		statusErr(fmt.Sprintf("Flipper connection failed: %v — check USB cable, try `--port /dev/ttyACM0` or `--transport ble`, or run `promptzero --init`", err))
		return nil, func() {}, fmt.Errorf("flipper: %w", err)
	}

	// ConnectURL ran DetectCapabilities as part of the report; reuse the
	// cached value rather than firing the command again.
	caps := flip.Capabilities()
	elapsed := time.Since(start).Round(time.Millisecond)
	if caps.HardwareName == "" {
		statusOK(fmt.Sprintf("Flipper connected %s(%s)%s", dim, elapsed, reset))
	} else {
		// Example: "Flipper connected: Yonigida · Xtreme XFW-0053 (122ms)"
		fw := strings.TrimSpace(strings.TrimSpace(caps.FriendlyFork()) + " " + caps.FirmwareVersion)
		statusOK(fmt.Sprintf("Flipper connected: %s%s%s %s· %s%s %s(%s)%s",
			bold, caps.HardwareName, reset,
			dim, fw, reset,
			dim, elapsed, reset))
	}
	printConnectionReportVerbose(report)
	if !caps.HasNFCSubshell {
		statusWarn(fmt.Sprintf("NFC CLI not available on %s firmware — NFC-detect/emulate tools will error with a hint", caps.FriendlyFork()))
	}

	// Apply the pipeline profile FIRST so per-op timeout overrides below
	// can still narrow the deadline. SetPipeline normalises empty/unknown
	// names to "balanced", which matches today's hard-coded behaviour
	// byte-for-byte — so configs that never set a profile see no drift.
	flip.SetPipeline(flipper.PipelineProfile(cfg.Flipper.Pipeline))

	// Apply configurable per-operation timeouts. Zero values in the config
	// leave the flip defaults (10 s) in place.
	if cfg.Flipper.ExecTimeout > 0 {
		flip.SetExecTimeout(cfg.Flipper.ExecTimeout)
	}
	if cfg.Flipper.WriteFileTimeout > 0 {
		flip.SetWriteFileTimeout(cfg.Flipper.WriteFileTimeout)
	}

	return flip, func() { flip.Close() }, nil
}

// printConnectionReportVerbose dumps every connection check to stderr in
// "[LEVEL] name (Xms): detail" form when verbose logging is on.
//
// Trigger: PROMPTZERO_LOG_LEVEL=debug or PROMPTZERO_VERBOSE_CONNECT=1.
// Default UX (single-line connect status) is unchanged — the verbose
// dump is additive and silent unless explicitly enabled.
func printConnectionReportVerbose(report *flipper.ConnectionReport) {
	if report == nil {
		return
	}
	if !verboseConnectEnabled() {
		return
	}
	for _, c := range report.Checks() {
		tag := strings.ToUpper(string(c.Level))
		var colour string
		switch c.Level {
		case flipper.LevelPass:
			colour = green
		case flipper.LevelWarn:
			colour = yellow
		case flipper.LevelFail:
			colour = red
		default:
			colour = dim
		}
		ms := c.Elapsed.Round(time.Millisecond)
		line := fmt.Sprintf("    %s[%s]%s %s%s%s (%s): %s",
			colour, tag, reset,
			bold, c.Name, reset,
			ms, c.Detail)
		fmt.Fprintln(os.Stderr, line)
	}
}

// verboseConnectEnabled reports whether the operator opted into the
// per-check connection-report dump. Either knob flips it on so existing
// PROMPTZERO_LOG_LEVEL=debug operators get it for free, while a future
// --verbose flag can route through PROMPTZERO_VERBOSE_CONNECT.
func verboseConnectEnabled() bool {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("PROMPTZERO_LOG_LEVEL"))); v == "debug" {
		return true
	}
	if v := strings.TrimSpace(os.Getenv("PROMPTZERO_VERBOSE_CONNECT")); v != "" && v != "0" && strings.ToLower(v) != "false" {
		return true
	}
	return false
}

// setupMetrics builds the Prometheus recorder when metrics are enabled.
// Returns nil when disabled; all Recorder methods are nil-safe so callers
// don't need to branch.
func setupMetrics(cfg *config.Config) *obs.Recorder {
	if !cfg.Observability.MetricsEnabled {
		return nil
	}
	rec := obs.NewRecorder()
	rec.SetFlipperConnected(true)
	return rec
}

// runMCPMode serves stdio MCP over the connected Flipper (and optional
// Marauder sidecar) until the server exits. Called early, before the
// agent is constructed — MCP has its own conversation model.
func runMCPMode(cfg *config.Config, flip *flipper.Flipper, wifiEnabled bool) error {
	var m *marauder.Marauder
	if wifiEnabled || cfg.Marauder.Enabled {
		m, _ = marauder.Connect(cfg.Marauder.Port, cfg.Marauder.BaudRate)
		if m != nil {
			defer m.Close()
		}
	}
	srv := mcp.NewServer(flip, m)
	statusOK("MCP server running on stdio")
	return srv.ServeStdio()
}

// --- Subsystem wiring ---------------------------------------------------

// setupCostTracker wires the cost tracker and its usage/stream-error
// callbacks onto the agent. The offline callback flips the Prometheus
// gauge and prints a banner when three stream errors land within 60s.
func setupCostTracker(cfg *config.Config, ai *agent.Agent, rec *obs.Recorder) *cost.Tracker {
	overrides := make(map[string]cost.Rate, len(cfg.Cost.Rates))
	for k, v := range cfg.Cost.Rates {
		overrides[k] = cost.Rate{InputPerMTok: v.Input, OutputPerMTok: v.Output}
	}
	tracker := cost.NewTracker(cost.NewPricer(overrides), cfg.Model, func(offline bool) {
		if rec != nil {
			rec.SetAnthropicReachable(!offline)
		}
		if offline {
			statusWarn("OFFLINE — Anthropic API unreachable (3 consecutive stream errors)")
		} else {
			statusOK("Back online — Anthropic API reachable")
		}
	})
	ai.SetUsageCallback(func(u agent.Usage) {
		tracker.AddUsageFull(u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheCreationTokens)
		if rec != nil {
			rec.RecordTokens("input", u.InputTokens)
			rec.RecordTokens("output", u.OutputTokens)
			rec.RecordTokens("cache_read", u.CacheReadTokens)
			rec.RecordTokens("cache_creation", u.CacheCreationTokens)
		}
	})
	ai.SetStreamErrorCallback(func(_ error) {
		tracker.RecordStreamError()
	})
	return tracker
}

// setupPersona loads built-in + user personas, picks the active one per
// --persona / config.persona / default, and applies it to the agent.
// Unknown names short-circuit the run so operators don't silently get the
// default when they asked for rf-recon.
func setupPersona(cfg *config.Config, personaName string, ai *agent.Agent) (*persona.Persona, *persona.Registry, error) {
	personas := persona.NewRegistry()
	if dir, dErr := persona.UserDir(); dErr == nil {
		if loadErr := personas.LoadDir(dir); loadErr != nil {
			statusWarn(fmt.Sprintf("Persona directory %s: %v", dir, loadErr))
		}
	}
	choice := cfg.Persona
	if personaName != "" {
		choice = personaName
	}
	if choice == "" {
		choice = "default"
	}
	active, ok := personas.Get(choice)
	if !ok {
		return nil, nil, fmt.Errorf("unknown persona %q; available: %s", choice, strings.Join(personas.Names(), ", "))
	}
	ai.SetPersona(active)
	scope := fmt.Sprintf("%d tools allowed", len(active.Tools))
	if active.IsUnrestricted() {
		scope = "all tools allowed"
	}
	statusOK(fmt.Sprintf("Persona %s%s%s %s· %s%s",
		bold, active.Name, reset,
		dim, scope, reset))
	return active, personas, nil
}

// setupRiskGate resolves the confirm-risk threshold from config + flags +
// persona default, applies it to the agent, and returns whether the gate
// is enabled. Persona default only kicks in when the operator has not
// asked for something specific — an absent override means "take the
// persona's opinion".
func setupRiskGate(cfg *config.Config, confirmRisk string, yolo bool, p *persona.Persona, ai *agent.Agent) bool {
	threshold, enabled, resolveErr := resolveConfirmRisk(cfg.ConfirmRisk, confirmRisk, yolo)
	if resolveErr != nil {
		statusWarn(resolveErr.Error())
	}
	if p.DefaultRiskThreshold != "" && cfg.ConfirmRisk == "" && confirmRisk == "" && !yolo {
		if pt, _, pErr := resolveConfirmRisk(p.DefaultRiskThreshold, "", false); pErr == nil {
			threshold, enabled = pt, true
		}
	}
	ai.SetConfirmThreshold(threshold)
	if enabled {
		statusOK(fmt.Sprintf("Risk gate %s(threshold: %s)%s — override with --confirm-risk on next launch", dim, threshold.String(), reset))
	} else {
		statusWarn("Risk gate disabled — destructive tools run without prompting")
	}
	return enabled
}

// setupMode resolves the operation mode from CLI flag + config (flag
// wins) and applies it to the agent. An empty string from both
// sources falls through to mode.ModeStandard, which is the
// behaviour-preserving default. Unknown values log a warning and
// fall back to Standard rather than aborting startup — operators
// who typo a mode shouldn't lose their whole session.
func setupMode(cfg *config.Config, modeFlag string, ai *agent.Agent) {
	raw := cfg.Mode
	if modeFlag != "" {
		raw = modeFlag
	}
	m, err := mode.ParseMode(raw)
	if err != nil {
		statusWarn(fmt.Sprintf("%v — falling back to standard", err))
		m = mode.ModeStandard
	}
	ai.SetMode(m)
	switch m {
	case mode.ModeStandard:
		// Default is silent — same banner real estate as today when
		// no operator action is needed.
	case mode.ModeAssault:
		statusWarn(fmt.Sprintf("Operation mode: %s — %s", m.DisplayName(), m.Description()))
	default:
		statusOK(fmt.Sprintf("Operation mode: %s%s%s %s· %s%s",
			bold, m.DisplayName(), reset,
			dim, m.Description(), reset))
	}
}

// setupSessionStore attaches the on-disk session store and honours
// --resume / --auto-resume. Auto-resume only picks up sessions touched
// within 24h; older ones require an explicit --resume.
func setupSessionStore(ai *agent.Agent, resumeID string, autoResume bool) {
	store, err := agent.DefaultSessionStore()
	if err != nil {
		statusWarn(fmt.Sprintf("Session persistence unavailable: %v", err))
		return
	}
	ai.SetSessionStore(store)
	statusOK(fmt.Sprintf("Sessions on-disk %s(id: %s)%s", dim, ai.SessionID(), reset))

	// Snapshot manager: rooted at ~/.promptzero/snapshots. Writes
	// through fileformat_edit capture the pre-write SD content so
	// /rewind can restore. Failure to resolve the root is a warning
	// (operator still gets the session but no undo), not a fatal.
	if root, rErr := snapshot.DefaultRoot(); rErr == nil {
		ai.SetSnapshotManager(snapshot.NewManager(root))
	} else {
		statusWarn(fmt.Sprintf("Snapshot manager unavailable: %v", rErr))
	}

	// Target memory: per-target facts persisted across sessions (Batch
	// B). DB open failure is a warning — the target_* tools become
	// inert but the rest of the agent still runs.
	if tmPath, tmErr := targetmem.DefaultPath(); tmErr == nil {
		if store, tmOpenErr := targetmem.Open(tmPath); tmOpenErr == nil {
			ai.SetTargetMemory(store)
		} else {
			statusWarn(fmt.Sprintf("Target memory unavailable: %v", tmOpenErr))
		}
	} else {
		statusWarn(fmt.Sprintf("Target memory path unresolved: %v", tmErr))
	}

	if resumeID != "" {
		if err := ai.ResumeSession(resumeID); err != nil {
			statusWarn(fmt.Sprintf("Resume %q failed: %v", resumeID, err))
		} else {
			statusOK(fmt.Sprintf("Resumed session %s%s%s", bold, resumeID, reset))
		}
		return
	}
	if !autoResume {
		return
	}
	sessions, err := ai.ListSessions()
	if err != nil || len(sessions) == 0 {
		return
	}
	latest := sessions[0]
	for _, s := range sessions[1:] {
		if s.UpdatedAt.After(latest.UpdatedAt) {
			latest = s
		}
	}
	if time.Since(latest.UpdatedAt) >= 24*time.Hour {
		return
	}
	if err := ai.ResumeSession(latest.ID); err != nil {
		statusWarn(fmt.Sprintf("Auto-resume failed: %v", err))
		return
	}
	statusOK(fmt.Sprintf("Auto-resumed session %s%s%s %s(updated %s ago)%s",
		bold, latest.ID, reset,
		dim, time.Since(latest.UpdatedAt).Round(time.Minute), reset))
}

// setupAuditLog opens the append-only audit DB under ~/.promptzero and
// attaches it to the agent. Returns nil on failure with a no-op cleanup
// so callers can defer unconditionally.
func setupAuditLog(ai *agent.Agent) (*audit.Log, func()) {
	dataDir := filepath.Join(os.Getenv("HOME"), ".promptzero")
	log, err := audit.Open(filepath.Join(dataDir, "audit.db"))
	if err != nil {
		statusWarn(fmt.Sprintf("Audit log unavailable: %v", err))
		return nil, func() {}
	}
	ai.SetAuditLog(log)
	statusOK(fmt.Sprintf("Audit logging %s(session: %s)%s", dim, log.SessionID(), reset))
	return log, func() { log.Close() }
}

// setupWebhooks builds the dispatcher from config. An empty subscriber
// list yields a no-op-ish dispatcher so downstream callback wiring stays
// branch-free.
//
// Each subscription URL is validated up-front via webhook.ValidateSubscription
// so misconfigured (loopback, RFC1918, cloud-metadata, non-http(s)) targets
// fail loudly at startup rather than leaking on the first event. Operators
// who legitimately want internal sinks can set
// PROMPTZERO_WEBHOOK_ALLOW_INTERNAL=1.
func setupWebhooks(cfg *config.Config) webhook.Dispatcher {
	var subs []webhook.Subscription
	for _, w := range cfg.Webhooks {
		evs := make([]webhook.Event, 0, len(w.Events))
		for _, e := range w.Events {
			evs = append(evs, webhook.Event(e))
		}
		sub := webhook.Subscription{
			Name:    w.Name,
			URL:     w.URL,
			Events:  evs,
			Headers: w.Headers,
			Secret:  w.Secret,
		}
		if err := webhook.ValidateSubscription(sub); err != nil {
			statusWarn(fmt.Sprintf("webhook subscription rejected: %v — skipping", err))
			continue
		}
		subs = append(subs, sub)
	}
	return webhook.New(subs)
}

// setupRules loads declarative rules from config and registers the audit
// observer that fans events out to the engine, the metrics recorder, and
// the webhook dispatcher on critical severity. Webhook-subscriber count
// is printed here to match the original banner order (after rules,
// before gen).
func setupRules(cfg *config.Config, wh webhook.Dispatcher, auditLog *audit.Log, rec *obs.Recorder) *rules.Engine {
	engine := rules.New(rules.Deps{
		WebhookFire: func(name string, payload map[string]any) {
			wh.Fire(webhook.Event(name), payload)
		},
	})
	for _, rc := range cfg.Rules {
		if rc.Enabled != nil && !*rc.Enabled {
			continue
		}
		r, parseErr := buildRule(rc)
		if parseErr != nil {
			statusWarn(fmt.Sprintf("rule %q: %v", rc.Name, parseErr))
			continue
		}
		engine.Register(r)
	}
	if n := len(engine.List()); n > 0 {
		statusOK(fmt.Sprintf("Reactive rules %s(%d loaded)%s", dim, n, reset))
	}
	if auditLog != nil {
		auditLog.AddObserver(func(e audit.Entry) {
			if rec != nil {
				rec.RecordAudit(e.Risk, string(e.Level))
			}
			engine.Handle(e)
			if e.Level == audit.LevelCritical {
				wh.Fire(webhook.EventAuditCritical, e)
			}
		})
	}
	if n := len(cfg.Webhooks); n > 0 {
		statusOK(fmt.Sprintf("Webhooks %s(%d subscriber%s)%s", dim, n, plural(n), reset))
	}
	return engine
}

// setupAttack wires the default MITRE ATT&CK index onto the agent so
// the runtime constraint filter (/attack REPL command) and the report
// generator can resolve tool-to-technique mappings. Pure metadata —
// no runtime cost unless an operator actively installs a constraint.
// Also installs the technique resolver on the audit log so every
// recorded entry carries the ATT&CK technique IDs for its tool
// (P1-07 audit path tracking).
func setupAttack(ai *agent.Agent, auditLog *audit.Log) {
	idx := attack.NewDefaultIndex()
	ai.SetAttackIndex(idx)
	if auditLog != nil {
		auditLog.SetTechniqueResolver(func(tool string) []string {
			return idx.TechniquesForTool(tool)
		})
	}
}

// setupDetectors installs the default DetectorEngine on the agent and
// registers the three built-in detectors (wifi_deauth / PMKID / NFC
// clone) with a JudgeFunc backed by the session's Anthropic client at
// the classification cost tier. Operators who don't want auto-
// detection can disable by passing a nil engine — but the default
// behaviour is to surface deceptive / suspicious tool results so the
// agent can react in its next turn.
func setupDetectors(client *anthropic.Client, ai *agent.Agent, cfg *config.Config) {
	judge := func(ctx context.Context, system, user string) (string, error) {
		resp, err := client.Messages.New(ctx, anthropic.MessageNewParams{
			Model:     anthropic.Model(ai.ModelFor(agent.TierClassify)),
			MaxTokens: 256,
			System:    []anthropic.TextBlockParam{{Text: system}},
			Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(user))},
		})
		if err != nil {
			return "", err
		}
		var raw string
		for _, b := range resp.Content {
			if b.Type == "text" {
				raw += b.Text
			}
		}
		return raw, nil
	}
	engine := rules.NewDetectorEngine(10 * time.Second).RegisterBuiltins(judge)
	ai.SetDetectorEngine(engine)
	statusOK(fmt.Sprintf("Detectors %s(wifi_deauth / pmkid / nfc-clone)%s", dim, reset))
	_ = cfg // reserved for future config-gated detectors
}

// setupMCPFederation parses cfg.MCPClients into typed mcpfed.ClientConfig
// entries, brings up a Federation, registers each remote tool as a Spec,
// and returns a cleanup closure for the deferred shutdown.
//
// A misconfigured client entry logs a warning but does not abort startup —
// federation is best-effort because the operator may have a half-tuned
// stack of external servers. A clean (no-op) close is returned when no
// mcp_clients section is present in the config.
func setupMCPFederation(ctx context.Context, cfg *config.Config) func() {
	noop := func() {}
	if len(cfg.MCPClients) == 0 {
		return noop
	}

	clients, err := mcpfed.ParseClientConfigs(cfg.MCPClients)
	if err != nil {
		statusWarn(fmt.Sprintf("MCP federation config: %v", err))
		// Continue with the entries that did parse cleanly — partial
		// success is more useful than aborting startup over one bad
		// entry.
	}
	if len(clients) == 0 {
		return noop
	}

	fed := mcpfed.New(mcpfed.Options{
		Logger: func(format string, args ...any) {
			statusOK(fmt.Sprintf("mcpfed: "+format, args...))
		},
	})
	if err := fed.Start(ctx, mcpfed.FederationConfig{Clients: clients}); err != nil {
		statusWarn(fmt.Sprintf("MCP federation start: %v", err))
		// Even on partial-failure, fed.Start may have brought some
		// clients up — don't tear them down.
	}

	prefixes := fed.Prefixes()
	statusOK(fmt.Sprintf("MCP federation %s(%d server%s: %s)%s",
		dim, len(prefixes), pluralS(len(prefixes)), strings.Join(prefixes, ", "), reset))

	return func() {
		if err := fed.Close(); err != nil {
			statusWarn(fmt.Sprintf("MCP federation close: %v", err))
		}
	}
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// setupGenerator picks the generation provider per --gen-provider,
// falling back to Claude when OpenRouter lacks a key. Wires it onto the
// agent as both the payload generator and the "gen LLM" used by REPL
// slash commands.
func setupGenerator(cfg *config.Config, ai *agent.Agent, flip *flipper.Flipper, client *anthropic.Client, genProvider, ollamaURL, ollamaModel string) provider.Provider {
	var genLLM provider.Provider
	switch genProvider {
	case "ollama":
		genLLM = provider.NewOllama(ollamaURL, ollamaModel)
	case "openrouter":
		key := os.Getenv("OPENROUTER_API_KEY")
		if key == "" {
			statusWarn("OPENROUTER_API_KEY not set, falling back to Claude")
		} else {
			genLLM = provider.NewOpenRouter(key, "")
		}
	}
	if genLLM == nil {
		genLLM = provider.NewClaude(client, cfg.Model)
	}
	ai.SetGenerator(generate.New(genLLM, flip))
	ai.SetGenLLM(genLLM)
	statusOK(fmt.Sprintf("Generation engine %s(%s)%s", dim, genLLM.Name(), reset))
	return genLLM
}

// validateMarauderFlags catches mutually-exclusive Marauder transport flags.
// --marauder-ble and --marauder-bridge cannot both be set: the first asks for
// a direct BLE link to a standalone devboard, the second asks for the Flipper
// to bridge USB-UART traffic to a stacked Marauder. Picking one means
// rejecting the other; surfacing the conflict at startup beats discovering
// halfway through the connect sequence that one path silently won.
func validateMarauderFlags(f *runFlags) error {
	if f.marauderBLEAddr != "" && f.marauderBridge {
		return fmt.Errorf("--marauder-ble and --marauder-bridge are mutually exclusive: pick one (BLE goes direct to a standalone devboard; bridge routes through the Flipper UART)")
	}
	return nil
}

// setupMarauder attempts to connect the ESP32 Marauder WiFi devboard
// when enabled. Returns (hasMarauder, cleanup). A failed connection is
// non-fatal — the operator can still drive the Flipper alone. When
// cfg.Marauder.Bridge is set, the Marauder is reached via the Flipper's
// USB-UART Bridge app (single-cable rig); otherwise the legacy
// separate-cable path is used.
func setupMarauder(ctx context.Context, cfg *config.Config, ai *agent.Agent, rec *obs.Recorder, flip *flipper.Flipper, wifiEnabled bool) (bool, func()) {
	if !wifiEnabled && !cfg.Marauder.Enabled {
		return false, func() {}
	}
	if cfg.Marauder.Bridge {
		return setupMarauderViaBridge(ctx, cfg, ai, flip, rec)
	}
	if strings.EqualFold(cfg.Marauder.Transport, "ble") {
		return setupMarauderViaBLE(ctx, cfg, ai, rec)
	}
	statusInfo(fmt.Sprintf("Connecting to Marauder on %s%s%s...", bold, cfg.Marauder.Port, reset))
	m, err := marauder.Connect(cfg.Marauder.Port, cfg.Marauder.BaudRate)
	if err != nil {
		statusWarn(fmt.Sprintf("Marauder unavailable: %v", err))
		return false, func() {}
	}
	ai.SetMarauder(m)
	if rec != nil {
		rec.SetMarauderConnected(true)
	}
	statusOK("Marauder WiFi devboard connected")
	return true, func() { m.Close() }
}

// setupMarauderViaBLE connects directly to a standalone ESP32-Marauder devboard
// over its native BLE serial GATT layout. This path bypasses the Flipper UART
// bridge entirely; no Flipper handle is touched, so the Flipper CLI (when
// connected over its own transport) keeps working unchanged.
//
// The connect ctx applies to the scan + GATT discovery phase only — once
// dialled, the BLE notifications drive Read independently of ctx.
func setupMarauderViaBLE(ctx context.Context, cfg *config.Config, ai *agent.Agent, rec *obs.Recorder) (bool, func()) {
	addr := cfg.Marauder.Port
	if addr == "" {
		statusWarn("Marauder BLE: address required (set marauder.port to a MAC/UUID/name or pass --marauder-ble <addr>)")
		return false, func() {}
	}
	statusInfo(fmt.Sprintf("Connecting to Marauder over BLE at %sble://%s%s...", bold, addr, reset))
	m, err := marauder.ConnectBLE(ctx, addr)
	if err != nil {
		statusWarn(fmt.Sprintf("Marauder BLE unavailable: %v", err))
		return false, func() {}
	}
	ai.SetMarauder(m)
	if rec != nil {
		rec.SetMarauderConnected(true)
	}
	statusOK(fmt.Sprintf("Marauder devboard connected over BLE at %sble://%s%s", bold, addr, reset))
	return true, func() { m.Close() }
}

// setupMarauderViaBridge launches the Flipper's USB-UART Bridge app and
// reopens the same serial port as a Marauder client. On success the
// passed *flipper.Flipper is suspended and all flipper_* CLI ops will
// return ErrFlipperSuspended until process exit (auto-resume is out of
// scope — see SPEC §8).
//
// Returns (true, cleanup) on success; (false, no-op) on failure.
// Failure is non-fatal — the operator gets a warning and the agent runs
// Flipper-only.
func setupMarauderViaBridge(ctx context.Context, cfg *config.Config, ai *agent.Agent, flip *flipper.Flipper, rec *obs.Recorder) (bool, func()) {
	if flip == nil {
		statusWarn("Marauder bridge requires a connected Flipper — connect Flipper first or remove --marauder-bridge")
		return false, func() {}
	}
	if flip.IsSuspended() {
		statusWarn("Flipper already suspended — refusing to re-run bridge setup")
		return false, func() {}
	}
	// Hybrid (BLE Flipper + USB-bridged Marauder) needs an explicit
	// Marauder USB device — the Flipper isn't on USB so cfg.Serial.Port
	// is irrelevant. Single-cable still uses cfg.Serial.Port.
	hybrid := false
	port := cfg.Serial.Port
	if t := flip.Transport(); t != nil && t.Kind() == "ble" {
		hybrid = true
		if cfg.Marauder.Port == "" {
			statusWarn("Hybrid bridge mode requires --marauder-port (Flipper is on BLE; Marauder USB device path must be set explicitly)")
			return false, func() {}
		}
		port = cfg.Marauder.Port
	}
	statusInfo(fmt.Sprintf("Launching Flipper USB-UART Bridge for Marauder on %s%s%s...", bold, port, reset))
	m, err := marauder.ConnectViaFlipper(
		ctx,
		flip,
		port,
		cfg.Marauder.BaudRate,
		cfg.Marauder.BridgeCommand,
		cfg.Marauder.BridgeSettle,
		cfg.Marauder.BridgePortReopenTimeout,
	)
	if err != nil {
		statusWarn(fmt.Sprintf("Marauder bridge: %v", err))
		return false, func() {}
	}
	ai.SetMarauder(m)
	if rec != nil {
		rec.SetMarauderConnected(true)
		if !hybrid {
			rec.SetFlipperConnected(false) // CLI is gone for the rest of the session
		}
	}
	if hybrid {
		statusOK(fmt.Sprintf("Marauder via Flipper UART bridge on %s (Flipper CLI on BLE — both active)", port))
	} else {
		statusOK(fmt.Sprintf("Marauder via Flipper UART bridge on %s (Flipper CLI suspended)", port))
		statusWarn("flipper_* tools disabled while UART bridge is active")
	}
	return true, func() { m.Close() }
}

// probeMarauderFirmware runs the `info` command and updates the web
// server's marauder.firmware status field. Intended to be called in a
// goroutine — the probe blocks the serial port for ~100ms, which is too
// slow to inline in the connect path. Failures are silent; the firmware
// pill simply stays empty when the probe times out or returns garbage.
func probeMarauderFirmware(m *marauder.Marauder, srv *web.Server, port string) {
	out, err := m.Exec("info", 2*time.Second)
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "version:"); ok {
			if fw := strings.TrimSpace(rest); fw != "" {
				srv.SetMarauderInfo(port, fw)
				return
			}
		}
	}
}

// setupBruce attempts to connect a Bruce ESP32 devboard when the
// operator has configured one. Failure is non-fatal — the agent runs
// without Bruce and bruce_* Specs return a "not connected" error.
func setupBruce(ctx context.Context, cfg *config.Config, ai *agent.Agent) (bool, func()) {
	if cfg.Bruce.Port == "" {
		return false, func() {}
	}
	baud := cfg.Bruce.Baud
	if baud == 0 {
		baud = 115200
	}
	statusInfo(fmt.Sprintf("Connecting to Bruce on %s%s%s...", bold, cfg.Bruce.Port, reset))
	c, err := bruce.Connect(ctx, cfg.Bruce.Port, baud)
	if err != nil {
		statusWarn(fmt.Sprintf("Bruce unavailable: %v", err))
		return false, func() {}
	}
	ai.SetBruce(c)
	statusOK(fmt.Sprintf("Bruce ESP32 backend %s(board: %s)%s", dim, cfg.Bruce.BoardType, reset))
	return true, func() { _ = c.Close() }
}

// setupFaultier attempts to connect a hextreeio Faultier USB voltage-
// glitcher. Failure is non-fatal.
func setupFaultier(cfg *config.Config, ai *agent.Agent) (bool, func()) {
	if cfg.Faultier.Port == "" {
		return false, func() {}
	}
	baud := cfg.Faultier.Baud
	if baud == 0 {
		baud = 115200
	}
	statusInfo(fmt.Sprintf("Connecting to Faultier on %s%s%s...", bold, cfg.Faultier.Port, reset))
	c, err := faultier.Connect(cfg.Faultier.Port, baud)
	if err != nil {
		statusWarn(fmt.Sprintf("Faultier unavailable: %v", err))
		return false, func() {}
	}
	ai.SetFaultier(c)
	statusOK("Faultier voltage-glitcher connected")
	return true, func() { _ = c.Close() }
}

// setupBusPirate attempts to connect a Bus Pirate 5 universal-bus probe.
// Failure is non-fatal.
func setupBusPirate(ctx context.Context, cfg *config.Config, ai *agent.Agent) (bool, func()) {
	if cfg.BusPirate.Port == "" {
		return false, func() {}
	}
	baud := cfg.BusPirate.Baud
	if baud == 0 {
		baud = 115200
	}
	statusInfo(fmt.Sprintf("Connecting to Bus Pirate 5 on %s%s%s...", bold, cfg.BusPirate.Port, reset))
	c, err := buspirate.Connect(ctx, cfg.BusPirate.Port, baud)
	if err != nil {
		statusWarn(fmt.Sprintf("Bus Pirate unavailable: %v", err))
		return false, func() {}
	}
	ai.SetBusPirate(c)
	statusOK("Bus Pirate 5 universal-bus probe connected")
	return true, func() { _ = c.Close() }
}

// setupVoice constructs the Whisper-backed voice engine when the
// OpenAI key is present. Returns nil when absent — the CLI still runs,
// just without voice input.
func setupVoice(cfg *config.Config) *voice.Engine {
	if cfg.OpenAIKey == "" {
		return nil
	}
	e := voice.New(cfg.OpenAIKey)
	statusOK(fmt.Sprintf("Voice engine %s(Whisper)%s", dim, reset))
	return e
}

// printCapabilitySummary emits the "N tools loaded — Flipper · …" banner
// that tops the REPL. Shown once, right before the REPL starts or the
// web server binds. flipperSuspended drives the red "(suspended)"
// Flipper pill (single-cable bridge); bridgeMarauder drives the magenta
// "(bridge)" Marauder pill. Hybrid mode (BLE Flipper + USB Marauder) is
// flipperSuspended=false, bridgeMarauder=true — Flipper stays green
// because the CLI is still reachable over BLE.
func printCapabilitySummary(hasMarauder, hasVoice, bridgeMarauder, flipperSuspended bool) {
	printSeparator()

	tools := len(agent.ToolNames(hasMarauder))
	fmt.Fprintf(os.Stderr, "  %s%s%d tools%s loaded", bold, white, tools, reset)

	flipperPill := fmt.Sprintf("%sFlipper%s", green, reset)
	if flipperSuspended {
		flipperPill = fmt.Sprintf("%sFlipper (suspended)%s", red, reset)
	}
	features := []string{flipperPill}
	if hasMarauder {
		marauderPill := fmt.Sprintf("%sMarauder%s", cyan, reset)
		if bridgeMarauder {
			marauderPill = fmt.Sprintf("%sMarauder (bridge)%s", magenta, reset)
		}
		features = append(features, marauderPill)
	}
	features = append(features, fmt.Sprintf("%sGenerate%s", magenta, reset))
	if hasVoice {
		features = append(features, fmt.Sprintf("%sVoice%s", yellow, reset))
	}
	fmt.Fprintf(os.Stderr, " — %s\n", strings.Join(features, " · "))

	printSeparator()
	fmt.Fprintf(os.Stderr, "\n")
}

// --- Session lifecycle events -------------------------------------------

// fireSessionStarted publishes the session_started lifecycle event to
// the webhook dispatcher. Safe to call when no subscribers are
// configured — the dispatcher is a no-op in that case.
func fireSessionStarted(cfg *config.Config, auditLog *audit.Log, wh webhook.Dispatcher) {
	payload := map[string]any{
		"session_id": sessionIDOf(auditLog),
		"started_at": time.Now().UTC(),
		"model":      cfg.Model,
	}
	wh.Fire(webhook.EventSessionStarted, payload)
}

// fireSessionEnded publishes the session_ended lifecycle event and then
// drains the webhook dispatcher with a 5s shutdown deadline. Call as the
// very last defer before the flipper/audit closes so in-flight tool
// events get delivered before teardown.
func fireSessionEnded(auditLog *audit.Log, wh webhook.Dispatcher) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	payload := map[string]any{
		"session_id": sessionIDOf(auditLog),
		"ended_at":   time.Now().UTC(),
	}
	wh.Fire(webhook.EventSessionEnded, payload)
	_ = wh.Close(shutdownCtx)
}

// sessionIDOf returns the audit log's session ID when available, or an
// empty string when the audit log failed to open.
func sessionIDOf(log *audit.Log) string {
	if log == nil {
		return ""
	}
	return log.SessionID()
}

// --- Web mode ------------------------------------------------------------

// WebDeps bundles every subsystem the HTTP UI can surface. Each field is
// optional — panels in the cockpit hide cleanly when their backing
// subsystem is nil, matching the REPL's behaviour. Passed through from
// run() so the web mode doesn't need to reach back into the deps graph.
type WebDeps struct {
	Ai             *agent.Agent
	Voice          *voice.Engine
	Rec            *obs.Recorder
	Personas       *persona.Registry
	CostTracker    *cost.Tracker
	RulesEngine    *rules.Engine
	Flipper        *flipper.Flipper
	FlipperOnline  bool
	MarauderOnline bool
}

// runWebMode binds the HTTP UI on the configured address and serves
// until the context is cancelled. web.NewServer warns internally when
// the bind is non-loopback; we re-read srv.Addr() so the status line
// matches the effective bind.
func runWebMode(ctx context.Context, sh *signalHandler, cfg *config.Config, deps WebDeps) error {
	addr := fmt.Sprintf("%s:%d", cfg.Web.Host, cfg.Web.Port)
	srv := web.NewServer(addr, deps.Ai, deps.Voice)
	srv.SetMetrics(deps.Rec, cfg.Observability.MetricsPath)
	srv.SetAuthToken(cfg.Web.Token)
	srv.SetCORSOrigins(cfg.Web.CORSOrigins)
	srv.SetAllowAnyOrigin(cfg.Web.AllowAnyOrigin)
	srv.SetAllowUnauthedPublic(cfg.Web.AllowUnauthedPublic)
	if cfg.Web.Token != "" {
		statusOK(fmt.Sprintf("Web auth %s(bearer token, %d chars)%s", dim, len(cfg.Web.Token), reset))
	} else {
		statusWarn("Web auth disabled — set web.token or PROMPTZERO_WEB_TOKEN")
	}
	// Wire the Phase-14 panel surface. Flipper may be nil when the
	// operator launched --web without a device attached; Marauder and
	// the others are independently optional. Panels guard on their own
	// nil deps and render an offline state when the backing facility
	// isn't wired.
	if deps.Personas != nil {
		srv.SetPersonaRegistry(deps.Personas)
	}
	if deps.CostTracker != nil {
		srv.SetCostTracker(deps.CostTracker)
	}
	if deps.RulesEngine != nil {
		srv.SetRulesEngine(deps.RulesEngine)
	}
	if deps.Flipper != nil {
		srv.SetFlipper(deps.Flipper)
	}
	// Wire the Marauder client into the synth-panel WS handler. The agent
	// already holds the live client (set by setupMarauder / setupMarauderViaBridge);
	// we plug the same instance into the web server so the Marauder TFT panel
	// can drive Exec / Stream without going through agent tool-use.
	if m := deps.Ai.Marauder(); m != nil {
		srv.SetMarauder(m)
	}
	// Always wire the session driver — *agent.Agent.SessionID returns an
	// empty string until SetSessionStore runs, so the API layer simply
	// reports an empty list when persistence is unavailable.
	srv.SetSessionDriver(deps.Ai)
	// Forward web UI navigation state into the agent so buildUIContextBlock
	// can inject it as a turn prefix (same pipeline as device-state oracle).
	srv.OnUIContext(func(view, path string) {
		deps.Ai.SetUIContext(view, path)
	})
	srv.SetFlipperConnected(deps.FlipperOnline)
	srv.SetMarauderConnected(deps.MarauderOnline)
	if deps.MarauderOnline {
		srv.SetMarauderInfo(cfg.Marauder.Port, "")
		if m := deps.Ai.Marauder(); m != nil {
			go probeMarauderFirmware(m, srv, cfg.Marauder.Port)
		}
	}
	statusOK(fmt.Sprintf("Web UI at %s%shttp://%s%s", bold, cyan, srv.Addr(), reset))
	if deps.Rec != nil {
		path := cfg.Observability.MetricsPath
		if path == "" {
			path = "/metrics"
		}
		statusOK(fmt.Sprintf("Metrics at %shttp://%s%s%s", cyan, srv.Addr(), path, reset))
	}
	fmt.Fprintf(os.Stderr, "\n")
	webCtx, releaseWeb := sh.withCancel(ctx)
	defer releaseWeb()
	return srv.Start(webCtx)
}
