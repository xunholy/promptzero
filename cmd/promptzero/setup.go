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
	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/cost"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/generate"
	"github.com/xunholy/promptzero/internal/marauder"
	"github.com/xunholy/promptzero/internal/mcp"
	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/persona"
	"github.com/xunholy/promptzero/internal/provider"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/rules"
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
	fmt.Fprintln(os.Stderr, "    2. Set ANTHROPIC_API_KEY (required) — export it or add api_key to the config")
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
  port: "/dev/ttyUSB0"    # Usually a separate USB serial port
  baud_rate: 115200

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
	yoloMode             bool
	confirmRisk          string
	personaName          string
	watchPaths           stringSlice
}

// parseFlags binds all CLI flags and calls flag.Parse. Returns the
// populated struct.
func parseFlags() *runFlags {
	f := &runFlags{}
	flag.StringVar(&f.cfgPath, "config", "config.yaml", "Path to config file")
	flag.StringVar(&f.portOverride, "port", "", "Flipper serial port (overrides config; e.g., /dev/ttyACM1 for a second device)")
	flag.StringVar(&f.transportOverride, "transport", "", "Flipper transport URL (overrides --port + config). Schemes: serial:// (USB), mock:// (tests), ble:// (reserved; Phase-B)")
	flag.BoolVar(&f.webMode, "web", false, "Start web UI mode")
	flag.IntVar(&f.webPort, "web-port", 0, "Web server port (overrides config)")
	flag.BoolVar(&f.voiceMode, "voice", false, "Enable voice input (requires sox + OPENAI_API_KEY)")
	flag.BoolVar(&f.wifiEnabled, "wifi", false, "Connect to ESP32 Marauder WiFi devboard")
	flag.StringVar(&f.marauderPortOverride, "marauder-port", "", "Marauder serial port (overrides config; e.g. /dev/ttyUSB0 for CP210x-bridged Marauders, /dev/ttyACM1 for ESP32-S2 native USB)")
	flag.BoolVar(&f.mcpMode, "mcp", false, "Run as MCP server (stdin/stdout)")
	flag.BoolVar(&f.doInit, "init", false, "Scaffold ~/.promptzero/config.yaml and exit")
	flag.StringVar(&f.resumeID, "resume", "", "Resume a saved session by id")
	flag.BoolVar(&f.autoResume, "auto-resume", false, "Auto-resume the most recent session if it's less than 24h old")
	flag.StringVar(&f.genProvider, "gen-provider", "claude", "LLM provider for payload generation: claude, ollama, openrouter")
	flag.StringVar(&f.ollamaURL, "ollama-url", "http://localhost:11434", "Ollama server URL")
	flag.StringVar(&f.ollamaModel, "ollama-model", "llama3.1", "Ollama model for generation")
	flag.DurationVar(&f.connectTimeout, "connect-timeout", 10*time.Second, "Max time to wait for Flipper CLI prompt (Ctrl+C cancels sooner)")
	flag.BoolVar(&f.yoloMode, "yolo", false, "Skip risk confirmations (shorthand for --confirm-risk=none)")
	flag.StringVar(&f.confirmRisk, "confirm-risk", "", "Confirmation threshold: none|low|medium|high|critical (default: high)")
	flag.StringVar(&f.personaName, "persona", "", "Operator persona (default: value from config or 'default')")
	flag.Var(&f.watchPaths, "watch", "Watch a directory for FS events; repeat to watch several")
	flag.BoolVar(&f.showVersion, "version", false, "Show version")
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
	flip, err := flipper.ConnectURL(connectCtx, transportURL, connectTimeout)
	releaseConnect()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			statusWarn("Flipper connection cancelled")
			return nil, func() {}, err
		}
		statusErr(fmt.Sprintf("Flipper connection failed: %v", err))
		return nil, func() {}, fmt.Errorf("flipper: %w", err)
	}

	caps, capsErr := flip.DetectCapabilities()
	elapsed := time.Since(start).Round(time.Millisecond)
	if capsErr != nil || caps.HardwareName == "" {
		statusOK(fmt.Sprintf("Flipper connected %s(%s)%s", dim, elapsed, reset))
	} else {
		// Example: "Flipper connected: Yonigida · Xtreme XFW-0053 (122ms)"
		fw := strings.TrimSpace(strings.TrimSpace(caps.FriendlyFork()) + " " + caps.FirmwareVersion)
		statusOK(fmt.Sprintf("Flipper connected: %s%s%s %s· %s%s %s(%s)%s",
			bold, caps.HardwareName, reset,
			dim, fw, reset,
			dim, elapsed, reset))
	}
	if !caps.HasNFCSubshell {
		statusWarn(fmt.Sprintf("NFC CLI not available on %s firmware — NFC-detect/emulate tools will error with a hint", caps.FriendlyFork()))
	}

	return flip, func() { flip.Close() }, nil
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
	ai.SetUsageCallback(func(in, out int64) {
		tracker.AddUsage(in, out)
		if rec != nil {
			rec.RecordTokens("input", in)
			rec.RecordTokens("output", out)
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
	statusOK(fmt.Sprintf("Persona %s%s%s %s· %d tools allowed%s",
		bold, active.Name, reset,
		dim, len(active.Tools), reset))
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
		statusOK(fmt.Sprintf("Risk gate %s(threshold: %s)%s", dim, threshold.String(), reset))
	} else {
		statusWarn("Risk gate disabled — destructive tools run without prompting")
	}
	return enabled
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
func setupWebhooks(cfg *config.Config) webhook.Dispatcher {
	var subs []webhook.Subscription
	for _, w := range cfg.Webhooks {
		evs := make([]webhook.Event, 0, len(w.Events))
		for _, e := range w.Events {
			evs = append(evs, webhook.Event(e))
		}
		subs = append(subs, webhook.Subscription{
			Name:    w.Name,
			URL:     w.URL,
			Events:  evs,
			Headers: w.Headers,
			Secret:  w.Secret,
		})
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

// setupMarauder attempts to connect the ESP32 Marauder WiFi devboard
// when enabled. Returns (hasMarauder, cleanup). A failed connection is
// non-fatal — the operator can still drive the Flipper alone.
func setupMarauder(cfg *config.Config, ai *agent.Agent, rec *obs.Recorder, wifiEnabled bool) (bool, func()) {
	if !wifiEnabled && !cfg.Marauder.Enabled {
		return false, func() {}
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
// web server binds.
func printCapabilitySummary(hasMarauder, hasVoice bool) {
	printSeparator()

	tools := len(agent.ToolNames(hasMarauder))
	fmt.Fprintf(os.Stderr, "  %s%s%d tools%s loaded", bold, white, tools, reset)
	features := []string{fmt.Sprintf("%sFlipper%s", green, reset)}
	if hasMarauder {
		features = append(features, fmt.Sprintf("%sMarauder%s", cyan, reset))
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
	if cfg.Web.Token != "" {
		statusOK(fmt.Sprintf("Web auth %s(bearer token, %d chars)%s", dim, len(cfg.Web.Token), reset))
	} else {
		statusWarn("Web auth disabled — set web.token or PROMPTZERO_WEB_TOKEN")
	}
	// Wire the Phase-14 panel surface. Flipper is always connected here
	// (run() bailed earlier if the serial connect failed); Marauder and
	// the others may be nil, and the panels handle that.
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
	srv.SetFlipperConnected(true)
	srv.SetMarauderConnected(deps.MarauderOnline)
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
