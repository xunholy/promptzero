package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
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
	"github.com/xunholy/promptzero/internal/mqtt"
	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/persona"
	"github.com/xunholy/promptzero/internal/provider"
	"github.com/xunholy/promptzero/internal/rules"
	"github.com/xunholy/promptzero/internal/version"
	"github.com/xunholy/promptzero/internal/voice"
	"github.com/xunholy/promptzero/internal/web"
	"github.com/xunholy/promptzero/internal/webhook"
)

// stringSlice is a flag.Value that collects repeated string flags into a
// slice — used by --watch so operators can aim multiple paths at one
// invocation without quoting a comma-separated list.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

// configTemplate is written by --init when no user config exists. Kept in
// sync with config.example.yaml by hand; embedding the repo file isn't
// possible because //go:embed only accepts paths at or below this package.
const configTemplate = `# promptzero configuration

# Anthropic API key (or set ANTHROPIC_API_KEY env var)
api_key: ""

# OpenAI API key for Whisper voice transcription (or set OPENAI_API_KEY env var)
openai_api_key: ""

# Claude model to use
model: "claude-sonnet-4-6"

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

func main() {
	if err := run(); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "\n  %scancelled.%s\n\n", dim, reset)
			return
		}
		fmt.Fprintf(os.Stderr, "\n  %s%serror: %v%s\n\n", bold, red, err, reset)
		os.Exit(1)
	}
}

func run() error {
	var (
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
	)

	flag.StringVar(&cfgPath, "config", "config.yaml", "Path to config file")
	flag.StringVar(&portOverride, "port", "", "Flipper serial port (overrides config; e.g., /dev/ttyACM1 for a second device)")
	flag.StringVar(&transportOverride, "transport", "", "Flipper transport URL (overrides --port + config). Schemes: serial:// (USB), mock:// (tests), ble:// (reserved; Phase-B)")
	flag.BoolVar(&webMode, "web", false, "Start web UI mode")
	flag.IntVar(&webPort, "web-port", 0, "Web server port (overrides config)")
	flag.BoolVar(&voiceMode, "voice", false, "Enable voice input (requires sox + OPENAI_API_KEY)")
	flag.BoolVar(&wifiEnabled, "wifi", false, "Connect to ESP32 Marauder WiFi devboard")
	flag.StringVar(&marauderPortOverride, "marauder-port", "", "Marauder serial port (overrides config; e.g. /dev/ttyUSB0 for CP210x-bridged Marauders, /dev/ttyACM1 for ESP32-S2 native USB)")
	flag.BoolVar(&mcpMode, "mcp", false, "Run as MCP server (stdin/stdout)")
	flag.BoolVar(&doInit, "init", false, "Scaffold ~/.promptzero/config.yaml and exit")
	flag.StringVar(&resumeID, "resume", "", "Resume a saved session by id")
	flag.BoolVar(&autoResume, "auto-resume", false, "Auto-resume the most recent session if it's less than 24h old")
	flag.StringVar(&genProvider, "gen-provider", "claude", "LLM provider for payload generation: claude, ollama, openrouter")
	flag.StringVar(&ollamaURL, "ollama-url", "http://localhost:11434", "Ollama server URL")
	flag.StringVar(&ollamaModel, "ollama-model", "llama3.1", "Ollama model for generation")
	flag.DurationVar(&connectTimeout, "connect-timeout", 10*time.Second, "Max time to wait for Flipper CLI prompt (Ctrl+C cancels sooner)")
	flag.BoolVar(&yoloMode, "yolo", false, "Skip risk confirmations (shorthand for --confirm-risk=none)")
	flag.StringVar(&confirmRisk, "confirm-risk", "", "Confirmation threshold: none|low|medium|high|critical (default: high)")
	flag.StringVar(&personaName, "persona", "", "Operator persona (default: value from config or 'default')")
	flag.Var(&watchPaths, "watch", "Watch a directory for FS events; repeat to watch several")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.Parse()

	if showVersion {
		fmt.Printf("promptzero %s\n", version.String())
		return nil
	}

	if doInit {
		return runInit()
	}

	// First-run UX: no config anywhere and no API key env var? Print an
	// onboarding hint and exit cleanly so this doesn't look like a crash.
	if p := os.Getenv("PROMPTZERO_CONFIG"); p != "" {
		cfgPath = p
	}
	if isFirstRun(cfgPath) {
		printFirstRunHint()
		return nil
	}

	// --- Signal handling ---
	// We intercept SIGINT ourselves so the first press cancels the currently
	// in-flight operation (connect, API call, tool run) and a second press
	// within 2s exits hard — same feel as Claude Code / modern CLIs.
	sh := &signalHandler{}
	defer sh.install()()
	ctx := context.Background()

	// --- Banner ---
	if !mcpMode {
		printBanner()
		printSeparator()
	}

	// --- Config ---
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	if webPort > 0 {
		cfg.Web.Port = webPort
	}
	if portOverride != "" {
		cfg.Serial.Port = portOverride
	}
	// --transport beats both --port and the config serial block. An
	// empty override leaves the existing TransportURL from the config
	// file in place; empty-after-merge falls back to the serial URL
	// constructed from Port + BaudRate (see the Connect call below).
	if transportOverride != "" {
		cfg.Serial.TransportURL = transportOverride
	}
	if marauderPortOverride != "" {
		cfg.Marauder.Port = marauderPortOverride
	}

	// --- Structured logging ---
	// Install the slog handler first so every subsequent subsystem (flipper,
	// audit, agent) shares a configured default. Env PROMPTZERO_LOG_LEVEL is
	// an additional operator-only override: it beats the config file so a
	// debug-level spike does not need a config edit.
	if lvl := os.Getenv("PROMPTZERO_LOG_LEVEL"); lvl != "" {
		cfg.Observability.LogLevel = lvl
	}
	obs.Setup(obs.LogConfig{
		Level:  cfg.Observability.LogLevel,
		Format: cfg.Observability.LogFormat,
		File:   cfg.Observability.LogFile,
	})

	// Multi-Flipper sanity check: if several ACM-class serial devices are
	// present and the user didn't pin a specific one via --port, warn so a
	// surprising device doesn't get driven blindly. Skipped when the
	// transport URL is non-default (mock://, ble://) because the user
	// has explicitly opted out of ACM discovery.
	if portOverride == "" && cfg.Serial.TransportURL == "" && strings.HasPrefix(cfg.Serial.Port, "/dev/ttyACM") {
		if matches, _ := filepath.Glob("/dev/ttyACM*"); len(matches) > 1 {
			statusWarn(fmt.Sprintf("Multiple Flipper-class serial devices detected (%s) — using configured port; use --port to target a specific device.",
				strings.Join(matches, ", ")))
		}
	}

	// --- Connect to Flipper ---
	// TransportURL wins if set (by --transport or config); otherwise we
	// fall back to the legacy path + baud pair so existing config
	// files and the default behaviour are preserved.
	transportURL := cfg.Serial.TransportURL
	if transportURL == "" {
		transportURL = fmt.Sprintf("serial://%s?baud=%d", cfg.Serial.Port, cfg.Serial.BaudRate)
	}
	statusInfo(fmt.Sprintf("Connecting to Flipper Zero on %s%s%s... %s(timeout %s, press Ctrl+C to cancel)%s", bold, transportURL, reset, dim, connectTimeout, reset))
	start := time.Now()
	connectCtx, releaseConnect := sh.withCancel(ctx)
	flip, err := flipper.ConnectURL(connectCtx, transportURL, connectTimeout)
	releaseConnect()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			statusWarn("Flipper connection cancelled")
			return err
		}
		statusErr(fmt.Sprintf("Flipper connection failed: %v", err))
		return fmt.Errorf("flipper: %w", err)
	}
	defer flip.Close()

	// --- Metrics recorder ---
	// Built before any subsystem so connect-time gauges and audit observers
	// can feed it without nil-checks (Recorder methods are nil-safe, but we
	// want the early state changes captured when enabled).
	var rec *obs.Recorder
	if cfg.Observability.MetricsEnabled {
		rec = obs.NewRecorder()
		rec.SetFlipperConnected(true)
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
	// Inform the user (and the agent) about any firmware-specific CLI gaps.
	if !caps.HasNFCSubshell {
		statusWarn(fmt.Sprintf("NFC CLI not available on %s firmware — NFC-detect/emulate tools will error with a hint", caps.FriendlyFork()))
	}

	// --- MCP mode ---
	if mcpMode {
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

	// --- Claude agent ---
	client := anthropic.NewClient()
	ai := agent.New(&client, flip, cfg)
	statusOK(fmt.Sprintf("Agent ready %s(model: %s)%s", dim, cfg.Model, reset))

	// --- Cost tracker + offline detection ---
	// The tracker accumulates token usage per stream response and trips the
	// offline banner after three consecutive stream errors <60s apart.
	overrides := make(map[string]cost.Rate, len(cfg.Cost.Rates))
	for k, v := range cfg.Cost.Rates {
		overrides[k] = cost.Rate{InputPerMTok: v.Input, OutputPerMTok: v.Output}
	}
	costTracker := cost.NewTracker(cost.NewPricer(overrides), cfg.Model, func(offline bool) {
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
		costTracker.AddUsage(in, out)
		if rec != nil {
			rec.RecordTokens("input", in)
			rec.RecordTokens("output", out)
		}
	})
	ai.SetStreamErrorCallback(func(_ error) {
		costTracker.RecordStreamError()
	})

	// --- Persona registry ---
	// Built-ins plus any user YAML in ~/.promptzero/personas. --persona wins
	// over config.persona. Unknown names short-circuit the run so the operator
	// doesn't silently get the default when they asked for rf-recon.
	personas := persona.NewRegistry()
	if dir, dErr := persona.UserDir(); dErr == nil {
		if loadErr := personas.LoadDir(dir); loadErr != nil {
			statusWarn(fmt.Sprintf("Persona directory %s: %v", dir, loadErr))
		}
	}
	personaChoice := cfg.Persona
	if personaName != "" {
		personaChoice = personaName
	}
	if personaChoice == "" {
		personaChoice = "default"
	}
	activePersona, ok := personas.Get(personaChoice)
	if !ok {
		return fmt.Errorf("unknown persona %q; available: %s", personaChoice, strings.Join(personas.Names(), ", "))
	}
	ai.SetPersona(activePersona)
	statusOK(fmt.Sprintf("Persona %s%s%s %s· %d tools allowed%s",
		bold, activePersona.Name, reset,
		dim, len(activePersona.Tools), reset))

	// --- Risk confirmation threshold ---
	// Flags override config; --yolo is shorthand for --confirm-risk=none.
	// Callback registration happens later (interactive REPL only); MCP/web
	// paths keep confirmCb nil so tools execute without prompting.
	threshold, gateEnabled, resolveErr := resolveConfirmRisk(cfg.ConfirmRisk, confirmRisk, yoloMode)
	if resolveErr != nil {
		statusWarn(resolveErr.Error())
	}
	// Persona default threshold kicks in only when the operator has not asked
	// for something specific via flag/config/yolo — we treat an absent
	// override as "take the persona's opinion".
	if activePersona.DefaultRiskThreshold != "" && cfg.ConfirmRisk == "" && confirmRisk == "" && !yoloMode {
		if pt, _, pErr := resolveConfirmRisk(activePersona.DefaultRiskThreshold, "", false); pErr == nil {
			threshold, gateEnabled = pt, true
		}
	}
	ai.SetConfirmThreshold(threshold)
	if gateEnabled {
		statusOK(fmt.Sprintf("Risk gate %s(threshold: %s)%s", dim, threshold.String(), reset))
	} else {
		statusWarn("Risk gate disabled — destructive tools run without prompting")
	}

	// --- Session store (opt-in persistence) ---
	if store, err := agent.DefaultSessionStore(); err != nil {
		statusWarn(fmt.Sprintf("Session persistence unavailable: %v", err))
	} else {
		ai.SetSessionStore(store)
		statusOK(fmt.Sprintf("Sessions on-disk %s(id: %s)%s", dim, ai.SessionID(), reset))
		if resumeID != "" {
			if err := ai.ResumeSession(resumeID); err != nil {
				statusWarn(fmt.Sprintf("Resume %q failed: %v", resumeID, err))
			} else {
				statusOK(fmt.Sprintf("Resumed session %s%s%s", bold, resumeID, reset))
			}
		} else if autoResume {
			// Pick the most recent session if it's <24h old. Older sessions
			// are left alone — user can still resume explicitly with --resume.
			if sessions, err := ai.ListSessions(); err == nil && len(sessions) > 0 {
				latest := sessions[0]
				for _, s := range sessions[1:] {
					if s.UpdatedAt.After(latest.UpdatedAt) {
						latest = s
					}
				}
				if time.Since(latest.UpdatedAt) < 24*time.Hour {
					if err := ai.ResumeSession(latest.ID); err != nil {
						statusWarn(fmt.Sprintf("Auto-resume failed: %v", err))
					} else {
						statusOK(fmt.Sprintf("Auto-resumed session %s%s%s %s(updated %s ago)%s",
							bold, latest.ID, reset,
							dim, time.Since(latest.UpdatedAt).Round(time.Minute), reset))
					}
				}
			}
		}
	}

	// --- Audit log ---
	dataDir := filepath.Join(os.Getenv("HOME"), ".promptzero")
	auditLog, err := audit.Open(filepath.Join(dataDir, "audit.db"))
	if err != nil {
		statusWarn(fmt.Sprintf("Audit log unavailable: %v", err))
	} else {
		defer auditLog.Close()
		ai.SetAuditLog(auditLog)
		statusOK(fmt.Sprintf("Audit logging %s(session: %s)%s", dim, auditLog.SessionID(), reset))
	}

	// --- Outbound webhooks ---
	// Construct unconditionally (empty config yields a no-op-ish dispatcher
	// whose workers idle on an empty subscription list). This keeps the
	// downstream callback wiring branch-free.
	var webhookSubs []webhook.Subscription
	for _, w := range cfg.Webhooks {
		evs := make([]webhook.Event, 0, len(w.Events))
		for _, e := range w.Events {
			evs = append(evs, webhook.Event(e))
		}
		webhookSubs = append(webhookSubs, webhook.Subscription{
			Name:    w.Name,
			URL:     w.URL,
			Events:  evs,
			Headers: w.Headers,
			Secret:  w.Secret,
		})
	}
	wh := webhook.New(webhookSubs)

	// --- MQTT bridge ---
	// Enabled=false in config yields a no-op Bridge, so the downstream wiring
	// doesn't need to branch on nil. Connect is best-effort; a broker that
	// isn't up right now will keep retrying in the background.
	mqttBridge := mqtt.New(cfg.MQTT)
	if mqttBridge.Enabled() {
		go func() {
			if err := mqttBridge.Connect(); err != nil {
				statusWarn(fmt.Sprintf("MQTT broker unreachable: %v (auto-reconnect running)", err))
				return
			}
			statusOK(fmt.Sprintf("MQTT bridge %s(%s → %s/…)%s", dim, cfg.MQTT.Broker, mqttBridge.BasePath(), reset))
		}()
		defer mqttBridge.Close()
	}

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		endedPayload := map[string]any{
			"session_id": func() string {
				if auditLog != nil {
					return auditLog.SessionID()
				}
				return ""
			}(),
			"ended_at": time.Now().UTC(),
		}
		wh.Fire(webhook.EventSessionEnded, endedPayload)
		mqttBridge.PublishEvent("session_ended", endedPayload)
		_ = wh.Close(shutdownCtx)
	}()
	// --- Reactive rules engine ---
	// Subscribe to the audit observer so declarative YAML rules react to
	// tool calls. Actions dispatch through the same webhook/MQTT plumbing
	// as first-class events, so the wire format stays uniform.
	ruleEngine := rules.New(rules.Deps{
		WebhookFire: func(name string, payload map[string]any) {
			wh.Fire(webhook.Event(name), payload)
		},
		MQTTPublish: func(topic string, payload map[string]any) {
			mqttBridge.PublishEvent(topic, payload)
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
		ruleEngine.Register(r)
	}
	if n := len(ruleEngine.List()); n > 0 {
		statusOK(fmt.Sprintf("Reactive rules %s(%d loaded)%s", dim, n, reset))
	}

	if auditLog != nil {
		auditLog.AddObserver(func(e audit.Entry) {
			rec.RecordAudit(e.Risk, string(e.Level))
			ruleEngine.Handle(e)
			if e.Level == audit.LevelCritical {
				wh.Fire(webhook.EventAuditCritical, e)
				mqttBridge.PublishAuditCritical(e)
			}
		})
	}
	if len(webhookSubs) > 0 {
		statusOK(fmt.Sprintf("Webhooks %s(%d subscriber%s)%s", dim, len(webhookSubs), plural(len(webhookSubs)), reset))
	}
	sessionStartPayload := map[string]any{
		"session_id": func() string {
			if auditLog != nil {
				return auditLog.SessionID()
			}
			return ""
		}(),
		"started_at": time.Now().UTC(),
		"model":      cfg.Model,
	}
	wh.Fire(webhook.EventSessionStarted, sessionStartPayload)
	mqttBridge.PublishEvent("session_started", sessionStartPayload)

	// --- Generation provider ---
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
		genLLM = provider.NewClaude(&client, cfg.Model)
	}

	gen := generate.New(genLLM, flip)
	ai.SetGenerator(gen)
	ai.SetGenLLM(genLLM)
	statusOK(fmt.Sprintf("Generation engine %s(%s)%s", dim, genLLM.Name(), reset))

	// --- Marauder WiFi devboard ---
	hasMarauder := false
	if wifiEnabled || cfg.Marauder.Enabled {
		statusInfo(fmt.Sprintf("Connecting to Marauder on %s%s%s...", bold, cfg.Marauder.Port, reset))
		m, err := marauder.Connect(cfg.Marauder.Port, cfg.Marauder.BaudRate)
		if err != nil {
			statusWarn(fmt.Sprintf("Marauder unavailable: %v", err))
		} else {
			defer m.Close()
			ai.SetMarauder(m)
			hasMarauder = true
			rec.SetMarauderConnected(true)
			statusOK("Marauder WiFi devboard connected")
		}
	}

	// --- Voice engine ---
	var voiceEngine *voice.Engine
	if cfg.OpenAIKey != "" {
		voiceEngine = voice.New(cfg.OpenAIKey)
		statusOK(fmt.Sprintf("Voice engine %s(Whisper)%s", dim, reset))
	}

	// --- Capability summary ---
	printSeparator()

	tools := len(agent.ToolNames(hasMarauder))
	fmt.Fprintf(os.Stderr, "  %s%s%d tools%s loaded", bold, white, tools, reset)
	features := []string{fmt.Sprintf("%sFlipper%s", green, reset)}
	if hasMarauder {
		features = append(features, fmt.Sprintf("%sMarauder%s", cyan, reset))
	}
	features = append(features, fmt.Sprintf("%sGenerate%s", magenta, reset))
	if voiceEngine != nil {
		features = append(features, fmt.Sprintf("%sVoice%s", yellow, reset))
	}
	fmt.Fprintf(os.Stderr, " — %s\n", strings.Join(features, " · "))

	printSeparator()
	fmt.Fprintf(os.Stderr, "\n")

	// --- Web mode ---
	if webMode {
		// Empty Host defaults to loopback inside web.NewServer, which also
		// warns if the user picked a non-loopback bind explicitly. We read
		// the EFFECTIVE addr back so the "Web UI at ..." status line
		// doesn't contradict the warning.
		addr := fmt.Sprintf("%s:%d", cfg.Web.Host, cfg.Web.Port)
		srv := web.NewServer(addr, ai, voiceEngine)
		srv.SetMetrics(rec, cfg.Observability.MetricsPath)
		statusOK(fmt.Sprintf("Web UI at %s%shttp://%s%s", bold, cyan, srv.Addr(), reset))
		if rec != nil {
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

	// --- CLI REPL ---
	return enterREPL(&REPLDeps{
		ctx:           ctx,
		sh:            sh,
		cfg:           cfg,
		ai:            ai,
		flip:          flip,
		genLLM:        genLLM,
		hasMarauder:   hasMarauder,
		voiceEngine:   voiceEngine,
		voiceMode:     voiceMode,
		auditLog:      auditLog,
		rec:           rec,
		activePersona: activePersona,
		personas:      personas,
		costTracker:   costTracker,
		wh:            wh,
		mqttBridge:    mqttBridge,
		ruleEngine:    ruleEngine,
		gateEnabled:   gateEnabled,
		watchPaths:    watchPaths,
	})
}
