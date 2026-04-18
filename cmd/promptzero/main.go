package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/version"
)

// stringSlice is a flag.Value that collects repeated string flags into a
// slice — used by --watch so operators can aim multiple paths at one
// invocation without quoting a comma-separated list.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

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

// run is the top-level lifecycle: parse flags → handle early-exit modes →
// load + override config → connect hardware → build agent → bootstrap
// subsystems via setup.go helpers → hand off to enterREPL (or the web /
// MCP entrypoint). Each subsystem returns a cleanup closure which is
// deferred here so the order matches the reverse of construction.
func run() error {
	f := parseFlags()

	if f.showVersion {
		fmt.Printf("promptzero %s\n", version.String())
		return nil
	}
	if f.doInit {
		return runInit()
	}

	// First-run UX: no config anywhere and no API key env var? Print an
	// onboarding hint and exit cleanly so this doesn't look like a crash.
	if p := os.Getenv("PROMPTZERO_CONFIG"); p != "" {
		f.cfgPath = p
	}
	if isFirstRun(f.cfgPath) {
		printFirstRunHint()
		return nil
	}

	// Intercept SIGINT so the first press cancels the in-flight op
	// (connect, API call, tool run) and a second press within 2s exits
	// hard — same feel as Claude Code / modern CLIs.
	sh := &signalHandler{}
	defer sh.install()()
	ctx := context.Background()

	if !f.mcpMode {
		printBanner()
		printSeparator()
	}

	cfg, err := config.Load(f.cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	applyConfigOverrides(cfg, f)

	// Install the slog handler before any subsystem so they share a
	// configured default. PROMPTZERO_LOG_LEVEL is an operator-only
	// env override on top of the config file.
	obs.Setup(obs.LogConfig{
		Level:  cfg.Observability.LogLevel,
		Format: cfg.Observability.LogFormat,
		File:   cfg.Observability.LogFile,
	})
	warnMultiFlipper(cfg, f.portOverride)

	flip, flipClose, err := connectFlipper(ctx, sh, cfg, f.connectTimeout)
	if err != nil {
		return err
	}
	defer flipClose()

	rec := setupMetrics(cfg)

	if f.mcpMode {
		return runMCPMode(cfg, flip, f.wifiEnabled)
	}

	client := anthropic.NewClient()
	ai := agent.New(&client, flip, cfg)
	statusOK(fmt.Sprintf("Agent ready %s(model: %s)%s", dim, cfg.Model, reset))

	costTracker := setupCostTracker(cfg, ai, rec)
	activePersona, personas, err := setupPersona(cfg, f.personaName, ai)
	if err != nil {
		return err
	}
	gateEnabled := setupRiskGate(cfg, f.confirmRisk, f.yoloMode, activePersona, ai)
	setupSessionStore(ai, f.resumeID, f.autoResume)

	auditLog, auditClose := setupAuditLog(ai)
	defer auditClose()

	wh := setupWebhooks(cfg)
	mqttBridge, mqttClose := setupMQTT(cfg)
	defer mqttClose()

	// Fires session_ended + drains the webhook dispatcher. Deferred
	// here (LIFO) so it runs before mqtt.Close and audit.Close, but
	// after any setupMarauder cleanup registered later.
	defer fireSessionEnded(auditLog, wh, mqttBridge)

	ruleEngine := setupRules(cfg, wh, mqttBridge, auditLog, rec)
	fireSessionStarted(cfg, auditLog, wh, mqttBridge)

	genLLM := setupGenerator(cfg, ai, flip, &client, f.genProvider, f.ollamaURL, f.ollamaModel)

	hasMarauder, marauderClose := setupMarauder(cfg, ai, rec, f.wifiEnabled)
	defer marauderClose()

	voiceEngine := setupVoice(cfg)

	printCapabilitySummary(hasMarauder, voiceEngine != nil)

	if f.webMode {
		return runWebMode(ctx, sh, cfg, WebDeps{
			Ai:             ai,
			Voice:          voiceEngine,
			Rec:            rec,
			Personas:       personas,
			CostTracker:    costTracker,
			RulesEngine:    ruleEngine,
			Flipper:        flip,
			MarauderOnline: hasMarauder,
		})
	}

	return enterREPL(&REPLDeps{
		ctx:           ctx,
		sh:            sh,
		cfg:           cfg,
		ai:            ai,
		flip:          flip,
		genLLM:        genLLM,
		hasMarauder:   hasMarauder,
		voiceEngine:   voiceEngine,
		voiceMode:     f.voiceMode,
		auditLog:      auditLog,
		rec:           rec,
		activePersona: activePersona,
		personas:      personas,
		costTracker:   costTracker,
		wh:            wh,
		mqttBridge:    mqttBridge,
		ruleEngine:    ruleEngine,
		gateEnabled:   gateEnabled,
		watchPaths:    f.watchPaths,
	})
}
