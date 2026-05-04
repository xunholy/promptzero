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
	// Subcommand dispatch: if the first positional arg is a known
	// management verb, peel it off and route to a dedicated handler
	// *before* the REPL's flag parser runs. Keeps `promptzero upgrade`
	// and `promptzero version` free of the REPL-only flags (--config,
	// --web, --wifi, etc.) that would confuse their help output.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "upgrade":
			opts := parseUpgradeFlags(os.Args[2:])
			if err := runUpgrade(context.Background(), opts); err != nil {
				fmt.Fprintf(os.Stderr, "\n  %s%serror: %v%s\n\n", bold, red, err, reset)
				os.Exit(1)
			}
			return
		case "version":
			check := parseVersionFlags(os.Args[2:])
			if err := runVersionCheck(context.Background(), check); err != nil {
				fmt.Fprintf(os.Stderr, "\n  %s%serror: %v%s\n\n", bold, red, err, reset)
				os.Exit(1)
			}
			return
		}
	}

	if err := run(); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "\n  %scancelled.%s\n\n", dim, reset)
			// POSIX convention: 128 + signal number; SIGINT = 2 → 130.
			// Lets shell scripts distinguish user-cancellation from a
			// real failure (exit 1).
			os.Exit(130)
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
	if f.bleDiscover {
		return runBLEDiscover(f.bleDiscoverDuration)
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
	if err := validateMarauderFlags(f); err != nil {
		return err
	}

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
		// --web is allowed to start without a Flipper attached so the
		// operator can open the cockpit, browse panels, and plug the
		// device in later. SIGINT during connect still aborts. Other
		// modes (REPL, --mcp) keep the original fatal behaviour because
		// they have no useful surface without the device.
		if !f.webMode || errors.Is(err, context.Canceled) {
			return err
		}
		statusWarn("continuing without Flipper — device-dependent panels and tool calls will be disabled until reconnect")
		flip = nil
		flipClose = func() {}
	}
	defer flipClose()

	rec := setupMetrics(cfg)

	// Wire OpenTelemetry tracing. Honours OTEL_EXPORTER_OTLP_ENDPOINT —
	// when unset, returns a noop shutdown and every span call in the
	// agent is a cheap drop. The deferred shutdown force-flushes any
	// pending spans so a crash doesn't lose the final batch.
	otelShutdown, err := obs.InitOTel(ctx)
	if err != nil {
		statusWarn(fmt.Sprintf("OTel init failed (tracing disabled): %v", err))
	} else {
		defer func() { _ = otelShutdown(context.Background()) }()
	}

	if f.mcpMode {
		return runMCPMode(cfg, flip, f.wifiEnabled)
	}

	if err := cfg.RequireAPIKey(); err != nil {
		return err
	}

	client := anthropic.NewClient()
	ai := agent.New(&client, flip, cfg)
	if cfg.Agent.ConfirmIdleTimeout > 0 {
		ai.SetConfirmIdleTimeout(cfg.Agent.ConfirmIdleTimeout)
	}
	statusOK(fmt.Sprintf("Agent ready %s(model: %s)%s", dim, cfg.Model, reset))

	costTracker := setupCostTracker(cfg, ai, rec)
	activePersona, personas, err := setupPersona(cfg, f.personaName, ai)
	if err != nil {
		return err
	}
	gateEnabled := setupRiskGate(cfg, f.confirmRisk, f.yoloMode, activePersona, ai)
	setupMode(cfg, f.modeName, ai)
	setupReadOnly(cfg, f.readOnly, ai)
	setupSessionStore(ai, f.resumeID, f.autoResume)

	auditLog, auditClose := setupAuditLog(ai)
	defer auditClose()

	wh := setupWebhooks(cfg)

	// Fires session_ended + drains the webhook dispatcher. Deferred
	// here (LIFO) so it runs before audit.Close, but after any
	// setupMarauder cleanup registered later.
	defer fireSessionEnded(auditLog, wh)

	ruleEngine := setupRules(cfg, wh, auditLog, rec)
	fireSessionStarted(cfg, auditLog, wh)

	setupAttack(ai, auditLog)
	setupDetectors(&client, ai, cfg)

	// Federation must come AFTER setupDetectors so any auto-detector
	// rules referencing federated tools by name can find them, and
	// BEFORE the REPL hands a turn to the model — federated Specs are
	// registered into tools.Register at this point and become visible
	// in the agent's tool advertisement on the next turn.
	mcpfedClose := setupMCPFederation(ctx, cfg)
	defer mcpfedClose()

	genLLM := setupGenerator(cfg, ai, flip, &client, f.genProvider, f.ollamaURL, f.ollamaModel)

	hasMarauder, marauderClose := setupMarauder(ctx, cfg, ai, rec, flip, f.wifiEnabled)
	defer marauderClose()

	_, bruceClose := setupBruce(ctx, cfg, ai)
	defer bruceClose()
	_, faultierClose := setupFaultier(cfg, ai)
	defer faultierClose()
	_, busPirateClose := setupBusPirate(ctx, cfg, ai)
	defer busPirateClose()

	voiceEngine := setupVoice(cfg)

	// Pill rendering: bridgeMarauder gives the Marauder "(bridge)" tag
	// in either single-cable or hybrid mode; flipperSuspended drives the
	// red "(suspended)" Flipper pill, which only fires in single-cable
	// mode (hybrid keeps CLI alive over BLE so the pill stays green).
	bridgeMarauder := cfg.Marauder.Bridge && hasMarauder
	flipperSuspended := flip != nil && flip.IsSuspended()
	printCapabilitySummary(hasMarauder, voiceEngine != nil, bridgeMarauder, flipperSuspended)

	if f.webMode {
		return runWebMode(ctx, sh, cfg, WebDeps{
			Ai:             ai,
			Voice:          voiceEngine,
			Rec:            rec,
			Personas:       personas,
			CostTracker:    costTracker,
			RulesEngine:    ruleEngine,
			Flipper:        flip,
			FlipperOnline:  flip != nil,
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
		ruleEngine:    ruleEngine,
		gateEnabled:   gateEnabled,
		watchPaths:    f.watchPaths,
	})
}
