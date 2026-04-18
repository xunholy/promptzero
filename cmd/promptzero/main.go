package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/rules"
	"github.com/xunholy/promptzero/internal/version"
	"github.com/xunholy/promptzero/internal/voice"
	"github.com/xunholy/promptzero/internal/watch"
	"github.com/xunholy/promptzero/internal/web"
	"github.com/xunholy/promptzero/internal/webhook"
	"golang.org/x/term"
)

// turnResult is the outcome of one ai.Run, delivered back to the REPL
// select loop so it can update UI state on the main goroutine.
type turnResult struct {
	response string
	err      error
}

// stringSlice is a flag.Value that collects repeated string flags into a
// slice — used by --watch so operators can aim multiple paths at one
// invocation without quoting a comma-separated list.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

// Style carries ANSI colour escapes. When stderr is not a TTY, or NO_COLOR
// is set in the environment, all fields are empty strings so callers emit
// plain text without per-site branching.
type Style struct {
	reset, bold, dim, red, green, yellow, blue, magenta, cyan, white, gray string
}

func newStyles() Style {
	if os.Getenv("NO_COLOR") != "" || !term.IsTerminal(int(os.Stderr.Fd())) {
		return Style{}
	}
	return Style{
		reset:   "\033[0m",
		bold:    "\033[1m",
		dim:     "\033[2m",
		red:     "\033[31m",
		green:   "\033[32m",
		yellow:  "\033[33m",
		blue:    "\033[34m",
		magenta: "\033[35m",
		cyan:    "\033[36m",
		white:   "\033[37m",
		gray:    "\033[90m",
	}
}

var styles = newStyles()

// Package-level shortcuts for the active Style. Declared as vars (not
// consts) so they reflect the NO_COLOR / TTY decision made at process
// start. Consumed by both main.go and lineedit.go.
var (
	reset   = styles.reset
	bold    = styles.bold
	dim     = styles.dim
	red     = styles.red
	green   = styles.green
	yellow  = styles.yellow
	blue    = styles.blue
	magenta = styles.magenta
	cyan    = styles.cyan
	white   = styles.white
	gray    = styles.gray
)

func hasColor() bool { return styles.red != "" }

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

func printBanner() {
	if !hasColor() {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  promptzero — AI operator for Flipper Zero")
		fmt.Fprintln(os.Stderr)
		return
	}
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "%s%s", bold, red)
	fmt.Fprintf(os.Stderr, "  ██████╗ ██████╗  ██████╗ ███╗   ███╗██████╗ ████████╗\n")
	fmt.Fprintf(os.Stderr, "  ██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗╚══██╔══╝\n")
	fmt.Fprintf(os.Stderr, "  ██████╔╝██████╔╝██║   ██║██╔████╔██║██████╔╝   ██║   \n")
	fmt.Fprintf(os.Stderr, "  ██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔═══╝    ██║   \n")
	fmt.Fprintf(os.Stderr, "  ██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║██║        ██║   \n")
	fmt.Fprintf(os.Stderr, "  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝        ╚═╝   \n")
	fmt.Fprintf(os.Stderr, "%s%s", reset, cyan)
	fmt.Fprintf(os.Stderr, "  ███████╗███████╗██████╗  ██████╗ \n")
	fmt.Fprintf(os.Stderr, "  ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗\n")
	fmt.Fprintf(os.Stderr, "    ███╔╝ █████╗  ██████╔╝██║   ██║\n")
	fmt.Fprintf(os.Stderr, "   ███╔╝  ██╔══╝  ██╔══██╗██║   ██║\n")
	fmt.Fprintf(os.Stderr, "  ███████╗███████╗██║  ██║╚██████╔╝\n")
	fmt.Fprintf(os.Stderr, "  ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ \n")
	fmt.Fprintf(os.Stderr, "%s\n", reset)
	fmt.Fprintf(os.Stderr, "  %s%sAI-Powered Flipper Zero Operator%s\n", dim, white, reset)
	fmt.Fprintf(os.Stderr, "  %s%sno limits // no filters%s\n\n", dim, gray, reset)
}

func status(icon string, msg string) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", icon, msg)
}

func statusOK(msg string)   { status(green+"●"+reset, msg) }
func statusWarn(msg string) { status(yellow+"●"+reset, msg) }
func statusErr(msg string)  { status(red+"●"+reset, msg) }
func statusInfo(msg string) { status(blue+"●"+reset, msg) }

func printSeparator() {
	fmt.Fprintf(os.Stderr, "  %s%s%s\n", dim, strings.Repeat("─", 52), reset)
}

// Input box glyphs — a full rounded rectangle around the current prompt.
// Typed input lives inside; past prompts demote to a single dim "> ..." line.
const (
	boxTL   = "╭"
	boxTR   = "╮"
	boxBL   = "╰"
	boxBR   = "╯"
	boxV    = "│"
	boxRule = "─"
	boxPad  = 2 // leading spaces before the left border
)

// termUI owns a persistent 3-line input box pinned to the bottom of the
// terminal. The area above (a DEC scroll region) carries all agent/tool
// output; the box is redrawn once at setup and only the input line is
// refreshed after each Enter, so the box visually stays put while output
// scrolls past it. Not a full TUI, but gets the Claude-Code feel without
// a TUI framework.
//
// rows/cols are atomics so the SIGWINCH handler can update them from a
// signal goroutine while the render path reads them. The render path
// still serialises against outputMu — the atomics only cover the
// dimension reads/writes themselves.
type termUI struct {
	rows    atomic.Int32
	cols    atomic.Int32
	enabled bool
}

const boxHeight = 3

func newTermUI() *termUI {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return &termUI{enabled: false}
	}
	cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || rows < 8 || cols < 24 {
		return &termUI{enabled: false}
	}
	ui := &termUI{enabled: true}
	ui.rows.Store(int32(rows))
	ui.cols.Store(int32(cols))
	return ui
}

// Rows returns the current terminal row count. Updated by the SIGWINCH
// handler; safe to call from any goroutine.
func (t *termUI) Rows() int { return int(t.rows.Load()) }

// Cols returns the current terminal column count. Updated by the SIGWINCH
// handler; safe to call from any goroutine.
func (t *termUI) Cols() int { return int(t.cols.Load()) }

// resize reads the current terminal size and updates rows/cols. Returns
// whether the dimensions actually changed. Caller owns redrawing.
func (t *termUI) resize() bool {
	if !t.enabled {
		return false
	}
	cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || rows < 8 || cols < 24 {
		return false
	}
	changed := int(t.rows.Load()) != rows || int(t.cols.Load()) != cols
	t.rows.Store(int32(rows))
	t.cols.Store(int32(cols))
	return changed
}

func (t *termUI) setup() {
	if !t.enabled {
		return
	}
	rows := t.Rows()
	fmt.Fprintf(os.Stderr, "\033[1;%dr", rows-boxHeight)
	t.drawBoxFrame()
	t.drawInputLineEmpty()
	fmt.Fprintf(os.Stderr, "\033[%d;1H", rows-boxHeight)
}

func (t *termUI) teardown() {
	if !t.enabled {
		return
	}
	fmt.Fprint(os.Stderr, "\033[r")
	fmt.Fprintf(os.Stderr, "\033[%d;1H\n", t.Rows())
}

func (t *termUI) positionOutput() {
	if !t.enabled {
		return
	}
	fmt.Fprintf(os.Stderr, "\033[%d;1H", t.Rows()-boxHeight)
}

func (t *termUI) positionInput() {
	if !t.enabled {
		return
	}
	fmt.Fprintf(os.Stderr, "\033[%d;%dH", t.Rows()-1, boxPad+4+1)
}

func (t *termUI) drawBoxFrame() {
	rows, cols := t.Rows(), t.Cols()
	width := cols - boxPad
	inner := width - 2
	rule := strings.Repeat(boxRule, inner)
	pad := strings.Repeat(" ", boxPad)
	fmt.Fprintf(os.Stderr, "\033[%d;1H\033[2K%s%s%s%s%s%s",
		rows-2, pad, dim, boxTL, rule, boxTR, reset)
	fmt.Fprintf(os.Stderr, "\033[%d;1H\033[2K%s%s%s%s%s%s",
		rows, pad, dim, boxBL, rule, boxBR, reset)
}

// drawStatusBorder redraws the box's top border. Empty status → plain rule
// of dashes (idle). Non-empty → status embedded inside the border like
// "╭── ⠙ Thinking · 5s · Ctrl+C to interrupt ───╮" so the user always has
// a visible turn-in-flight indicator without reserving an extra row.
func (t *termUI) drawStatusBorder(status string) {
	if !t.enabled {
		return
	}
	rows, cols := t.Rows(), t.Cols()
	width := cols - boxPad
	inner := width - 2
	pad := strings.Repeat(" ", boxPad)

	if status == "" {
		rule := strings.Repeat(boxRule, inner)
		fmt.Fprintf(os.Stderr, "\033[%d;1H\033[2K%s%s%s%s%s%s",
			rows-2, pad, dim, boxTL, rule, boxTR, reset)
		return
	}

	const leading = 2
	runes := []rune(status)
	avail := inner - leading - 2 // 2 spaces around the status text
	if avail < 1 {
		rule := strings.Repeat(boxRule, inner)
		fmt.Fprintf(os.Stderr, "\033[%d;1H\033[2K%s%s%s%s%s%s",
			rows-2, pad, dim, boxTL, rule, boxTR, reset)
		return
	}
	if len(runes) > avail {
		runes = append(runes[:avail-1], '…')
	}
	trailing := inner - leading - 2 - len(runes)
	if trailing < 0 {
		trailing = 0
	}

	// Layout: pad + dim(╭──) + " " + status + " " + dim(──╮) + reset
	// — status renders in the default style so it reads bright against the
	// dimmed border dashes.
	fmt.Fprintf(os.Stderr, "\033[%d;1H\033[2K%s%s%s%s%s %s %s%s%s%s",
		rows-2,
		pad,
		dim, boxTL, strings.Repeat(boxRule, leading), reset,
		string(runes),
		dim, strings.Repeat(boxRule, trailing), boxTR, reset,
	)
}

func (t *termUI) drawInputLineEmpty() {
	if !t.enabled {
		return
	}
	rows, cols := t.Rows(), t.Cols()
	width := cols - boxPad
	inner := width - 2
	tailSpaces := strings.Repeat(" ", inner-3)
	pad := strings.Repeat(" ", boxPad)
	fmt.Fprintf(os.Stderr, "\033[%d;1H\033[2K%s%s%s%s %s>%s %s%s%s%s",
		rows-1, pad, dim, boxV, reset,
		bold+red, reset,
		tailSpaces, dim, boxV, reset)
}

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
	mainCtx := context.Background()
	var currentCancel atomic.Pointer[context.CancelFunc]
	var lastSIGINT atomic.Int64
	var uiRef atomic.Pointer[termUI]
	var stdinRestore atomic.Pointer[func()]

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	go func() {
		const doubleTapWindow = 2 * time.Second
		for range sigCh {
			now := time.Now().UnixNano()
			prev := lastSIGINT.Swap(now)
			within := prev != 0 && time.Duration(now-prev) < doubleTapWindow

			if within {
				if fn := stdinRestore.Load(); fn != nil {
					(*fn)()
				}
				if u := uiRef.Load(); u != nil {
					u.teardown()
				}
				fmt.Fprintf(os.Stderr, "\n  %sGoodbye.%s\n\n", dim, reset)
				os.Exit(0)
			}
			if cfp := currentCancel.Load(); cfp != nil {
				(*cfp)()
			}
			if u := uiRef.Load(); u != nil {
				u.positionOutput()
			}
			fmt.Fprintf(os.Stderr, "\n  %s(Ctrl+C again within 2s to exit)%s\n", dim, reset)
			if u := uiRef.Load(); u != nil {
				u.drawInputLineEmpty()
				u.positionInput()
			}
		}
	}()

	withCancel := func(parent context.Context) (context.Context, func()) {
		opCtx, cancel := context.WithCancel(parent)
		cf := context.CancelFunc(cancel)
		currentCancel.Store(&cf)
		return opCtx, func() {
			currentCancel.Store(nil)
			cancel()
		}
	}
	ctx := mainCtx

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
	connectCtx, releaseConnect := withCancel(ctx)
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
		webCtx, releaseWeb := withCancel(ctx)
		defer releaseWeb()
		return srv.Start(webCtx)
	}

	// --- CLI REPL ---
	if voiceMode {
		if voiceEngine == nil {
			return fmt.Errorf("voice mode requires OPENAI_API_KEY")
		}
		if !voice.Available() {
			return fmt.Errorf("voice mode requires 'sox' (apt install sox / brew install sox)")
		}
		fmt.Fprintf(os.Stderr, "  %sVoice mode ON%s — press Enter to record, speak, stops on silence.\n\n", bold, reset)
	}

	fmt.Fprintf(os.Stderr, "  Type %s/help%s for commands, or just describe what you want.\n", dim, reset)
	fmt.Fprintf(os.Stderr, "  %sFlipper feedback:%s %s●%s blue LED while agent is working · %s●%s vibration on detection\n\n", dim, reset, blue, reset, green, reset)

	// --- Persistent input box at bottom of terminal ---
	ui := newTermUI()
	uiRef.Store(ui)
	ui.setup()
	defer ui.teardown()

	// --- Raw-mode stdin so the user can keep typing while a turn runs ---
	stdinFd := int(os.Stdin.Fd())
	if term.IsTerminal(stdinFd) {
		oldState, err := term.MakeRaw(stdinFd)
		if err != nil {
			return fmt.Errorf("raw mode: %w", err)
		}
		// MakeRaw disables OPOST, which also turns off ONLCR - so a plain \n
		// in our output moves the cursor down without carriage-returning to
		// column 0. That's what was causing confirm-prompt row 2 and streamed
		// text to drift rightward across lines. Re-enable OPOST + ONLCR so
		// \n writes behave as line breaks again. Leaves ICANON/ECHO/ISIG off
		// (we still own input handling and Ctrl+C routing). Platform-specific
		// termios details live in main_termios_<goos>.go.
		enableOPOSTONLCR(stdinFd)
		restore := func() { _ = term.Restore(stdinFd, oldState) }
		stdinRestore.Store(&restore)
		defer func() {
			stdinRestore.Store(nil)
			restore()
		}()
	}

	ed := newLineEditor(ui)

	// Enable bracketed paste (DECSET 2004) so multi-line pastes arrive as a
	// single buffered event rather than one Enter per line, and disable on
	// teardown so the next shell doesn't inherit the mode.
	if ui.enabled {
		fmt.Fprint(os.Stderr, "\033[?2004h")
		defer fmt.Fprint(os.Stderr, "\033[?2004l")
	}

	// SIGWINCH: refresh dimensions, re-scroll, redraw box + input.
	// Windows has no SIGWINCH — watchWindowSize is a no-op there (see
	// main_os_windows.go). On Unix it registers the signal handler.
	stopWinch := watchWindowSize(func() {
		if !ui.resize() {
			return
		}
		ed.outputMu.Lock()
		fmt.Fprintf(os.Stderr, "\033[1;%dr", ui.Rows()-boxHeight)
		ui.drawBoxFrame()
		ed.renderLocked()
		ed.outputMu.Unlock()
	})
	defer stopWinch()

	// Surface hot-plug reconnect phases in the output area. Keeps the user
	// informed when the Flipper drops off USB (WSL vhci_hcd glitch, physical
	// replug, etc.) without requiring /quit + relaunch.
	flip.SetReconnectCallback(func(phase, message string) {
		ed.writeOutput(func() {
			switch phase {
			case "start":
				fmt.Fprintf(os.Stderr, "  %s●%s %s\n", yellow, reset, message)
			case "success":
				fmt.Fprintf(os.Stderr, "  %s●%s %s\n", green, reset, message)
			case "fail":
				fmt.Fprintf(os.Stderr, "  %s●%s %s\n", red, reset, message)
			}
		})
	})

	// streaming is true while text deltas are actively landing on the
	// current output line. State transitions (tool start/finish, turn end)
	// flip it back to false so the next delta re-clears the status line.
	var streaming atomic.Bool

	// --- Turn status bar (Claude-Code-style spinner on top border) ---
	// turnStartedAt + turnNote drive the spinner goroutine below. The
	// spinner redraws the box's top border every ~100ms with the current
	// note (Thinking / Running <tool> / Responding) and elapsed time. It
	// exits cleanly once ed.running goes false.
	var turnStartedAt atomic.Pointer[time.Time]
	var turnNote atomic.Pointer[string]
	var turnToolCount atomic.Int32
	setNote := func(s string) { turnNote.Store(&s) }

	// P8 wiring — stream assistant text as it arrives. writeDelta preserves
	// the cursor position between chunks using DEC save/restore, so
	// successive tokens flow naturally across the scroll region instead of
	// clobbering each other at column 1 (which writeOutput would do).
	ai.SetTextDeltaCallback(func(td agent.TextDelta) {
		if streaming.CompareAndSwap(false, true) {
			setNote("Responding")
		}
		ed.writeDelta(td.Text)
	})

	// Tool-call status: routed through the editor so concurrent keystroke
	// redraws and tool events don't trample each other. P1 adds an inline
	// one-line output preview after each tool finish.
	ai.SetToolStatusCallback(func(ev agent.ToolEvent) {
		// End any in-flight delta stream cleanly before writing a status
		// line — the line editor's endDelta emits the closing newline.
		if streaming.Swap(false) {
			ed.endDelta()
		}
		ed.writeOutput(func() {
			switch ev.Phase {
			case "start":
				setNote("Running " + ev.Name)
				fmt.Fprintf(os.Stderr, "  %s▸%s %s %s%s%s\n", cyan, reset, ev.Name, dim, truncateArgs(ev.Input), reset)
			case "finish":
				setNote("Thinking")
				turnToolCount.Add(1)
				icon := green + "◦" + reset
				if ev.Err {
					icon = red + "✗" + reset
				}
				fmt.Fprintf(os.Stderr, "  %s %s %s(%s)%s\n", icon, ev.Name, dim, ev.Duration.Round(time.Millisecond), reset)
				if preview := outputPreview(ev.Output, ev.Err); preview != "" {
					fmt.Fprintln(os.Stderr, preview)
				}
			}
		})
		if ev.Phase == "finish" {
			status := "ok"
			if ev.Err {
				status = "error"
			}
			rec.RecordToolCall(ev.Name, risk.Classify(ev.Name).String(), status, ev.Duration)
			if strings.HasPrefix(ev.Name, "workflow_") {
				rec.RecordWorkflowRun(ev.Name, status, ev.Duration)
			}
			out := ev.Output
			if len(out) > 2048 {
				out = out[:2048] + "... [truncated]"
			}
			payload := map[string]any{
				"tool":        ev.Name,
				"input":       string(ev.Input),
				"duration_ms": ev.Duration.Milliseconds(),
				"error":       ev.Err,
				"output":      out,
			}
			wh.Fire(webhook.EventToolFinished, payload)
			mqttBridge.PublishEvent("tool_finished", payload)
			mqttBridge.PublishToolLast(ev.Name, payload)
			if strings.HasPrefix(ev.Name, "workflow_") {
				wh.Fire(webhook.EventWorkflowCompleted, payload)
				mqttBridge.PublishEvent("workflow_completed", payload)
			}
		}
	})

	// --- Risk confirmation prompt ---
	// The callback fires from the ai.Run goroutine. It parks a pendingConfirm
	// state and blocks on resultCh; the main REPL select loop routes the next
	// keystroke into that channel (see "pendingConfirm" check in the select
	// below) instead of the line editor.
	var pendingConfirm atomic.Pointer[confirmState]
	if gateEnabled {
		ai.SetConfirmCallback(func(ctx context.Context, req agent.ConfirmRequest) agent.Decision {
			promptPayload := map[string]any{
				"tool":  req.Tool,
				"risk":  req.Risk.String(),
				"input": string(req.Input),
			}
			wh.Fire(webhook.EventRiskPrompted, promptPayload)
			mqttBridge.PublishEvent("risk_prompted", promptPayload)
			resultCh := make(chan agent.Decision, 1)
			pendingConfirm.Store(&confirmState{req: req, result: resultCh})
			ed.writeOutput(func() {
				renderConfirmPrompt(req, ui.Cols())
			})
			defer pendingConfirm.Store(nil)
			var decision agent.Decision
			select {
			case d := <-resultCh:
				decision = d
			case <-ctx.Done():
				decision = agent.DecisionDeny
			}
			rec.RecordRiskPrompt(req.Tool, decisionLabel(decision))
			if decision == agent.DecisionDeny {
				denyPayload := map[string]any{
					"tool":  req.Tool,
					"risk":  req.Risk.String(),
					"input": string(req.Input),
				}
				wh.Fire(webhook.EventRiskDenied, denyPayload)
				mqttBridge.PublishEvent("risk_denied", denyPayload)
			}
			return decision
		})
	}

	keys := make(chan keyEvent, 64)
	go readKeys(keys)

	turnDone := make(chan turnResult, 4)

	var kbdCtrlCAt atomic.Int64

	dispatchTurn := func(input string) {
		streaming.Store(false)
		ed.writeOutput(func() {
			pad := strings.Repeat(" ", boxPad)
			fmt.Fprintf(os.Stderr, "\n%s%s>%s %s%s%s\n", pad, dim, reset, dim, input, reset)
		})
		_ = flip.SetLED("b", 0xff)
		now := time.Now()
		turnStartedAt.Store(&now)
		turnToolCount.Store(0)
		setNote("Thinking")
		ed.running.Store(true)
		go runTurnStatusBar(ed, &turnStartedAt, &turnNote, &turnToolCount)
		turnCtx, releaseTurn := withCancel(ctx)
		go func() {
			resp, runErr := ai.Run(turnCtx, input)
			releaseTurn()
			turnDone <- turnResult{response: resp, err: runErr}
		}()
	}

	busy := func() bool { return ed.running.Load() }

	// --- Filesystem watch (optional) ---
	// --watch flags take precedence over config.watch.paths; both fold into
	// the same rule set. A goroutine consumes the handler channel and forwards
	// events as REPL turns when the agent is idle, so an FS-triggered prompt
	// never collides with a user prompt mid-flight. Queue depth is bounded —
	// bursts beyond the cap drop events rather than growing unbounded.
	var watchMgr *watch.Watcher
	{
		paths := append([]string(nil), watchPaths...)
		paths = append(paths, cfg.Watch.Paths...)
		var rules []watch.Rule
		for _, r := range cfg.Watch.Rules {
			rules = append(rules, watch.Rule{Pattern: r.Pattern, Prompt: r.Prompt, Persona: r.Persona})
		}
		// Default rule set only applies when the operator asked for --watch
		// but didn't supply config rules — gives the feature sensible defaults
		// without surprising users who configured it explicitly.
		if len(paths) > 0 && len(rules) == 0 {
			rules = []watch.Rule{
				{Pattern: "*.sub", Prompt: "A new Sub-GHz capture landed at {{path}}. Decode it and summarise protocol + key data."},
				{Pattern: "*.nfc", Prompt: "A new NFC capture landed at {{path}}. Identify type, UID, sectors."},
				{Pattern: "*.rfid", Prompt: "A new RFID capture landed at {{path}}. Report protocol and UID."},
				{Pattern: "*.png", Prompt: "Analyze {{path}} — what Flipper-relevant thing is this?"},
				{Pattern: "*.jpg", Prompt: "Analyze {{path}} — what Flipper-relevant thing is this?"},
				{Pattern: "*.txt", Prompt: "Validate {{path}} as a BadUSB payload and summarise what it does."},
			}
		}
		if len(paths) > 0 {
			watchMgr = watch.New(paths, rules)
			events := make(chan struct {
				rule watch.Rule
				path string
			}, 16)
			watchCtx, cancelWatch := context.WithCancel(ctx)
			defer cancelWatch()
			go func() {
				if err := watchMgr.Run(watchCtx, func(r watch.Rule, p string) error {
					select {
					case events <- struct {
						rule watch.Rule
						path string
					}{r, p}:
					default:
						// Queue full — record and move on rather than blocking
						// the fsnotify goroutine. Bursts of 16+ events in the
						// debounce window are the only way this trips.
						ed.writeOutput(func() {
							fmt.Fprintf(os.Stderr, "  %s● watch queue full; dropping %s%s\n", yellow, p, reset)
						})
					}
					return nil
				}); err != nil {
					ed.writeOutput(func() {
						fmt.Fprintf(os.Stderr, "  %s● watch error: %v%s\n", red, err, reset)
					})
				}
			}()
			go func() {
				for {
					select {
					case <-watchCtx.Done():
						return
					case ev := <-events:
						// Wait until the REPL is idle before dispatching so
						// user turns and watch turns don't interleave.
						for ed.running.Load() {
							select {
							case <-watchCtx.Done():
								return
							case <-time.After(250 * time.Millisecond):
							}
						}
						if ev.rule.Persona != "" {
							if p, ok := personas.Get(ev.rule.Persona); ok {
								ai.SetPersona(p)
							}
						}
						ed.writeOutput(func() {
							fmt.Fprintf(os.Stderr, "  %s● watch fired:%s %s %s→%s %s\n",
								yellow, reset, ev.path, dim, reset, collapseWS(ev.rule.Prompt))
						})
						dispatchTurn(ev.rule.Prompt)
					}
				}
			}()
			statusOK(fmt.Sprintf("Watch active on %s%d path%s%s", bold, len(paths), plural(len(paths)), reset))
		}
	}

	deps := &REPLDeps{
		ctx:           ctx,
		cfg:           cfg,
		ai:            ai,
		flip:          flip,
		genLLM:        genLLM,
		hasMarauder:   hasMarauder,
		hasVoice:      voiceEngine != nil,
		auditLog:      auditLog,
		rec:           rec,
		activePersona: activePersona,
		personas:      personas,
		costTracker:   costTracker,
		watchMgr:      watchMgr,
		wh:            wh,
		mqttBridge:    mqttBridge,
		ruleEngine:    ruleEngine,
		ed:            ed,
		busy:          busy,
	}

	// handleSubmit is invoked when the user presses Enter. Returns true
	// when the REPL should exit.
	handleSubmit := func(raw string) bool {
		input := strings.TrimSpace(raw)

		if input == "" && voiceMode {
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "  %s● Recording...%s (stops on silence)\n", red, reset)
			})
			tmpFile := filepath.Join(os.TempDir(), "promptzero_voice.wav")
			if err := voiceEngine.Record(tmpFile); err != nil {
				ed.writeOutput(func() {
					fmt.Fprintf(os.Stderr, "  %s● Recording error: %v%s\n", red, err, reset)
				})
				return false
			}
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "  %s● Transcribing...%s\n", blue, reset)
			})
			text, err := voiceEngine.Transcribe(tmpFile)
			os.Remove(tmpFile)
			if err != nil {
				ed.writeOutput(func() {
					fmt.Fprintf(os.Stderr, "  %s● Transcription error: %v%s\n", red, err, reset)
				})
				return false
			}
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "  %s● You said:%s %s\n", green, reset, text)
			})
			input = text
		}

		if input == "" {
			return false
		}

		if handled, exit := dispatchSlashCommand(input, deps); handled {
			return exit
		}

		if ed.running.Load() {
			ed.setQueued(input)
			ed.writeOutput(func() {
				pad := strings.Repeat(" ", boxPad)
				fmt.Fprintf(os.Stderr, "\n%s%s>%s %s%s %s(queued)%s\n",
					pad, dim, reset, dim, input, dim, reset)
			})
			return false
		}
		dispatchTurn(input)
		return false
	}

	ed.render()

	for {
		select {
		case k, ok := <-keys:
			if !ok {
				return nil
			}
			// Hijack keystrokes when a risk confirmation is pending.
			// The line editor stays in whatever state it was in; it is
			// redrawn after the callback resolves.
			if cs := pendingConfirm.Load(); cs != nil {
				if resolveConfirmKey(cs, k, ed) {
					pendingConfirm.Store(nil)
				}
				continue
			}
			switch k.kind {
			case keyEOF:
				return nil
			case keyRune:
				ed.insert(k.r)
				ed.render()
			case keyPaste:
				ed.insertPaste(k.text)
				ed.render()
			case keyEnter:
				s := ed.takeInput()
				ed.render()
				if handleSubmit(s) {
					return nil
				}
			case keyBackspace:
				ed.backspace()
				ed.render()
			case keyDelete:
				ed.deleteForward()
				ed.render()
			case keyLeft:
				ed.moveLeft()
				ed.render()
			case keyRight:
				ed.moveRight()
				ed.render()
			case keyHome, keyCtrlA:
				ed.moveHome()
				ed.render()
			case keyEnd, keyCtrlE:
				ed.moveEnd()
				ed.render()
			case keyUp:
				ed.browseHistory(-1)
				ed.render()
			case keyDown:
				ed.browseHistory(+1)
				ed.render()
			case keyCtrlL:
				ed.clearScreen()
			case keyCtrlC:
				const doubleTapWindow = 2 * time.Second
				now := time.Now().UnixNano()
				prev := kbdCtrlCAt.Swap(now)
				if prev != 0 && time.Duration(now-prev) < doubleTapWindow {
					ed.writeOutput(func() {
						fmt.Fprintf(os.Stderr, "\n  %sGoodbye.%s\n\n", dim, reset)
					})
					return nil
				}
				if cfp := currentCancel.Load(); cfp != nil {
					(*cfp)()
				}
				ed.writeOutput(func() {
					fmt.Fprintf(os.Stderr, "\n  %s(Ctrl+C again within 2s to exit)%s\n", dim, reset)
				})
			case keyCtrlD:
				if len(ed.buf) == 0 {
					ed.writeOutput(func() {
						fmt.Fprintf(os.Stderr, "\n  %sShutting down.%s\n\n", dim, reset)
					})
					return nil
				}
			}
		case r := <-turnDone:
			ed.running.Store(false)
			_ = flip.SetLED("b", 0)
			streamed := streaming.Swap(false)
			// Close any in-flight delta stream first so subsequent atomic
			// writes land on a fresh row instead of racing writeDelta's
			// save/restore cursor.
			if streamed {
				ed.endDelta()
			}
			ed.writeOutput(func() {
				if r.err != nil {
					fmt.Fprintf(os.Stderr, "  %s● Error: %v%s\n\n", red, r.err, reset)
				} else if streamed {
					// Response already rendered via text deltas; separator.
					fmt.Fprintf(os.Stderr, "\n")
				} else {
					fmt.Fprintf(os.Stdout, "\n%s\n\n", r.response)
				}
			})
			if q, ok := ed.popQueued(); ok {
				ed.render()
				dispatchTurn(q)
			}
		}
	}
}
