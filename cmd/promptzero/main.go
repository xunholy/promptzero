package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/generate"
	"github.com/xunholy/promptzero/internal/marauder"
	"github.com/xunholy/promptzero/internal/mcp"
	"github.com/xunholy/promptzero/internal/provider"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/voice"
	"github.com/xunholy/promptzero/internal/web"
	"golang.org/x/term"
)

// turnResult is the outcome of one ai.Run, delivered back to the REPL
// select loop so it can update UI state on the main goroutine.
type turnResult struct {
	response string
	err      error
}

var version = "dev"

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
		cfgPath        string
		portOverride   string
		webMode        bool
		webPort        int
		voiceMode      bool
		wifiEnabled    bool
		mcpMode        bool
		showVersion    bool
		doInit         bool
		resumeID       string
		autoResume     bool
		genProvider    string
		ollamaURL      string
		ollamaModel    string
		connectTimeout time.Duration
		yoloMode       bool
		confirmRisk    string
	)

	flag.StringVar(&cfgPath, "config", "config.yaml", "Path to config file")
	flag.StringVar(&portOverride, "port", "", "Flipper serial port (overrides config; e.g., /dev/ttyACM1 for a second device)")
	flag.BoolVar(&webMode, "web", false, "Start web UI mode")
	flag.IntVar(&webPort, "web-port", 0, "Web server port (overrides config)")
	flag.BoolVar(&voiceMode, "voice", false, "Enable voice input (requires sox + OPENAI_API_KEY)")
	flag.BoolVar(&wifiEnabled, "wifi", false, "Connect to ESP32 Marauder WiFi devboard")
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
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.Parse()

	if showVersion {
		fmt.Printf("promptzero %s\n", version)
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

	// Multi-Flipper sanity check: if several ACM-class serial devices are
	// present and the user didn't pin a specific one via --port, warn so a
	// surprising device doesn't get driven blindly.
	if portOverride == "" && strings.HasPrefix(cfg.Serial.Port, "/dev/ttyACM") {
		if matches, _ := filepath.Glob("/dev/ttyACM*"); len(matches) > 1 {
			statusWarn(fmt.Sprintf("Multiple Flipper-class serial devices detected (%s) — using configured port; use --port to target a specific device.",
				strings.Join(matches, ", ")))
		}
	}

	// --- Connect to Flipper ---
	statusInfo(fmt.Sprintf("Connecting to Flipper Zero on %s%s%s... %s(timeout %s, press Ctrl+C to cancel)%s", bold, cfg.Serial.Port, reset, dim, connectTimeout, reset))
	start := time.Now()
	connectCtx, releaseConnect := withCancel(ctx)
	flip, err := flipper.Connect(connectCtx, cfg.Serial.Port, cfg.Serial.BaudRate, connectTimeout)
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

	// --- Risk confirmation threshold ---
	// Flags override config; --yolo is shorthand for --confirm-risk=none.
	// Callback registration happens later (interactive REPL only); MCP/web
	// paths keep confirmCb nil so tools execute without prompting.
	threshold, gateEnabled, resolveErr := resolveConfirmRisk(cfg.ConfirmRisk, confirmRisk, yoloMode)
	if resolveErr != nil {
		statusWarn(resolveErr.Error())
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
		// Empty Host is intentional: web.NewServer rewrites empty / 0.0.0.0
		// to loopback by default and warns loudly if the user set a
		// non-loopback host explicitly in config.
		addr := fmt.Sprintf("%s:%d", cfg.Web.Host, cfg.Web.Port)
		srv := web.NewServer(addr, ai, voiceEngine)
		statusOK(fmt.Sprintf("Web UI at %s%shttp://%s%s", bold, cyan, addr, reset))
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

	// P8 wiring — stream assistant text as it arrives.
	ai.SetTextDeltaCallback(func(td agent.TextDelta) {
		ed.writeOutput(func() {
			if streaming.CompareAndSwap(false, true) {
				// First delta of a streaming run: wipe any stale status on
				// the current row so deltas start at column 1.
				fmt.Fprint(os.Stderr, "\r\033[K")
				setNote("Responding")
			}
			fmt.Fprint(os.Stderr, td.Text)
		})
	})

	// Tool-call status: routed through the editor so concurrent keystroke
	// redraws and tool events don't trample each other. P1 adds an inline
	// one-line output preview after each tool finish.
	ai.SetToolStatusCallback(func(ev agent.ToolEvent) {
		ed.writeOutput(func() {
			// Close any streaming text line before overwriting this row.
			if streaming.Swap(false) {
				fmt.Fprintln(os.Stderr)
			}
			switch ev.Phase {
			case "start":
				setNote("Running " + ev.Name)
				fmt.Fprintf(os.Stderr, "\r\033[K  %s▸%s %s %s%s%s\n", cyan, reset, ev.Name, dim, truncateArgs(ev.Input), reset)
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
	})

	// --- Risk confirmation prompt ---
	// The callback fires from the ai.Run goroutine. It parks a pendingConfirm
	// state and blocks on resultCh; the main REPL select loop routes the next
	// keystroke into that channel (see "pendingConfirm" check in the select
	// below) instead of the line editor.
	var pendingConfirm atomic.Pointer[confirmState]
	if gateEnabled {
		ai.SetConfirmCallback(func(ctx context.Context, req agent.ConfirmRequest) agent.Decision {
			resultCh := make(chan agent.Decision, 1)
			pendingConfirm.Store(&confirmState{req: req, result: resultCh})
			ed.writeOutput(func() {
				renderConfirmPrompt(req, ui.Cols())
			})
			defer pendingConfirm.Store(nil)
			select {
			case d := <-resultCh:
				return d
			case <-ctx.Done():
				return agent.DecisionDeny
			}
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

		lower := strings.ToLower(input)
		switch {
		case lower == "/quit" || lower == "/exit" || lower == "quit" || lower == "exit" || lower == "q":
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "\n  %sShutting down.%s\n\n", dim, reset)
			})
			return true
		case lower == "/reset" || lower == "/clear" || lower == "reset" || lower == "clear":
			ai.Reset()
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "  %s● Conversation cleared.%s\n\n", green, reset)
			})
			return false
		case lower == "/help" || lower == "?":
			ed.writeOutput(func() { printHelp() })
			return false
		case lower == "/status":
			ed.writeOutput(func() { printStatus(cfg, genLLM, hasMarauder, voiceEngine != nil, auditLog, flip, busy) })
			return false
		case lower == "/sessions":
			ed.writeOutput(func() { printSessions(ai) })
			return false
		case lower == "/reconnect":
			// Force-reconnect to the Flipper. The SetReconnectCallback
			// above surfaces phase messages in the output area; we just
			// need to call it. Short ctx so a stuck reconnect doesn't
			// block the REPL indefinitely.
			go func() {
				reCtx, cancelRe := context.WithTimeout(ctx, 15*time.Second)
				defer cancelRe()
				if err := flip.Reconnect(reCtx); err != nil {
					ed.writeOutput(func() {
						fmt.Fprintf(os.Stderr, "  %s● reconnect failed: %v%s\n", red, err, reset)
					})
				}
			}()
			return false
		}

		// Parametric commands (first token dispatch).
		fields := strings.Fields(input)
		if len(fields) > 0 {
			head := strings.ToLower(fields[0])
			switch head {
			case "/history":
				n := 20
				if len(fields) > 1 {
					if parsed, err := strconv.Atoi(fields[1]); err == nil && parsed > 0 {
						n = parsed
					}
				}
				ed.writeOutput(func() { printHistory(auditLog, n) })
				return false
			case "/audit":
				ed.writeOutput(func() { handleAudit(auditLog, fields[1:]) })
				return false
			case "/tools":
				filter := ""
				if len(fields) > 1 {
					filter = fields[1]
				}
				ed.writeOutput(func() { printTools(hasMarauder, filter) })
				return false
			case "/resume":
				if len(fields) < 2 {
					ed.writeOutput(func() {
						fmt.Fprintf(os.Stderr, "  %susage: /resume <session-id>%s\n", dim, reset)
					})
					return false
				}
				id := fields[1]
				ed.writeOutput(func() {
					if err := ai.ResumeSession(id); err != nil {
						fmt.Fprintf(os.Stderr, "  %s● resume failed: %v%s\n", red, err, reset)
					} else {
						fmt.Fprintf(os.Stderr, "  %s● resumed session %s%s%s\n", green, bold, id, reset)
					}
				})
				return false
			case "/save":
				if len(fields) < 2 {
					ed.writeOutput(func() {
						fmt.Fprintf(os.Stderr, "  %susage: /save <name>%s\n", dim, reset)
					})
					return false
				}
				name := fields[1]
				ed.writeOutput(func() {
					if err := ai.SaveSessionAs(name); err != nil {
						fmt.Fprintf(os.Stderr, "  %s● save failed: %v%s\n", red, err, reset)
					} else {
						fmt.Fprintf(os.Stderr, "  %s● saved session as %s%s%s\n", green, bold, name, reset)
					}
				})
				return false
			}
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
			ed.writeOutput(func() {
				if r.err != nil {
					if streamed {
						fmt.Fprintln(os.Stderr)
					} else {
						fmt.Fprintf(os.Stderr, "\r\033[K")
					}
					fmt.Fprintf(os.Stderr, "  %s● Error: %v%s\n\n", red, r.err, reset)
				} else if streamed {
					// Response already rendered via text deltas.
					fmt.Fprintf(os.Stderr, "\n\n")
				} else {
					fmt.Fprintf(os.Stderr, "\r\033[K")
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

// --- First-run & init -----------------------------------------------------

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
	// Prefer the file on disk (so edits stay in sync), fall back to the
	// embedded template when the binary is run far from the repo.
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

// --- Slash-command renderers ---------------------------------------------

func printHelp() {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  %s%sCommands%s\n", bold, white, reset)
	fmt.Fprintf(os.Stderr, "  %sConversation%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "    %s/help%s, %s?%s            Show this help\n", cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/reset%s, %s/clear%s      Clear conversation history\n", cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/quit%s, %s/exit%s, %sq%s    Exit promptzero\n", cyan, reset, cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %sSession%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "    %s/sessions%s              List saved sessions\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/resume <id>%s           Resume a saved session by id\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/save <name>%s           Save current conversation under <name>\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %sInfo%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "    %s/status%s                Connection, capabilities, Flipper telemetry\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/tools [filter]%s        Enumerate registered tools (grouped)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/history [N]%s           Show last N audit rows (default 20)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit stats%s           Session audit summary\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s/audit export <path>%s   Write session audit JSON to <path>\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %sDevice%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "    %s/reconnect%s             Force reconnect to the Flipper (after replug / USB hiccup)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %sInput%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "    %sEnter%s (blank, voice)   In voice mode, records; otherwise no-op\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %sCtrl+C%s                 Cancel in-flight turn (press again within 2s to exit)\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %sCtrl+D%s                 Exit on empty input\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %sCtrl+L%s                 Clear screen\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %sUp%s/%sDown%s                 Browse history\n", cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "    %sCtrl+A%s/%sCtrl+E%s          Move cursor to line start / end\n", cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "\n  %s%sFlipper device feedback%s\n", bold, white, reset)
	fmt.Fprintf(os.Stderr, "    %s●%s Blue LED on          Flipper is actively scanning (RFID/NFC/SubGHz/IR/iButton)\n", blue, reset)
	fmt.Fprintf(os.Stderr, "    %s●%s Vibration buzz       Tag/signal detected and read successfully\n", green, reset)
	fmt.Fprintf(os.Stderr, "    %s●%s Idle                 Scan timed out (nothing detected)\n", dim, reset)
	fmt.Fprintf(os.Stderr, "  %sCLI commands like `rfid read` do NOT launch an on-screen app on the Flipper.%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "  %sTheir only visible indicator is the LED/vibro feedback above.%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "\n  %s%sAgent / tool-call legend%s\n", bold, white, reset)
	fmt.Fprintf(os.Stderr, "    %s▸%s tool {args}          Tool is executing\n", cyan, reset)
	fmt.Fprintf(os.Stderr, "    %s◦%s tool (1.3s)          Tool completed\n", green, reset)
	fmt.Fprintf(os.Stderr, "    %s✗%s tool (15s)           Tool errored or timed out\n", red, reset)
	fmt.Fprintf(os.Stderr, "\n  %s%sRisk confirmation%s\n", bold, white, reset)
	fmt.Fprintf(os.Stderr, "    %s⚠%s tool {args}          Awaiting approval (high/critical risk)\n", yellow, reset)
	fmt.Fprintf(os.Stderr, "    %sy%s approve · %sN%s / Enter deny (default) · type %sall%s + Enter to approve all remaining\n",
		bold+green, reset, bold+red, reset, bold+cyan, reset)
	fmt.Fprintf(os.Stderr, "    Use %s--yolo%s to disable, or %s--confirm-risk=<level>%s to adjust threshold.\n", cyan, reset, cyan, reset)
	fmt.Fprintf(os.Stderr, "\n")
}

func printStatus(cfg *config.Config, genLLM provider.Provider, wifi bool, hasVoice bool, auditLog *audit.Log, flip *flipper.Flipper, busy func() bool) {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  %s%sStatus%s\n", bold, white, reset)
	statusOK(fmt.Sprintf("Flipper Zero on %s", cfg.Serial.Port))
	statusOK(fmt.Sprintf("Agent model: %s", cfg.Model))
	statusOK(fmt.Sprintf("Generation: %s", genLLM.Name()))
	if wifi {
		statusOK(fmt.Sprintf("Marauder on %s", cfg.Marauder.Port))
	} else {
		statusWarn("Marauder not connected (use --wifi)")
	}
	if hasVoice {
		statusOK("Voice input (Whisper)")
	} else {
		statusWarn("Voice not configured (set OPENAI_API_KEY)")
	}
	if auditLog != nil {
		statusOK(fmt.Sprintf("Audit session: %s", auditLog.SessionID()))
	} else {
		statusWarn("Audit logging disabled")
	}

	fmt.Fprintf(os.Stderr, "\n  %s%sDevice%s\n", bold, white, reset)
	if flip == nil {
		statusWarn("Flipper unavailable")
	} else {
		summary := cachedDeviceSummary(flip, busy)
		fmt.Fprintf(os.Stderr, "  %s%s%s\n", dim, summary, reset)
	}
	fmt.Fprintf(os.Stderr, "\n")
}

// --- Device telemetry cache (P6) -----------------------------------------

var deviceCache struct {
	sync.Mutex
	at      time.Time
	summary string
}

const deviceCacheTTL = 5 * time.Second

func cachedDeviceSummary(flip *flipper.Flipper, busy func() bool) string {
	deviceCache.Lock()
	defer deviceCache.Unlock()
	if time.Since(deviceCache.at) < deviceCacheTTL && deviceCache.summary != "" {
		return deviceCache.summary
	}
	if busy != nil && busy() {
		if deviceCache.summary != "" {
			return deviceCache.summary + "  (stale, turn in flight)"
		}
		return "(turn in flight — skipping device fetch)"
	}
	s := deviceSummary(flip)
	deviceCache.at = time.Now()
	deviceCache.summary = s
	return s
}

func deviceSummary(flip *flipper.Flipper) string {
	var parts []string
	if raw, err := flip.PowerInfo(); err == nil {
		if pct := parseKVField(raw, "charge_level"); pct != "" {
			parts = append(parts, "Battery "+pct+"%")
		} else if pct := parseKVField(raw, "battery_charge"); pct != "" {
			parts = append(parts, "Battery "+pct+"%")
		}
	}
	if raw, err := flip.DeviceInfo(); err == nil {
		if fw := parseKVField(raw, "firmware_version"); fw != "" {
			parts = append(parts, "FW "+fw)
		} else if fw := parseKVField(raw, "hardware_model"); fw != "" {
			parts = append(parts, "HW "+fw)
		}
	}
	if raw, err := flip.StorageStat("/ext"); err == nil {
		line := strings.TrimSpace(firstLine(raw))
		if line != "" {
			parts = append(parts, "SD "+line)
		}
	}
	if len(parts) == 0 {
		return "no telemetry available"
	}
	return strings.Join(parts, " · ")
}

// parseKVField scans a Flipper CLI key/value dump for "<key>: <value>" or
// "<key> : <value>" lines and returns the trimmed value. Empty string if
// the key is absent.
func parseKVField(raw, key string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		trim := strings.TrimSpace(line)
		if !strings.HasPrefix(trim, key) {
			continue
		}
		rest := strings.TrimPrefix(trim, key)
		rest = strings.TrimLeft(rest, " \t:")
		rest = strings.TrimSpace(rest)
		if rest != "" {
			return rest
		}
	}
	return ""
}

// --- /history + /audit ----------------------------------------------------

func printHistory(auditLog *audit.Log, n int) {
	if auditLog == nil {
		fmt.Fprintf(os.Stderr, "  %saudit log not available%s\n", dim, reset)
		return
	}
	if n <= 0 {
		n = 20
	}
	entries, err := auditLog.Query(n)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s● history error: %v%s\n", red, err, reset)
		return
	}
	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "  %sno audit entries yet%s\n", dim, reset)
		return
	}
	for _, e := range entries {
		ts := e.Timestamp.Local().Format("15:04:05")
		input := collapseWS(e.Input)
		if len(input) > 40 {
			input = input[:39] + "…"
		}
		errMark := ""
		if !e.Success {
			errMark = " " + red + "✗" + reset
		}
		color := riskColor(e.Risk)
		risk := e.Risk
		if risk == "" {
			risk = "-"
		}
		fmt.Fprintf(os.Stderr, "  %s  %s[%s]%s  %s  %s(%dms)%s%s  %s%s%s\n",
			ts, color, risk, reset, e.Tool, dim, e.Duration, reset, errMark, dim, input, reset)
	}
}

func handleAudit(auditLog *audit.Log, args []string) {
	if auditLog == nil {
		fmt.Fprintf(os.Stderr, "  %saudit log not available%s\n", dim, reset)
		return
	}
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "  %susage: /audit stats | /audit export <path>%s\n", dim, reset)
		return
	}
	switch strings.ToLower(args[0]) {
	case "stats":
		s, err := auditLog.Stats()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● audit stats error: %v%s\n", red, err, reset)
			return
		}
		for _, line := range strings.Split(s, "\n") {
			fmt.Fprintf(os.Stderr, "  %s\n", line)
		}
	case "export":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "  %susage: /audit export <path>%s\n", dim, reset)
			return
		}
		path := args[1]
		data, err := auditLog.Export()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s● export error: %v%s\n", red, err, reset)
			return
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "  %s● write error: %v%s\n", red, err, reset)
			return
		}
		fmt.Fprintf(os.Stderr, "  %s●%s wrote %s\n", green, reset, path)
	default:
		fmt.Fprintf(os.Stderr, "  %sunknown /audit subcommand %q%s\n", dim, args[0], reset)
	}
}

func riskColor(r string) string {
	switch strings.ToLower(r) {
	case "low":
		return green
	case "medium":
		return yellow
	case "high":
		return red
	case "critical":
		return bold + red
	default:
		return gray
	}
}

func collapseWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// --- /sessions ------------------------------------------------------------

func printSessions(ai *agent.Agent) {
	sessions, err := ai.ListSessions()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s● sessions: %v%s\n", red, err, reset)
		return
	}
	if len(sessions) == 0 {
		fmt.Fprintf(os.Stderr, "  %sno sessions%s\n", dim, reset)
		return
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].UpdatedAt.After(sessions[j].UpdatedAt)
	})
	for _, s := range sessions {
		fmt.Fprintf(os.Stderr, "  %s%s%s  %s  %s%d msg%s\n",
			bold, s.ID, reset,
			s.UpdatedAt.Local().Format("2006-01-02 15:04"),
			dim, len(s.Messages), reset)
	}
}

// --- /tools ---------------------------------------------------------------

const toolsMaxRows = 40

func printTools(hasMarauder bool, filter string) {
	catalog := agent.ToolCatalog(hasMarauder)
	filtered := catalog
	lowerFilter := strings.ToLower(filter)
	if lowerFilter != "" {
		filtered = filtered[:0:0]
		for _, e := range catalog {
			if strings.Contains(strings.ToLower(e.Name), lowerFilter) {
				filtered = append(filtered, e)
			}
		}
	}
	if len(filtered) == 0 {
		if filter != "" {
			fmt.Fprintf(os.Stderr, "  %sno tools match %q%s\n", dim, filter, reset)
		} else {
			fmt.Fprintf(os.Stderr, "  %sno tools registered%s\n", dim, reset)
		}
		return
	}

	groups := map[string][]agent.ToolCatalogEntry{}
	var order []string
	for _, e := range filtered {
		g := toolGroup(e.Name)
		if _, ok := groups[g]; !ok {
			order = append(order, g)
		}
		groups[g] = append(groups[g], e)
	}
	sort.Strings(order)

	shown := 0
	fmt.Fprintln(os.Stderr)
outer:
	for _, g := range order {
		fmt.Fprintf(os.Stderr, "  %s%s%s%s\n", bold, white, g, reset)
		for _, e := range groups[g] {
			if shown >= toolsMaxRows {
				break outer
			}
			fmt.Fprintf(os.Stderr, "    %s%s%s  %s%s%s\n", cyan, e.Name, reset, dim, toolDescSummary(e.Description), reset)
			shown++
		}
	}
	if shown < len(filtered) {
		hint := "/tools <filter>"
		if filter != "" {
			hint = "use a narrower filter"
		}
		fmt.Fprintf(os.Stderr, "  %s… and %d more, try %s%s\n", dim, len(filtered)-shown, hint, reset)
	}
	fmt.Fprintln(os.Stderr)
}

// toolDescSummary returns the leading sentence of a tool description,
// trimmed to ~60 chars for use next to the tool name.
func toolDescSummary(desc string) string {
	desc = strings.TrimSpace(desc)
	if desc == "" {
		return ""
	}
	if i := strings.Index(desc, ". "); i > 0 {
		desc = desc[:i]
	}
	desc = collapseWS(desc)
	const max = 60
	if len(desc) > max {
		desc = desc[:max-1] + "…"
	}
	return desc
}

func toolGroup(name string) string {
	if i := strings.Index(name, "_"); i > 0 {
		return name[:i]
	}
	return "misc"
}

// --- Misc helpers ---------------------------------------------------------

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// truncateArgs renders a tool's JSON input for inline display: collapsed
// whitespace, trimmed to 60 chars. Empty args render as "{}".
func truncateArgs(raw []byte) string {
	s := strings.Join(strings.Fields(string(raw)), " ")
	if s == "" {
		return "{}"
	}
	const max = 60
	if len(s) > max {
		s = s[:max-1] + "…"
	}
	return s
}

// --- Risk confirmation ---------------------------------------------------

// confirmState carries an in-flight risk-confirmation request. The callback
// goroutine populates it; the REPL event loop drains it on the next key.
// typing buffers characters while the user spells out "all" + Enter — we
// refuse to bind approve-all to a single key since one stray paste would
// disable the risk gate for the rest of the turn.
type confirmState struct {
	req    agent.ConfirmRequest
	result chan agent.Decision
	typing []rune
}

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

// renderConfirmPrompt paints the two-line prompt shown before a destructive
// tool runs. Lives inside ed.writeOutput so it plays nicely with streaming
// output and tool-status redraws.
// spinnerFrames cycles through braille dots at 100ms intervals; looks like
// a smooth pulse in any modern terminal that renders unicode.
var spinnerFrames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// formatElapsed renders a running turn's elapsed time compactly: seconds
// under a minute, "Nm SSs" at or above a minute.
func formatElapsed(d time.Duration) string {
	s := int(d.Round(time.Second) / time.Second)
	if s < 60 {
		return fmt.Sprintf("%ds", s)
	}
	return fmt.Sprintf("%dm%02ds", s/60, s%60)
}

// runTurnStatusBar ticks every 100ms and redraws the box's top border with
// a spinner, the current note ("Thinking" / "Running <tool>" / "Responding"),
// elapsed time, tool count, and a Ctrl+C hint. When a prompt is queued it
// also appends "1 queued". Exits as soon as ed.running goes false, leaving
// a plain border behind.
func runTurnStatusBar(ed *lineEditor, started *atomic.Pointer[time.Time], note *atomic.Pointer[string], tools *atomic.Int32) {
	if !ed.ui.enabled {
		return
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	frame := 0
	for {
		if !ed.running.Load() {
			ed.outputMu.Lock()
			ed.ui.drawStatusBorder("")
			ed.renderLocked()
			ed.outputMu.Unlock()
			return
		}
		<-ticker.C
		if !ed.running.Load() {
			ed.outputMu.Lock()
			ed.ui.drawStatusBorder("")
			ed.renderLocked()
			ed.outputMu.Unlock()
			return
		}
		startedAt := started.Load()
		if startedAt == nil {
			continue
		}
		n := ""
		if p := note.Load(); p != nil {
			n = *p
		}
		var parts []string
		parts = append(parts, fmt.Sprintf("%c %s", spinnerFrames[frame], n))
		parts = append(parts, formatElapsed(time.Since(*startedAt)))
		if tc := tools.Load(); tc > 0 {
			parts = append(parts, fmt.Sprintf("%d tools", tc))
		}
		if ed.hasQueued.Load() {
			parts = append(parts, "1 queued")
		}
		parts = append(parts, "Ctrl+C to interrupt")
		status := strings.Join(parts, " · ")
		ed.outputMu.Lock()
		ed.ui.drawStatusBorder(status)
		ed.renderLocked()
		ed.outputMu.Unlock()
		frame = (frame + 1) % len(spinnerFrames)
	}
}

func renderConfirmPrompt(req agent.ConfirmRequest, cols int) {
	pad := strings.Repeat(" ", boxPad)
	// Size the args budget to the terminal width so a long JSON blob can't
	// overflow into a right-border-munging mess.
	argsBudget := cols - boxPad - 2 - len("⚠ About to run ") - len(req.Tool) - 1
	if argsBudget < 20 {
		argsBudget = 20
	}
	args := truncateArgsTo(req.Input, argsBudget)
	fmt.Fprintf(os.Stderr, "\r\033[K\n%s%s⚠ About to run%s %s%s%s %s%s%s\n",
		pad, yellow, reset, bold, req.Tool, reset, dim, args, reset)
	riskStr := fmt.Sprintf("%s  risk: %s%s%s", pad, riskColor(req.Risk.String()), req.Risk.String(), reset)
	approve := fmt.Sprintf("%s[y]%s approve", bold+green, reset)
	approveAll := fmt.Sprintf("type %sall%s+Enter to approve all remaining", bold+cyan, reset)
	deny := fmt.Sprintf("%s[N]%s deny (default)", bold+red, reset)
	if cols < 80 {
		fmt.Fprintf(os.Stderr, "%s\n", riskStr)
		fmt.Fprintf(os.Stderr, "%s    %s\n", pad, approve)
		fmt.Fprintf(os.Stderr, "%s    %s\n", pad, deny)
		fmt.Fprintf(os.Stderr, "%s    %s\n", pad, approveAll)
		return
	}
	fmt.Fprintf(os.Stderr, "%s · %s  %s  %s\n", riskStr, approve, deny, approveAll)
}

// truncateArgsTo renders a tool's JSON input collapsed to one line and
// capped at max chars. Empty args render as "{}".
func truncateArgsTo(raw []byte, max int) string {
	s := strings.Join(strings.Fields(string(raw)), " ")
	if s == "" {
		return "{}"
	}
	if max < 4 {
		max = 4
	}
	if len(s) > max {
		s = s[:max-1] + "…"
	}
	return s
}

// resolveConfirmKey interprets one keystroke as a confirmation answer.
// Returns true when the key resolved the prompt (and the caller should
// clear pendingConfirm). Non-decision keys (cursor moves, etc.) are
// dropped so stray arrow-key escapes don't accidentally approve.
//
// Single-key answers: y/Y approves this one, n/N denies, Enter/Esc/Ctrl+C
// denies. Any other printable key flips into "type-in" mode: we buffer
// characters until Enter. If the buffer equals "all", that's approve-all;
// anything else denies. This is deliberately slower than a single key so
// a stray paste or leaning on the keyboard can't disable the risk gate.
func resolveConfirmKey(cs *confirmState, k keyEvent, ed *lineEditor) bool {
	// Typed-word mode: the user has started spelling something, so queue
	// printable runes and act only on Enter / backspace / cancel keys.
	if cs.typing != nil {
		switch k.kind {
		case keyEnter:
			typed := strings.ToLower(strings.TrimSpace(string(cs.typing)))
			var d agent.Decision
			if typed == "all" {
				d = agent.DecisionApproveAll
			} else {
				d = agent.DecisionDeny
			}
			return confirmResolve(cs, d, ed)
		case keyBackspace:
			if len(cs.typing) > 0 {
				cs.typing = cs.typing[:len(cs.typing)-1]
			}
			return false
		case keyCtrlC, keyCtrlD, keyEOF:
			return confirmResolve(cs, agent.DecisionDeny, ed)
		case keyRune:
			cs.typing = append(cs.typing, k.r)
			return false
		default:
			return false
		}
	}

	switch k.kind {
	case keyRune:
		switch k.r {
		case 'y', 'Y':
			return confirmResolve(cs, agent.DecisionApprove, ed)
		case 'n', 'N':
			return confirmResolve(cs, agent.DecisionDeny, ed)
		default:
			// Start type-in mode. Buffer the rune and show a hint so the
			// user knows approve-all needs the full word.
			cs.typing = []rune{k.r}
			ed.writeOutput(func() {
				pad := strings.Repeat(" ", boxPad)
				fmt.Fprintf(os.Stderr, "%s  %s(type `all` then Enter to approve all remaining this turn, Enter to cancel)%s\n",
					pad, dim, reset)
			})
			return false
		}
	case keyEnter, keyCtrlC, keyCtrlD, keyEOF:
		return confirmResolve(cs, agent.DecisionDeny, ed)
	}
	return false
}

func confirmResolve(cs *confirmState, d agent.Decision, ed *lineEditor) bool {
	ed.writeOutput(func() {
		var label string
		switch d {
		case agent.DecisionApprove:
			label = green + "● approved" + reset
		case agent.DecisionApproveAll:
			label = cyan + "● approved (all remaining)" + reset
		case agent.DecisionDeny:
			label = red + "● denied" + reset
		}
		pad := strings.Repeat(" ", boxPad)
		fmt.Fprintf(os.Stderr, "%s  %s\n", pad, label)
	})
	select {
	case cs.result <- d:
	default:
	}
	return true
}

// outputPreview returns a single dim line summarising a tool's stdout, or a
// red one-liner when the tool errored. Returns "" for empty output, or when
// the output is only a Flipper CLI prompt character — in those cases we
// leave the scroll area alone. Short successful outputs (<20 chars on the
// first line) are also skipped — they don't teach the user anything the
// tool name + duration didn't already show. Errors always render regardless
// of length so failures stay visible.
func outputPreview(out string, isErr bool) string {
	var line string
	for _, raw := range strings.Split(out, "\n") {
		raw = strings.TrimRight(raw, "\r")
		raw = strings.TrimSpace(raw)
		if raw != "" {
			line = raw
			break
		}
	}
	if line == "" || line == ">" {
		return ""
	}
	if !isErr && len(line) < 20 {
		return ""
	}
	line = collapseWS(line)
	cols := 80
	if c, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && c > 20 {
		cols = c
	}
	maxW := cols - 8
	if maxW < 20 {
		maxW = 20
	}
	if len(line) > maxW {
		line = line[:maxW-1] + "…"
	}
	if isErr {
		return "    " + red + line + reset
	}
	return "    " + dim + line + reset
}
