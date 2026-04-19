// pzrunner is a non-interactive harness that drives the promptzero
// Agent end-to-end over a real Flipper. It runs one prompt per command
// line arg (or one prompt from stdin when --stdin is passed), executes
// it against the connected hardware, and emits a JSON record of every
// tool call plus the final assistant response on stdout. Progress goes
// to stderr.
//
// This binary exists so documentation examples and integration checks
// are reproducible: the same agent the REPL uses, without the terminal
// raw-mode UI. It is a development tool — task build does not ship it;
// build explicitly with `go build ./cmd/pzrunner` or `task build:runner`.
//
// Exit codes:
//
//	0  every prompt returned a response
//	1  config load or Flipper connect failed
//	2  flag / usage error
//	3  one or more prompts returned an error from ai.Run
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/generate"
	"github.com/xunholy/promptzero/internal/marauder"
	"github.com/xunholy/promptzero/internal/provider"
)

// connectTimeout bounds the initial Flipper handshake. Independent of
// the per-prompt timeout — connect is I/O-bound, turns are LLM-bound.
const connectTimeout = 10 * time.Second

// outputTruncate caps tool-output length in --quiet mode. Leaves enough
// for a human skim of a JSON response, not so much that transcripts
// balloon.
const outputTruncate = 120

// toolCall is one phase record ("start" or "finish") of a single tool
// invocation. Matches the shape emitted by agent.SetToolStatusCallback.
type toolCall struct {
	Phase      string          `json:"phase"`
	Name       string          `json:"name"`
	Input      json.RawMessage `json:"input,omitempty"`
	DurationMs int64           `json:"duration_ms,omitempty"`
	Err        bool            `json:"err,omitempty"`
	Output     string          `json:"output,omitempty"`
	At         time.Time       `json:"at"`
}

// runResult is the JSON envelope written to stdout per prompt.
type runResult struct {
	Prompt    string     `json:"prompt"`
	Response  string     `json:"response"`
	Error     string     `json:"error,omitempty"`
	Tools     []toolCall `json:"tools"`
	DurationS float64    `json:"duration_s"`
	Model     string     `json:"model"`
}

type cliFlags struct {
	cfgPath     string
	wifi        bool
	stdinIn     bool
	timeoutSec  int
	quiet       bool
	maxTools    int
	keepHistory bool
}

func parseFlags() *cliFlags {
	f := &cliFlags{}
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: pzrunner [flags] "<prompt>" ["<prompt2>" ...]
       pzrunner [flags] --stdin   # read one prompt from stdin

Runs each prompt through the promptzero Agent against the connected
Flipper and prints a JSON record of tool calls + final response to
stdout. Progress goes to stderr.

Flags:`)
		flag.PrintDefaults()
	}
	flag.StringVar(&f.cfgPath, "config", "", "Path to config.yaml (default ~/.promptzero/config.yaml)")
	flag.BoolVar(&f.wifi, "wifi", false, "Enable Marauder WiFi devboard")
	flag.BoolVar(&f.stdinIn, "stdin", false, "Read one prompt from stdin instead of argv")
	flag.IntVar(&f.timeoutSec, "timeout", 120, "Per-prompt timeout in seconds")
	flag.BoolVar(&f.quiet, "quiet", false, "Truncate tool output in stdout JSON")
	flag.IntVar(&f.maxTools, "max-tools", 32, "Cap on tool calls per turn")
	flag.BoolVar(&f.keepHistory, "keep", false, "Keep conversation history across prompts (multi-prompt runs only)")
	flag.Parse()
	return f
}

func main() {
	os.Exit(run())
}

func run() int {
	f := parseFlags()

	prompts, err := readPrompts(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		flag.Usage()
		return 2
	}

	cfg, err := loadConfig(f.cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return 1
	}

	// Overall deadline for the whole run. Each prompt gets its own
	// per-turn budget below; this outer context stops a runaway
	// invocation from holding the serial port forever.
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(f.timeoutSec)*time.Second*time.Duration(len(prompts)))
	defer cancel()

	flip, err := connectFlipper(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flipper: %v\n", err)
		return 1
	}
	defer flip.Close()

	client := anthropic.NewClient()
	ai := agent.New(&client, flip, cfg)
	ai.SetMaxToolsPerTurn(f.maxTools)

	// Generation pipeline: generate_* tools need an LLM provider
	// separate from the agent's chat model. Default to the same Claude
	// client — cheapest option and keeps the one-key story intact.
	genLLM := provider.NewClaude(&client, cfg.Model)
	ai.SetGenerator(generate.New(genLLM, flip))
	ai.SetGenLLM(genLLM)

	if f.wifi || cfg.Marauder.Enabled {
		m, mErr := marauder.Connect(cfg.Marauder.Port, cfg.Marauder.BaudRate)
		if mErr != nil {
			fmt.Fprintf(os.Stderr, "marauder: %v (continuing without)\n", mErr)
		} else {
			defer m.Close()
			ai.SetMarauder(m)
		}
	}

	tracker := newToolTracker()
	ai.SetToolStatusCallback(tracker.onEvent)
	// Deltas land in the final Run() return value too — discard them
	// here so they don't double-print to stderr.
	ai.SetTextDeltaCallback(func(agent.TextDelta) {})

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")

	runErrors := 0
	for _, prompt := range prompts {
		res := runPrompt(ctx, ai, tracker, prompt, cfg.Model, f)
		if res.Error != "" {
			runErrors++
		}
		_ = enc.Encode(res)
	}
	if runErrors > 0 {
		return 3
	}
	return 0
}

// readPrompts returns the prompts to execute in order. Returns an error
// (not os.Exit) so main() can surface the usage text.
func readPrompts(f *cliFlags) ([]string, error) {
	if f.stdinIn {
		if flag.NArg() > 0 {
			return nil, fmt.Errorf("--stdin cannot be combined with argv prompts")
		}
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		text := strings.TrimSpace(string(b))
		if text == "" {
			return nil, fmt.Errorf("stdin is empty")
		}
		return []string{text}, nil
	}
	args := flag.Args()
	if len(args) == 0 {
		return nil, fmt.Errorf("no prompts provided")
	}
	for i, a := range args {
		if strings.TrimSpace(a) == "" {
			return nil, fmt.Errorf("prompt %d is empty", i+1)
		}
	}
	if f.keepHistory && len(args) == 1 {
		fmt.Fprintln(os.Stderr, "note: --keep is a no-op with a single prompt")
	}
	return args, nil
}

// connectFlipper resolves the transport URL from config and brings up
// the serial client. Prints the detected capabilities banner to stderr
// so operators can confirm the right device without parsing JSON.
func connectFlipper(ctx context.Context, cfg *config.Config) (*flipper.Flipper, error) {
	transportURL := fmt.Sprintf("serial://%s?baud=%d", cfg.Serial.Port, cfg.Serial.BaudRate)
	fmt.Fprintf(os.Stderr, "▸ connecting flipper on %s...\n", cfg.Serial.Port)
	flip, err := flipper.ConnectURL(ctx, transportURL, connectTimeout)
	if err != nil {
		return nil, err
	}
	caps, _ := flip.DetectCapabilities()
	name := caps.HardwareName
	if name == "" {
		name = "(unknown)"
	}
	fmt.Fprintf(os.Stderr, "✓ connected: %s · %s %s\n",
		name, strings.TrimSpace(caps.FriendlyFork()), caps.FirmwareVersion)
	return flip, nil
}

// runPrompt executes one turn and returns the JSON envelope. Resets
// the tracker before each prompt and, unless --keep was passed, wipes
// the agent's conversation history so prompts are independent.
func runPrompt(ctx context.Context, ai *agent.Agent, tracker *toolTracker, prompt, model string, f *cliFlags) runResult {
	tracker.reset()
	promptStart := time.Now()

	fmt.Fprintf(os.Stderr, "\n▸ prompt: %s\n", prompt)
	turnCtx, turnCancel := context.WithTimeout(ctx, time.Duration(f.timeoutSec)*time.Second)
	resp, runErr := ai.Run(turnCtx, prompt)
	turnCancel()

	if !f.keepHistory {
		ai.Reset()
	}

	res := runResult{
		Prompt:    prompt,
		Response:  resp,
		DurationS: time.Since(promptStart).Seconds(),
		Model:     model,
		Tools:     tracker.snapshot(),
	}
	if runErr != nil {
		res.Error = runErr.Error()
	}
	if f.quiet {
		truncateOutputs(res.Tools)
	}
	return res
}

func truncateOutputs(tools []toolCall) {
	for i := range tools {
		if len(tools[i].Output) > outputTruncate {
			tools[i].Output = tools[i].Output[:outputTruncate] + "…"
		}
	}
}

// toolTracker batches tool-event records from the agent callback into a
// slice safe for concurrent writers. The agent fires the callback from
// its own goroutine, so every access is mutex-guarded.
type toolTracker struct {
	mu    sync.Mutex
	tools []toolCall
}

func newToolTracker() *toolTracker { return &toolTracker{} }

func (t *toolTracker) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tools = t.tools[:0]
}

func (t *toolTracker) snapshot() []toolCall {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]toolCall, len(t.tools))
	copy(out, t.tools)
	return out
}

func (t *toolTracker) onEvent(ev agent.ToolEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := toolCall{
		Phase: ev.Phase,
		Name:  ev.Name,
		Input: ev.Input,
		At:    time.Now(),
	}
	if ev.Phase == "start" {
		fmt.Fprintf(os.Stderr, "  ▸ %s %s\n", ev.Name, compactJSON(ev.Input))
	} else {
		rec.DurationMs = ev.Duration.Milliseconds()
		rec.Err = ev.Err
		rec.Output = ev.Output
		icon := "◦"
		if ev.Err {
			icon = "✗"
		}
		fmt.Fprintf(os.Stderr, "  %s %s (%dms)\n", icon, ev.Name, ev.Duration.Milliseconds())
	}
	t.tools = append(t.tools, rec)
}

// loadConfig defaults to ~/.promptzero/config.yaml when no --config is
// passed, matching the main promptzero binary's fallback.
func loadConfig(path string) (*config.Config, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolving home dir: %w", err)
		}
		path = filepath.Join(home, ".promptzero", "config.yaml")
	}
	return config.Load(path)
}

// compactJSON collapses whitespace and clips to a fixed width so the
// stderr progress line stays a single row even for big inputs.
func compactJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	s := strings.Join(strings.Fields(string(raw)), " ")
	if len(s) > 100 {
		s = s[:99] + "…"
	}
	return s
}
