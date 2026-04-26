//go:build linux

// Package testmocks centralises the shared mock harness used across
// PromptZero's test surfaces — flipper-agent tests, end-to-end REPL
// tests, workflow tests. Callers get ready-to-use backends without having
// to know which package owns the underlying mock (pty for flipper, fake
// port for marauder, httptest.Server for the Anthropic SDK).
//
// Every constructor registers cleanup hooks with the supplied testing.T,
// so tests don't need to defer Close themselves. Linux-only because the
// underlying flipper mock uses Linux pty syscalls.
package testmocks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/xunholy/promptzero/internal/flipper"
	flippermock "github.com/xunholy/promptzero/internal/flipper/mock"
	"github.com/xunholy/promptzero/internal/marauder"
)

// --- Flipper ---

// MockFlipperOption tunes NewMockFlipper at construction time.
type MockFlipperOption func(*mockFlipperConfig)

type mockFlipperConfig struct {
	handlers map[string]flippermock.Handler
	banner   string
}

// WithFlipperHandler registers a response handler for a Flipper CLI verb
// (the first whitespace-separated word of the command line). Overrides
// any handler the pty mock ships with by default.
func WithFlipperHandler(cmd string, h flippermock.Handler) MockFlipperOption {
	return func(c *mockFlipperConfig) { c.handlers[cmd] = h }
}

// WithFlipperBanner overrides the one-shot welcome banner emitted when
// the Flipper mock's slave fd is first read.
func WithFlipperBanner(s string) MockFlipperOption {
	return func(c *mockFlipperConfig) { c.banner = s }
}

// NewMockFlipper spins up the pty-backed Flipper mock and returns a
// connected *flipper.Flipper ready for assertions. Handshake + capability
// detection both complete before return; on failure t.Fatalf is called.
func NewMockFlipper(t *testing.T, opts ...MockFlipperOption) *flipper.Flipper {
	t.Helper()

	cfg := &mockFlipperConfig{handlers: map[string]flippermock.Handler{}}
	for _, opt := range opts {
		opt(cfg)
	}

	mockOpts := make([]flippermock.Option, 0, len(cfg.handlers)+1)
	for cmd, h := range cfg.handlers {
		mockOpts = append(mockOpts, flippermock.WithHandler(cmd, h))
	}
	if cfg.banner != "" {
		mockOpts = append(mockOpts, flippermock.WithBanner(cfg.banner))
	}

	m := flippermock.Spawn(t, mockOpts...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	flip, err := flipper.ConnectURL(ctx, m.URL(), 5*time.Second)
	if err != nil {
		t.Fatalf("testmocks: flipper connect: %v", err)
	}
	t.Cleanup(func() { _ = flip.Close() })

	if _, err := flip.DetectCapabilities(); err != nil {
		t.Fatalf("testmocks: flipper DetectCapabilities: %v", err)
	}
	return flip
}

// --- Marauder ---

// MockMarauderOption tunes NewMockMarauder at construction time.
type MockMarauderOption func(*fakeMarauderPort)

// WithMarauderResponse preloads a canned response body for the given
// command string (echoed back as "#<cmd>\n<body>\n> "). The body may span
// multiple lines and should not include the trailing prompt.
func WithMarauderResponse(cmd, body string) MockMarauderOption {
	return func(p *fakeMarauderPort) { p.responses[cmd] = body }
}

// NewMockMarauder returns a *marauder.Marauder wired to an in-memory fake
// serial port. Canned responses are registered through options; commands
// that lack a handler still receive a bare echo + prompt so Exec doesn't
// hang waiting on silence.
func NewMockMarauder(t *testing.T, opts ...MockMarauderOption) *marauder.Marauder {
	t.Helper()
	fp := newFakeMarauderPort()
	for _, opt := range opts {
		opt(fp)
	}
	m := marauder.NewWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// fakeMarauderPort is the shared in-memory port backing NewMockMarauder.
// Write bytes are queued, split on '\n', dispatched through the response
// map, and their synthesised replies buffered for the next Read.
type fakeMarauderPort struct {
	mu        sync.Mutex
	in        bytes.Buffer
	out       bytes.Buffer
	responses map[string]string
	timeout   time.Duration
	closed    bool
}

func newFakeMarauderPort() *fakeMarauderPort {
	return &fakeMarauderPort{
		responses: map[string]string{},
		timeout:   2 * time.Second,
	}
}

func (f *fakeMarauderPort) Read(p []byte) (int, error) {
	deadline := time.Now().Add(f.timeout)
	for {
		f.mu.Lock()
		if f.closed && f.out.Len() == 0 {
			f.mu.Unlock()
			return 0, io.EOF
		}
		if f.out.Len() > 0 {
			n, err := f.out.Read(p)
			f.mu.Unlock()
			return n, err
		}
		f.mu.Unlock()
		if time.Now().After(deadline) {
			return 0, nil
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *fakeMarauderPort) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, errors.New("port closed")
	}
	f.in.Write(p)
	for {
		idx := bytes.IndexByte(f.in.Bytes(), '\n')
		if idx < 0 {
			break
		}
		lineBytes := make([]byte, idx)
		copy(lineBytes, f.in.Bytes()[:idx])
		f.in.Next(idx + 1)
		line := strings.TrimSpace(string(lineBytes))
		body, ok := f.responses[line]
		fmt.Fprintf(&f.out, "#%s\r\n", line)
		if ok && body != "" {
			f.out.WriteString(body)
			if !strings.HasSuffix(body, "\n") {
				f.out.WriteString("\r\n")
			}
		}
		f.out.WriteString("> \r\n")
	}
	return len(p), nil
}

func (f *fakeMarauderPort) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeMarauderPort) SetReadTimeout(d time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d > 0 {
		f.timeout = d
	}
	return nil
}

// --- Anthropic ---

// AnthropicScript is one scripted model response consumed by a single
// streamOnce invocation. Text is emitted as a text block; when Tool is
// set, a tool_use block is emitted instead. Only one of Text or Tool
// should be non-zero per script entry — entries with both populated
// prioritise Tool.
type AnthropicScript struct {
	// Text is the plain-text body the fake model "generates" for this
	// turn. Ignored when Tool is set.
	Text string
	// Tool, when non-empty, instructs the mock to return a tool_use
	// block naming this tool with the supplied input arguments.
	Tool string
	// ToolID uniquely identifies the tool_use block (matches the id the
	// caller threads back as a tool_result). Defaults to "mock-<n>" when
	// empty.
	ToolID string
	// ToolInput is marshalled to JSON and placed in the tool_use block's
	// input field. nil is emitted as an empty object.
	ToolInput any
	// StopReason defaults to "end_turn" for text and "tool_use" for
	// tool entries. Override for edge-case coverage.
	StopReason string
}

// NewMockAnthropic starts an httptest.Server that replays the supplied
// script against /v1/messages streaming requests, and returns an
// anthropic.Client wired to it via WithBaseURL. Each /v1/messages POST
// consumes the next script entry; requests past the end of the script
// yield a canned "end of script" text response so tests that overshoot
// fail loudly rather than hang.
func NewMockAnthropic(t *testing.T, script []AnthropicScript) *anthropic.Client {
	t.Helper()

	var idx atomic.Int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/v1/messages") {
			http.NotFound(w, r)
			return
		}
		n := int(idx.Add(1)) - 1
		var entry AnthropicScript
		if n < len(script) {
			entry = script[n]
		} else {
			entry = AnthropicScript{Text: "end of script", StopReason: "end_turn"}
		}
		writeSSEMessage(w, n, entry)
	})

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client := anthropic.NewClient(
		option.WithAPIKey("test-key"),
		option.WithBaseURL(srv.URL),
	)
	return &client
}

// writeSSEMessage renders a single scripted model response as a Claude
// streaming SSE event stream. We compress the full lifecycle into a
// message_start (which carries the complete Message thanks to how
// Accumulate initialises the accumulator) + message_stop pair, which is
// the simplest shape the SDK's decoder accepts.
func writeSSEMessage(w http.ResponseWriter, n int, entry AnthropicScript) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, _ := w.(http.Flusher)

	id := fmt.Sprintf("msg_mock_%d", n)
	content := []map[string]any{}
	stopReason := entry.StopReason
	if entry.Tool != "" {
		toolID := entry.ToolID
		if toolID == "" {
			toolID = fmt.Sprintf("mock-%d", n)
		}
		input := entry.ToolInput
		if input == nil {
			input = map[string]any{}
		}
		content = append(content, map[string]any{
			"type":  "tool_use",
			"id":    toolID,
			"name":  entry.Tool,
			"input": input,
		})
		if stopReason == "" {
			stopReason = "tool_use"
		}
	} else {
		content = append(content, map[string]any{
			"type": "text",
			"text": entry.Text,
		})
		if stopReason == "" {
			stopReason = "end_turn"
		}
	}

	msg := map[string]any{
		"id":            id,
		"type":          "message",
		"role":          "assistant",
		"model":         "claude-mock",
		"content":       content,
		"stop_reason":   stopReason,
		"stop_sequence": nil,
		"usage":         map[string]any{"input_tokens": 1, "output_tokens": 1},
	}

	start := map[string]any{
		"type":    "message_start",
		"message": msg,
	}
	sendEvent(w, flusher, "message_start", start)

	sendEvent(w, flusher, "message_stop", map[string]any{"type": "message_stop"})
}

func sendEvent(w http.ResponseWriter, flusher http.Flusher, name string, body any) {
	data, _ := json.Marshal(body)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, data)
	if flusher != nil {
		flusher.Flush()
	}
}
