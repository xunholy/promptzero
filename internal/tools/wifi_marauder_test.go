package tools_test

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/marauder"
	"github.com/xunholy/promptzero/internal/tools"
)

// wifiInfoSpec is the wifi_info Spec captured at init time (before
// spec_test.go's resetForTest() calls clear the global registry). The
// wifi_marauder_test.go handler tests look up the Spec here rather than via
// tools.Get() so they're not sensitive to inter-test registry resets.
var wifiInfoSpec tools.Spec
var wifiInfoFound bool

func init() {
	// Capture in init() so it runs before any test function — including
	// TestMain in registry_size_test.go — but after all package init() funcs
	// have populated the registry.
	wifiInfoSpec, wifiInfoFound = tools.Get("wifi_info")
}

// --- RequireMarauder tests ---

func TestRequireMarauder_NilDeps(t *testing.T) {
	var d *tools.Deps
	err := d.RequireMarauder()
	if err == nil {
		t.Fatal("expected error for nil Deps, got nil")
	}
	if !strings.Contains(err.Error(), "WiFi devboard not connected") {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

func TestRequireMarauder_NilMarauder(t *testing.T) {
	d := &tools.Deps{Marauder: nil}
	err := d.RequireMarauder()
	if err == nil {
		t.Fatal("expected error for nil Marauder, got nil")
	}
	if !strings.Contains(err.Error(), "WiFi devboard not connected") {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

func TestRequireMarauder_Valid(t *testing.T) {
	fp := newTestPort()
	m := marauder.NewWithPort(fp)
	d := &tools.Deps{Marauder: m}
	err := d.RequireMarauder()
	if err != nil {
		t.Fatalf("expected nil error for valid Marauder, got: %v", err)
	}
}

// --- Handler sanity tests: wifi_info via registry ---

// TestWiFiInfoHandler_NoMarauder verifies that the registered wifi_info
// handler returns the RequireMarauder error when no Marauder is wired.
func TestWiFiInfoHandler_NoMarauder(t *testing.T) {
	if !wifiInfoFound {
		t.Skip("wifi_info not found in registry at init time (registry was cleared before capture)")
	}
	d := &tools.Deps{Marauder: nil}
	_, err := wifiInfoSpec.Handler(context.Background(), d, nil)
	if err == nil {
		t.Fatal("expected RequireMarauder error, got nil")
	}
	if !strings.Contains(err.Error(), "WiFi devboard not connected") {
		t.Errorf("unexpected error: %q", err.Error())
	}
}

// TestWiFiInfoHandler_WithMockMarauder exercises the full registry path with
// a fake Marauder that responds to the 'info' command, confirming the handler
// is wired correctly end-to-end.
func TestWiFiInfoHandler_WithMockMarauder(t *testing.T) {
	if !wifiInfoFound {
		t.Skip("wifi_info not found in registry at init time (registry was cleared before capture)")
	}

	fp := newTestPort()
	fp.respond("info", "version: 1.11.1\nchip: esp32s2")
	m := marauder.NewWithPort(fp)

	d := &tools.Deps{Marauder: m}
	out, err := wifiInfoSpec.Handler(context.Background(), d, map[string]any{})
	if err != nil {
		t.Fatalf("wifi_info handler error: %v", err)
	}
	if !strings.Contains(out, "1.11.1") {
		t.Errorf("expected version in output, got: %q", out)
	}
}

// --- testPort: minimal marauder.Port implementation for unit tests ---
//
// testPort is a synchronous in-memory port: writes trigger scripted
// responses using the Marauder wire protocol (echo "#<cmd>", body, "> ").
// Unscripted commands still get a prompt so readUntilPrompt terminates.

type testPort struct {
	mu        sync.Mutex
	incoming  bytes.Buffer
	outgoing  bytes.Buffer
	responses map[string]string
	timeout   time.Duration
}

func newTestPort() *testPort {
	return &testPort{
		responses: make(map[string]string),
		timeout:   2 * time.Second,
	}
}

// respond registers a canned response body for the given command string.
func (f *testPort) respond(cmd, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[cmd] = body
}

func (f *testPort) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.incoming.Write(p)
	// Dispatch each complete newline-terminated command line.
	for {
		idx := bytes.IndexByte(f.incoming.Bytes(), '\n')
		if idx < 0 {
			break
		}
		lineBytes := make([]byte, idx)
		copy(lineBytes, f.incoming.Bytes()[:idx])
		f.incoming.Next(idx + 1)
		line := strings.TrimSpace(string(lineBytes))
		body := f.responses[line]
		// Echo "#<cmd>" + optional body + "> " prompt.
		f.outgoing.WriteString("#" + line + "\r\n")
		if body != "" {
			f.outgoing.WriteString(body)
			if !strings.HasSuffix(body, "\n") {
				f.outgoing.WriteString("\r\n")
			}
		}
		f.outgoing.WriteString("> ")
	}
	return len(p), nil
}

func (f *testPort) Read(p []byte) (int, error) {
	deadline := time.Now().Add(f.timeout)
	for {
		f.mu.Lock()
		n, _ := f.outgoing.Read(p)
		f.mu.Unlock()
		if n > 0 {
			return n, nil
		}
		if time.Now().After(deadline) {
			return 0, nil // Simulate read timeout (no data)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *testPort) Close() error { return nil }

func (f *testPort) SetReadTimeout(d time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d > 0 {
		f.timeout = d
	}
	return nil
}
