//go:build linux

package flipper_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// stockDeviceInfo is a device_info blob that omits firmware_origin_fork, so
// detectCapabilities returns the stock defaults (HasNFCSubshell=true,
// SubGHzNeedsDev=false). Used by tests that want the stock code path
// instead of the Xtreme one baked into mock.DefaultDeviceInfo.
const stockDeviceInfo = `hardware_model                : Flipper Zero
hardware_uid                  : 4521480226E18000
hardware_name                 : MockDolphin
firmware_commit               : deadbeef
firmware_version              : STOCK-MOCK
firmware_build_date           : 01-01-2025`

// connectAndDetect spins up the Connect → DetectCapabilities pair against
// the supplied mock and returns the flipper ready for testing. The mock's
// lifecycle is tied to the test via its own t.Cleanup in Spawn; we register
// Close on the flipper too so a single failing assertion doesn't leave a
// hot serial port.
func connectAndDetect(t *testing.T, m *mock.Mock) *flipper.Flipper {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	flip, err := flipper.Connect(ctx, m.Path(), 115200, 10*time.Second)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = flip.Close() })
	if _, err := flip.DetectCapabilities(); err != nil {
		t.Fatalf("DetectCapabilities: %v", err)
	}
	return flip
}

// TestStorageCopySanitises is the smoke test for the Storage extension:
// (1) the wrapper issues exactly one `storage copy <src> <dst>` command,
// and (2) CRLF injected into either argument is stripped before the bytes
// reach the serial port.
func TestStorageCopySanitises(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("storage", func(args []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	before := m.Count()
	// Malicious args: \r and \n would each terminate a CLI command and let
	// the remainder inject a second command. sanitizeArg strips the
	// separator bytes, collapsing the payload into one harmless argument —
	// we don't care that the concatenated path is garbage, only that the
	// mock never sees two commands.
	_, _ = flip.StorageCopy("/ext/src\rpower reboot", "/ext/dst\nvibro 1")
	after := m.Count()

	if after-before != 1 {
		t.Errorf("storage copy dispatched %d commands, want 1 (CRLF should be stripped). lines=%v", after-before, m.Lines())
	}
	lines := m.Lines()
	storageSeen := false
	for _, l := range lines {
		trim := strings.TrimSpace(l)
		if strings.HasPrefix(trim, "storage copy ") {
			storageSeen = true
		}
		if trim == "power reboot" || trim == "vibro 1" {
			t.Errorf("CRLF injection succeeded — mock saw a standalone %q command (lines=%v)", trim, lines)
		}
	}
	if !storageSeen {
		t.Errorf("no storage copy line observed. lines=%v", lines)
	}
}

// TestLoaderMFKey verifies the quoting-free loader FAP shortcut issues the
// exact `loader open MFKey32` line the firmware expects.
func TestLoaderMFKey(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("loader", func(args []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	if _, err := flip.LoaderMFKey(); err != nil {
		t.Fatalf("LoaderMFKey: %v", err)
	}
	lines := m.Lines()
	wantSuffix := "loader open MFKey32"
	found := false
	for _, l := range lines {
		if strings.TrimSpace(l) == wantSuffix {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to see %q; lines=%v", wantSuffix, lines)
	}
}

// TestLoaderSubGHzBruteforcerQuotesName verifies that a multi-word FAP name
// is sent as a single quoted argument so the Flipper CLI parses it as one
// application identifier rather than splitting on whitespace.
func TestLoaderSubGHzBruteforcerQuotesName(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("loader", func(args []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	if _, err := flip.LoaderSubGHzBruteforcer(); err != nil {
		t.Fatalf("LoaderSubGHzBruteforcer: %v", err)
	}
	lines := m.Lines()
	want := `loader open "Sub-GHz BF"`
	found := false
	for _, l := range lines {
		if strings.TrimSpace(l) == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to see %q; lines=%v", want, lines)
	}
}

// TestNFCMFUReadForkGatedOnXtreme exercises the fork-gate path: on the
// Xtreme-flavored mock default, NFCMFURead must return a friendly-fork
// error instead of attempting the subshell dance.
func TestNFCMFUReadForkGatedOnXtreme(t *testing.T) {
	m := mock.Spawn(t) // default: Xtreme fork
	flip := connectAndDetect(t, m)

	_, err := flip.NFCMFURead(4, 5*time.Second)
	if err == nil {
		t.Fatal("expected NFCMFURead to error on Xtreme fork")
	}
	if !strings.Contains(err.Error(), "NFC CLI not available") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestNFCMFURead_StockSubshell drives the full subshell plumbing against a
// mock advertising a stock-fork device_info (HasNFCSubshell=true). Asserts
// the wrapper enters the subshell, issues `mfu rdbl <page>`, and exits.
func TestNFCMFURead_StockSubshell(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(args []string) string { return stockDeviceInfo }),
		mock.WithHandler("nfc", func(args []string) string { return "" }),
		mock.WithHandler("mfu", func(args []string) string {
			if len(args) >= 2 && args[0] == "rdbl" && args[1] == "4" {
				return "Page 04: 01 02 03 04"
			}
			return ""
		}),
		mock.WithHandler("exit", func(args []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	out, err := flip.NFCMFURead(4, 5*time.Second)
	if err != nil {
		t.Fatalf("NFCMFURead: %v (out=%q)", err, out)
	}
	if !strings.Contains(out, "Page 04") {
		t.Errorf("expected Page 04 in output, got %q", out)
	}

	// Confirm the exact subshell dance was issued.
	seen := map[string]bool{}
	for _, l := range m.Lines() {
		seen[strings.TrimSpace(l)] = true
	}
	for _, want := range []string{"nfc", "mfu rdbl 4", "exit"} {
		if !seen[want] {
			t.Errorf("missing expected command %q; lines=%v", want, m.Lines())
		}
	}
}

// TestJSRunForkGatedOnStock verifies JSRun refuses to even issue the CLI
// command on firmware forks without a JS runtime.
func TestJSRunForkGatedOnStock(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(args []string) string { return stockDeviceInfo }),
	)
	flip := connectAndDetect(t, m)

	before := m.Count()
	_, err := flip.JSRun("/ext/apps/Scripts/hello.js", 5*time.Second)
	if err == nil {
		t.Fatal("expected JSRun to error on stock fork")
	}
	if !strings.Contains(err.Error(), "JS runtime not available") {
		t.Errorf("unexpected error: %v", err)
	}
	// The fork gate must short-circuit — no `js` command should have been sent.
	for _, l := range m.Lines() {
		if strings.HasPrefix(strings.TrimSpace(l), "js ") {
			t.Errorf("JSRun dispatched %q despite fork gate", l)
		}
	}
	if m.Count() < before {
		t.Fatalf("impossible: count moved backward from %d to %d", before, m.Count())
	}
}

// TestJSRunHappyPathExecLong covers the ExecLong code path: on a supported
// fork (mock default is Xtreme), JSRun must emit `js <path>` exactly once
// and complete within the supplied duration.
func TestJSRunHappyPathExecLong(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("js", func(args []string) string { return "script done" }),
	)
	flip := connectAndDetect(t, m)

	before := m.Count()
	out, err := flip.JSRun("/ext/apps/Scripts/hello.js", 5*time.Second)
	if err != nil {
		t.Fatalf("JSRun: %v", err)
	}
	if !strings.Contains(out, "script done") {
		t.Errorf("expected script output in return, got %q", out)
	}
	if got := m.Count() - before; got != 1 {
		t.Errorf("JSRun dispatched %d commands, want 1. lines=%v", got, m.Lines())
	}
	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == "js /ext/apps/Scripts/hello.js" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected `js /ext/apps/Scripts/hello.js`, got lines=%v", m.Lines())
	}
}

// TestI2CScanFallsBackToLoader covers the "try CLI → fallback to FAP" path:
// when the firmware responds with an "unknown command" style error for
// `i2c scan`, I2CScan must launch the I2C Scanner FAP instead. We observe
// the fallback via the mock's command log (mutex-protected) rather than
// through a handler-side bool, which would race with the main goroutine.
func TestI2CScanFallsBackToLoader(t *testing.T) {
	if testing.Short() {
		t.Skip("slow; exercises CLI→FAP fallback wait — rerun without -short")
	}
	m := mock.Spawn(t,
		mock.WithHandler("i2c", func(args []string) string {
			return "`i2c` is not a recognized command. Use `help` or `?` to list available commands."
		}),
		mock.WithHandler("loader", func(args []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	if _, err := flip.I2CScan(); err != nil {
		t.Fatalf("I2CScan: %v", err)
	}

	wantLine := `loader open "I2C Scanner"`
	sawI2C := false
	sawLoader := false
	for _, l := range m.Lines() {
		trim := strings.TrimSpace(l)
		if trim == "i2c scan" {
			sawI2C = true
		}
		if trim == wantLine {
			sawLoader = true
		}
	}
	if !sawI2C {
		t.Errorf("expected i2c scan to be tried first; lines=%v", m.Lines())
	}
	if !sawLoader {
		t.Errorf("expected fallback line %q; lines=%v", wantLine, m.Lines())
	}
}

// TestLogStreamExecLongRunsToCompletion drives the ExecLong path for the
// `log` command: the mock immediately emits a prompt after echoing, which
// satisfies readUntilPrompt well within the supplied duration. We rely on
// this succeeding cleanly without hanging.
func TestLogStreamExecLongRunsToCompletion(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("log", func(args []string) string { return "log line 1\nlog line 2" }),
	)
	flip := connectAndDetect(t, m)

	start := time.Now()
	out, err := flip.LogStream(5 * time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("LogStream: %v", err)
	}
	if elapsed >= 5*time.Second {
		t.Errorf("LogStream should have returned on prompt, not timeout; took %s", elapsed)
	}
	if !strings.Contains(out, "log line 1") {
		t.Errorf("expected log output in return, got %q", out)
	}
}

// TestStorageMD5Plain is a bare smoke test ensuring the one-liner wrapper
// wires through. Regression only — if sanitizeArg is ever dropped from
// StorageMD5 this test would still fail because the injected CRLF path
// would split into two mock commands.
func TestStorageMD5SanitisesPath(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("storage", func(args []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	before := m.Count()
	_, _ = flip.StorageMD5("/ext/foo\rpower reboot")
	if got := m.Count() - before; got != 1 {
		t.Errorf("StorageMD5 dispatched %d commands, want 1 (CRLF should be stripped). lines=%v", got, m.Lines())
	}
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == "power reboot" {
			t.Errorf("CRLF injection succeeded — mock observed %q", l)
		}
	}
}
