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

// TestMockHandshakeAndDeviceInfo drives the real flipper.Connect path
// against a pty-backed mock, then exercises DetectCapabilities. This is
// the regression test that would have caught the ONLCR drift bug and any
// future change that breaks the CLI handshake. If the real Connect has
// an issue, it surfaces here in milliseconds without hardware.
func TestMockHandshakeAndDeviceInfo(t *testing.T) {
	m := mock.Spawn(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	flip, err := flipper.Connect(ctx, m.Path(), 115200, 10*time.Second)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer flip.Close()

	caps, err := flip.DetectCapabilities()
	if err != nil {
		t.Fatalf("DetectCapabilities: %v", err)
	}
	if caps.FirmwareFork != "Xtreme" {
		t.Errorf("FirmwareFork = %q, want Xtreme", caps.FirmwareFork)
	}
	if caps.HardwareName != "MockDolphin" {
		t.Errorf("HardwareName = %q, want MockDolphin", caps.HardwareName)
	}
	if caps.HasNFCSubshell {
		t.Errorf("Xtreme fork should not report HasNFCSubshell = true")
	}
	if caps.PowerInfoCmd != "info power" {
		t.Errorf("PowerInfoCmd = %q, want 'info power'", caps.PowerInfoCmd)
	}
}

// TestMockPowerInfoRoutesByFork verifies PowerInfo picks "info power" on
// Xtreme and parses the canned response rather than silently failing.
func TestMockPowerInfoRoutesByFork(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("info", func(args []string) string {
			if len(args) >= 1 && args[0] == "power" {
				return "charge.level                  : 42\nbattery.voltage               : 3700"
			}
			return ""
		}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	flip, err := flipper.Connect(ctx, m.Path(), 115200, 10*time.Second)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer flip.Close()

	if _, err := flip.DetectCapabilities(); err != nil {
		t.Fatalf("DetectCapabilities: %v", err)
	}

	out, err := flip.PowerInfo()
	if err != nil {
		t.Fatalf("PowerInfo: %v", err)
	}
	if !strings.Contains(out, "charge.level") || !strings.Contains(out, "42") {
		t.Errorf("PowerInfo output missing expected fields: %q", out)
	}
}

// TestMockLoaderListParsed verifies the new list_apps parser against the
// mock's canned "Apps:/Settings:" layout.
func TestMockLoaderListParsed(t *testing.T) {
	m := mock.Spawn(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	flip, err := flipper.Connect(ctx, m.Path(), 115200, 10*time.Second)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer flip.Close()

	apps, err := flip.LoaderListParsed()
	if err != nil {
		t.Fatalf("LoaderListParsed: %v", err)
	}
	if len(apps.Apps) != 3 {
		t.Errorf("Apps = %v, want 3 entries", apps.Apps)
	}
	if len(apps.Settings) != 2 {
		t.Errorf("Settings = %v, want 2 entries", apps.Settings)
	}
	wantApps := map[string]bool{"SubGHz": true, "NFC": true, "RFID": true}
	for _, a := range apps.Apps {
		if !wantApps[a] {
			t.Errorf("unexpected app %q in parsed output", a)
		}
	}
}

// TestMockConnectionReport drives ConnectURL through the mock and
// asserts the structured ConnectionReport surfaces the canonical
// happy-path checks operators rely on (transport.dial + handshake at
// LevelPass, plus detect_capabilities). The point isn't to pin every
// detail string — it's to guarantee the report has the named checks
// at all, since /api/device and PROMPTZERO_VERBOSE_CONNECT consumers
// downstream read these names by hand.
func TestMockConnectionReport(t *testing.T) {
	m := mock.Spawn(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	flip, report, err := flipper.ConnectURL(ctx, m.URL(), 10*time.Second)
	if err != nil {
		t.Fatalf("ConnectURL: %v", err)
	}
	defer flip.Close()

	if report == nil {
		t.Fatal("ConnectURL returned nil report on success")
	}
	if got := flip.ConnectionReport(); got != report {
		t.Errorf("Flipper.ConnectionReport mismatch: got %p want %p", got, report)
	}

	want := map[string]flipper.CheckLevel{
		"transport.open":      flipper.LevelPass,
		"transport.dial":      flipper.LevelPass,
		"handshake":           flipper.LevelPass,
		"detect_capabilities": flipper.LevelPass,
	}
	got := map[string]flipper.CheckLevel{}
	for _, c := range report.Checks() {
		got[c.Name] = c.Level
	}
	for name, lvl := range want {
		if got[name] != lvl {
			t.Errorf("check %q: level = %q, want %q (full report=%+v)",
				name, got[name], lvl, report.Checks())
		}
	}

	if report.PassedCount() < 3 {
		t.Errorf("PassedCount = %d, want at least 3", report.PassedCount())
	}
	if report.FailedCount() != 0 {
		t.Errorf("FailedCount = %d, want 0", report.FailedCount())
	}
	if report.CompletedAt.IsZero() {
		t.Error("CompletedAt not stamped on success")
	}
}

// TestMockSanitisesCRLF proves the CRLF sanitiser prevents an LLM-supplied
// path containing \r from injecting a second CLI command. Without
// sanitisation the mock would observe 2 commands; with it, only 1.
func TestMockSanitisesCRLF(t *testing.T) {
	m := mock.Spawn(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	flip, err := flipper.Connect(ctx, m.Path(), 115200, 10*time.Second)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer flip.Close()

	before := m.Count()
	// Malicious path: \r would terminate the first command and inject a
	// second. sanitizeArg should strip it inside SubGHzTx before the bytes
	// ever reach the serial port.
	_, _ = flip.SubGHzTx("malicious.sub\rvibro 1")
	after := m.Count()
	lines := m.Lines()
	if after-before != 1 {
		t.Errorf("mock observed %d commands for a single sanitised call; want 1 (CRLF injection should be stripped). lines=%v", after-before, lines)
	}
	for _, l := range lines {
		if strings.Contains(l, "vibro") && strings.TrimSpace(l) == "vibro 1" {
			t.Errorf("CRLF injection succeeded — mock saw a standalone %q command", l)
		}
	}
}
