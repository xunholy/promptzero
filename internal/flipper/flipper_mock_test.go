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
