package main

import (
	"strings"
	"testing"

	flippermock "github.com/xunholy/promptzero/internal/flipper/mock"
	"github.com/xunholy/promptzero/internal/testmocks"
)

func TestHandleValidate_NoPath_ShowsUsage(t *testing.T) {
	// dispatchSlashCommand sends the usage hint when the user omits the
	// path argument. Exercise it end-to-end so the public entry point stays
	// wired.
	flip := testmocks.NewMockFlipper(t)
	deps := &REPLDeps{flip: flip, ed: newLineEditor(&termUI{enabled: false})}

	out := captureStderr(t, func() {
		handled, exit := dispatchSlashCommand("/validate", deps)
		if !handled {
			t.Fatalf("/validate with no args should be handled")
		}
		if exit {
			t.Fatalf("/validate should not trigger REPL exit")
		}
	})
	if !strings.Contains(out, "usage: /validate") {
		t.Fatalf("usage line missing: %q", out)
	}
}

func TestHandleValidate_CleanPayload(t *testing.T) {
	payload := "REM benign demo\nDELAY 500\nSTRING hello world\n"
	flip := testmocks.NewMockFlipper(t, testmocks.WithFlipperHandler("storage", func(args []string) string {
		if len(args) >= 1 && args[0] == "read" {
			return payload
		}
		return ""
	}))

	out := captureStderr(t, func() {
		handleValidate(flip, "/ext/badusb/demo.txt")
	})

	if !strings.Contains(out, "no findings") {
		t.Fatalf("expected 'no findings' for clean payload, got:\n%s", out)
	}
}

func TestHandleValidate_CriticalPayload(t *testing.T) {
	// rm -rf / on a STRING line — exactly the shape badusb_validate is
	// meant to flag before the Flipper types it.
	payload := "STRING rm -rf /\n"
	flip := testmocks.NewMockFlipper(t, testmocks.WithFlipperHandler("storage", func(args []string) string {
		if len(args) >= 1 && args[0] == "read" {
			return payload
		}
		return ""
	}))

	out := captureStderr(t, func() {
		handleValidate(flip, "/ext/badusb/bad.txt")
	})

	if !strings.Contains(out, "critical") {
		t.Fatalf("expected critical severity label, got:\n%s", out)
	}
	if !strings.Contains(out, "rm -rf /") {
		t.Fatalf("expected payload excerpt in output, got:\n%s", out)
	}
}

func TestHandleValidate_NilFlipper(t *testing.T) {
	// handleValidate defends against being called without a connected
	// Flipper (e.g. when the REPL starts in a degraded state).
	out := captureStderr(t, func() {
		handleValidate(nil, "/ext/badusb/demo.txt")
	})
	if !strings.Contains(out, "needs a connected Flipper") {
		t.Fatalf("expected guard message, got:\n%s", out)
	}
}

// Ensure flippermock import stays referenced if the handler type changes.
var _ flippermock.Handler = func(args []string) string { return "" }

// /forget without an id should print the usage hint via dispatchSlashCommand
// and not exit the REPL. Exercises the dispatcher path so a future rename
// of /forget can't silently strand it.
func TestForget_NoArgs_ShowsUsage(t *testing.T) {
	deps := &REPLDeps{ed: newLineEditor(&termUI{enabled: false})}

	out := captureStderr(t, func() {
		handled, exit := dispatchSlashCommand("/forget", deps)
		if !handled {
			t.Fatalf("/forget with no args should be handled")
		}
		if exit {
			t.Fatalf("/forget should not trigger REPL exit")
		}
	})
	if !strings.Contains(out, "usage: /forget") {
		t.Fatalf("usage line missing: %q", out)
	}
}
