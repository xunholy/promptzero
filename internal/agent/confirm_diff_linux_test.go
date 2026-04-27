//go:build linux

package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/testmocks"
)

// TestBuildConfirmRequest_DiffOnExistingFile exercises the happy path:
// the file already exists, so the confirmation flow fetches it via
// Storage Read and renders a unified diff against the proposed content.
func TestBuildConfirmRequest_DiffOnExistingFile(t *testing.T) {
	const path = "/ext/agent_diff_canary.txt"
	const oldContent = "alpha\nbeta\ngamma\n"

	flip := testmocks.NewMockFlipper(t,
		testmocks.WithFlipperHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "read" && args[1] == path {
				// Mirror the firmware shape: "Size: <N>\n" then bytes.
				return "Size: " + itoa(len(oldContent)) + "\n" + oldContent
			}
			return ""
		}),
	)
	a := &Agent{flipper: flip}

	newContent := "alpha\nBETA\ngamma\n"
	body := map[string]any{"path": path, "content": newContent}
	raw, _ := json.Marshal(body)

	req := a.buildConfirmRequest("storage_write", raw, risk.Medium)
	if req.Diff == "" {
		t.Fatalf("expected non-empty diff for existing file change")
	}
	if !strings.Contains(req.Diff, "-beta") || !strings.Contains(req.Diff, "+BETA") {
		t.Errorf("diff missing expected change lines:\n%s", req.Diff)
	}
	if !strings.Contains(req.Diff, "--- "+path) {
		t.Errorf("diff missing expected file header: %q", req.Diff)
	}
}

// TestBuildConfirmRequest_FreshFileEmptyOldSide verifies that a write
// to a path the firmware reports as missing renders the new content
// as a pure-additions diff (no '-' lines, no warning).
func TestBuildConfirmRequest_FreshFileEmptyOldSide(t *testing.T) {
	const path = "/ext/agent_diff_fresh.txt"

	flip := testmocks.NewMockFlipper(t,
		testmocks.WithFlipperHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "read" {
				// Standard Flipper firmware response for a missing file.
				return "Storage error: File does not exist"
			}
			return ""
		}),
	)
	a := &Agent{flipper: flip}

	body := map[string]any{"path": path, "content": "hello\nworld\n"}
	raw, _ := json.Marshal(body)

	req := a.buildConfirmRequest("storage_write", raw, risk.Medium)
	if req.Diff == "" {
		t.Fatalf("expected non-empty diff for fresh write")
	}
	if strings.Contains(req.Diff, "unable to fetch") {
		t.Errorf("missing-file should be treated as empty old side, not a warning. got:\n%s", req.Diff)
	}
	if !strings.Contains(req.Diff, "+hello") || !strings.Contains(req.Diff, "+world") {
		t.Errorf("expected each new line prefixed '+', got:\n%s", req.Diff)
	}
}

// itoa is a tiny inline helper to avoid pulling strconv into the
// happy-path test fixture.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
