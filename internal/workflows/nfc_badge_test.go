//go:build linux

package workflows_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper/mock"
	"github.com/xunholy/promptzero/internal/workflows"
)

// stockDeviceInfo omits firmware_origin_fork so detectCapabilities returns
// the stock defaults (HasNFCSubshell=true). Needed for every workflow that
// drives the nfc subshell, since the mock's default is Xtreme.
const stockDeviceInfo = `hardware_model                : Flipper Zero
hardware_uid                  : 4521480226E18000
hardware_name                 : MockDolphin
firmware_commit               : deadbeef
firmware_version              : STOCK-MOCK
firmware_build_date           : 01-01-2025`

// TestNFCBadgePipelineMIFAREClassic drives the MIFARE Classic branch:
// nfc_detect returns a Classic tag, no attempt_dump flag, and the
// workflow returns the mfkey-recovery next steps.
func TestNFCBadgePipelineMIFAREClassic(t *testing.T) {
	f, _ := mockFlipper(t,
		mock.WithHandler("device_info", func(args []string) string { return stockDeviceInfo }),
		mock.WithHandler("nfc", func(args []string) string { return "" }), // entering subshell
		// The mock dispatches `scanner` (the default NFCDetect subcommand)
		// as a top-level handler because the pty passes each command on its
		// own line. Return a Classic-shaped response.
		mock.WithHandler("scanner", func(args []string) string {
			return "Found Mifare Classic 1K\nUID: 04 A2 B3 C4\nATQA: 00 04\nSAK: 08"
		}),
		mock.WithHandler("exit", func(args []string) string { return "" }),
	)

	out, err := workflows.NFCBadgePipeline(context.Background(), workflows.Deps{Flipper: f}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("NFCBadgePipeline: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, out)
	}
	summary, _ := got["summary"].(string)
	if !strings.Contains(summary, "Mifare Classic") {
		t.Errorf("summary missing protocol: %q", summary)
	}
	if !strings.Contains(summary, "04 A2 B3 C4") {
		t.Errorf("summary missing UID: %q", summary)
	}

	protocol, _ := got["protocol"].(string)
	if protocol != "Mifare Classic" {
		t.Errorf("extra.protocol = %q, want Mifare Classic", protocol)
	}

	nextSteps, _ := got["next_steps"].([]interface{})
	if len(nextSteps) == 0 {
		t.Fatalf("expected non-empty next_steps")
	}
	joined := ""
	for _, s := range nextSteps {
		if str, ok := s.(string); ok {
			joined += str
		}
	}
	if !strings.Contains(joined, "mfkey") {
		t.Errorf("expected mfkey mention in next_steps, got %v", nextSteps)
	}
}

// TestNFCBadgePipelineNoTag verifies the bail-out path: when the scanner
// returns an empty output we surface "no tag detected" and still emit
// valid JSON with the detect phase recorded.
func TestNFCBadgePipelineNoTag(t *testing.T) {
	f, _ := mockFlipper(t,
		mock.WithHandler("device_info", func(args []string) string { return stockDeviceInfo }),
		mock.WithHandler("nfc", func(args []string) string { return "" }),
		mock.WithHandler("scanner", func(args []string) string { return "no tag found in field" }),
		mock.WithHandler("exit", func(args []string) string { return "" }),
	)

	out, err := workflows.NFCBadgePipeline(context.Background(), workflows.Deps{Flipper: f}, map[string]interface{}{"timeout_seconds": 5})
	if err != nil {
		t.Fatalf("NFCBadgePipeline: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v", err)
	}
	summary, _ := got["summary"].(string)
	if !strings.Contains(summary, "no tag detected") {
		t.Errorf("expected no-tag summary, got %q", summary)
	}
	phases, _ := got["phases"].([]interface{})
	if len(phases) != 1 {
		t.Errorf("expected exactly one phase (detect), got %d", len(phases))
	}
}
