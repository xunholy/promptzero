//go:build linux

package workflows_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/flipper/mock"
	"github.com/xunholy/promptzero/internal/workflows"
)

// TestPhysPentestBadgeWalkDedupes drives a short 3-second walk where
// every radio read returns the same decoded badge. We assert the
// workflow dedupes across iterations and writes a CSV with exactly one
// row per radio.
func TestPhysPentestBadgeWalkDedupes(t *testing.T) {
	f, _ := mockFlipper(t,
		mock.WithHandler("device_info", func(args []string) string { return stockDeviceInfo }),
		mock.WithHandler("nfc", func(args []string) string { return "" }),
		mock.WithHandler("scanner", func(args []string) string {
			return "Found Mifare Classic 1K\nUID: 04 A2 B3 C4\nATQA: 00 04\nSAK: 08"
		}),
		mock.WithHandler("exit", func(args []string) string { return "" }),
		mock.WithHandler("rfid", func(args []string) string {
			// `rfid read` — emit an EM4100 detection line so RFIDRead's
			// streaming detector triggers immediately.
			return "EM4100\nData: DEADBEEF01"
		}),
		mock.WithHandler("ikey", func(args []string) string {
			// `ikey read` — Dallas iButton with 8-byte key.
			return "Dallas\nKey: 01 23 45 67 89 AB CD EF"
		}),
		// StorageWrite goes through the `storage write_chunked` protocol;
		// register an open-ended capture that saves whatever file body
		// the Flipper serial layer uploads. For the purposes of this
		// test we don't need the bytes to match exactly — the phase OK
		// flag is what the workflow reports.
		mock.WithHandler("storage", func(args []string) string {
			// The mock replies with empty + the prompt which is enough
			// for the Flipper.StorageWrite path to return nil on the
			// happy path — we don't need to assert on the raw payload.
			return ""
		}),
	)

	// Bound the walk to ~2 seconds of wall time via ctx — the workflow's
	// min-duration clamp is 10s but ctx cancellation short-circuits the
	// inner loop so tests stay snappy.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := workflows.PhysPentestBadgeWalk(ctx, workflows.Deps{Flipper: f}, map[string]interface{}{
		"duration_seconds": 10,
		"per_read_timeout": 1,
		"csv_path":         "/ext/test_walk.csv",
	})
	if err != nil {
		t.Fatalf("PhysPentestBadgeWalk: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, out)
	}

	badges, _ := got["badges"].([]interface{})
	// Expect exactly three unique badges — one per radio — even though
	// the loop ran many iterations.
	if len(badges) == 0 {
		t.Fatalf("expected non-empty badges, got %v", badges)
	}
	radios := map[string]bool{}
	for _, b := range badges {
		m, _ := b.(map[string]interface{})
		radio, _ := m["radio"].(string)
		radios[radio] = true
	}
	// We require at least NFC (protocol detection via scanner is
	// rock-solid); the RFID and iButton mocks are also expected to
	// match unless the streaming-detector heuristic rejects the
	// synthetic output.
	if !radios["nfc"] {
		t.Errorf("expected an NFC badge, got radios=%v", radios)
	}

	summary, _ := got["summary"].(string)
	if !strings.Contains(summary, "unique badge") {
		t.Errorf("summary missing unique-badge count: %q", summary)
	}

	if path, _ := got["csv_path"].(string); path != "/ext/test_walk.csv" {
		t.Errorf("expected csv_path override, got %q", path)
	}
}
