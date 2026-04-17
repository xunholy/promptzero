//go:build linux

package workflows_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/workflows"
)

// TestWiFiTargetToHashcatRefusesWithoutMarauder verifies the workflow
// structured-refuses when no Marauder devboard is wired — it must not
// panic and must surface clear next-steps.
func TestWiFiTargetToHashcatRefusesWithoutMarauder(t *testing.T) {
	f, _ := mockFlipper(t)

	out, err := workflows.WiFiTargetToHashcat(context.Background(),
		workflows.Deps{Flipper: f, Marauder: nil}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("WiFiTargetToHashcat: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, out)
	}
	summary, _ := got["summary"].(string)
	if !strings.Contains(summary, "Marauder") {
		t.Errorf("expected Marauder-required refusal, got %q", summary)
	}
	phases, _ := got["phases"].([]interface{})
	if len(phases) != 0 {
		t.Errorf("expected no phases on refusal, got %d", len(phases))
	}
}

// The Marauder package doesn't ship a pty-backed mock (unlike the
// Flipper), so the happy path is exercised by unit-testing the parser
// + formatter helpers directly. These tests pin the hashcat-22000 wire
// format so any future firmware-output change is caught here rather
// than silently at crack time.

func TestHashcat22000LineWellFormed(t *testing.T) {
	line := workflows.Hashcat22000LineForTest(workflows.PMKIDCaptureForTest{
		PMKID:     "aabbccddeeff00112233445566778899",
		APMAC:     "aa:bb:cc:dd:ee:ff",
		ClientMAC: "11:22:33:44:55:66",
		SSID:      "TestAP",
	})
	// Expected: WPA*01*<pmkid>*<apmac_nosep>*<clientmac_nosep>*<essid_hex>***
	parts := strings.Split(line, "*")
	if len(parts) != 9 {
		t.Fatalf("expected 9 *-separated fields, got %d in %q", len(parts), line)
	}
	if parts[0] != "WPA" || parts[1] != "01" {
		t.Errorf("bad header: %s*%s, want WPA*01", parts[0], parts[1])
	}
	if parts[2] != "aabbccddeeff00112233445566778899" {
		t.Errorf("bad PMKID: %s", parts[2])
	}
	if parts[3] != "aabbccddeeff" {
		t.Errorf("AP MAC should be colon-stripped lower: %s", parts[3])
	}
	if parts[4] != "112233445566" {
		t.Errorf("client MAC should be colon-stripped lower: %s", parts[4])
	}
	// "TestAP" → hex = 54657374 4150 (no space)
	if parts[5] != "546573744150" {
		t.Errorf("bad essid hex: %s, want 546573744150", parts[5])
	}
}

func TestParsePMKIDExtractsCoreFields(t *testing.T) {
	out := `Starting PMKID sniff on channel 6...
AP: AA:BB:CC:DD:EE:FF SSID=Target
Client: 11:22:33:44:55:66
PMKID: AABBCCDDEEFF00112233445566778899 captured`
	cap := workflows.ParsePMKIDForTest(out)
	if cap == nil {
		t.Fatal("expected non-nil capture")
	}
	if cap.PMKID != "aabbccddeeff00112233445566778899" {
		t.Errorf("PMKID not lowercased/trimmed: %q", cap.PMKID)
	}
	if cap.APMAC != "aabbccddeeff" {
		t.Errorf("APMAC should be normalised: %q", cap.APMAC)
	}
	if cap.ClientMAC != "112233445566" {
		t.Errorf("ClientMAC should be normalised: %q", cap.ClientMAC)
	}
}

func TestPickStrongestWPAIgnoresOpenAndPicksBestRSSI(t *testing.T) {
	aps := []workflows.MarauderAPForTest{
		{Index: 0, BSSID: "00:11:22:33:44:55", SSID: "OpenNet", Encryption: "OPEN", RSSI: -40},
		{Index: 1, BSSID: "AA:BB:CC:DD:EE:FF", SSID: "WeakWPA", Encryption: "WPA2", RSSI: -80},
		{Index: 2, BSSID: "11:22:33:44:55:66", SSID: "StrongWPA", Encryption: "WPA2", RSSI: -55},
		{Index: 3, BSSID: "99:88:77:66:55:44", SSID: "WPA3Net", Encryption: "WPA3", RSSI: -30},
	}
	best := workflows.PickStrongestWPAForTest(aps)
	if best == nil {
		t.Fatal("expected a candidate")
	}
	if best.SSID != "StrongWPA" {
		t.Errorf("expected StrongWPA (best RSSI among WPA/WPA2), got %q", best.SSID)
	}
}
