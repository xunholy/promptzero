package bruce

import (
	"context"
	"strings"
	"testing"
)

// newTestClient returns a Client wired to a MockPort with the given canned
// responses pre-installed.
func newTestClient(caps Capabilities) (*Client, *MockPort) {
	mp := NewMockPort()
	c := NewWithPort(mp)
	c.SetCapabilities(caps)
	return c, mp
}

func allCaps() Capabilities {
	return Capabilities{
		HasFiveGHz: true,
		HasZigbee:  true,
		HasLoRa:    true,
		HasNFC:     true,
		HasIR:      true,
		BoardType:  "esp32-c5",
	}
}

// --- Capabilities -----------------------------------------------------------

func TestCapabilities_RoundTrip(t *testing.T) {
	caps := allCaps()
	c, _ := newTestClient(caps)
	got := c.Capabilities()
	if got.HasFiveGHz != caps.HasFiveGHz {
		t.Errorf("HasFiveGHz: got %v, want %v", got.HasFiveGHz, caps.HasFiveGHz)
	}
	if got.BoardType != caps.BoardType {
		t.Errorf("BoardType: got %q, want %q", got.BoardType, caps.BoardType)
	}
}

// --- ScanWiFi ---------------------------------------------------------------

func TestScanWiFi_ReturnsAPs(t *testing.T) {
	c, mp := newTestClient(Capabilities{})
	mp.Respond("wifi scan",
		"SSID: TestNet, BSSID: aa:bb:cc:dd:ee:ff, RSSI: -60, CH: 6\n"+
			"SSID: Other, BSSID: 11:22:33:44:55:66, RSSI: -75, CH: 11")

	aps, err := c.ScanWiFi(context.Background())
	if err != nil {
		t.Fatalf("ScanWiFi: %v", err)
	}
	if len(aps) != 2 {
		t.Fatalf("expected 2 APs, got %d", len(aps))
	}
	if aps[0].SSID != "TestNet" {
		t.Errorf("first AP SSID: got %q, want %q", aps[0].SSID, "TestNet")
	}
	if aps[0].Band != "2.4GHz" {
		t.Errorf("band: got %q, want %q", aps[0].Band, "2.4GHz")
	}
}

func TestScanWiFi_EmptyResponse(t *testing.T) {
	c, mp := newTestClient(Capabilities{})
	mp.Respond("wifi scan", "No APs found")

	aps, err := c.ScanWiFi(context.Background())
	if err != nil {
		t.Fatalf("ScanWiFi: %v", err)
	}
	// "No APs found" has no BSSID/SSID so parses to zero APs.
	if len(aps) != 0 {
		t.Errorf("expected 0 APs, got %d", len(aps))
	}
}

// --- Scan5GHz ---------------------------------------------------------------

func TestScan5GHz_CapabilityPresent(t *testing.T) {
	c, mp := newTestClient(Capabilities{HasFiveGHz: true})
	mp.Respond("wifi 5g scan",
		"SSID: Fast5G, BSSID: aa:bb:cc:dd:ee:ff, RSSI: -50, CH: 36")

	aps, err := c.Scan5GHz(context.Background())
	if err != nil {
		t.Fatalf("Scan5GHz: %v", err)
	}
	if len(aps) != 1 {
		t.Fatalf("expected 1 AP, got %d", len(aps))
	}
	if aps[0].Band != "5GHz" {
		t.Errorf("band: got %q, want %q", aps[0].Band, "5GHz")
	}
}

func TestScan5GHz_CapabilityMissing(t *testing.T) {
	c, _ := newTestClient(Capabilities{HasFiveGHz: false})
	_, err := c.Scan5GHz(context.Background())
	if err == nil {
		t.Fatal("expected ErrCapabilityNotAvailable, got nil")
	}
	if err != ErrCapabilityNotAvailable {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- Deauth -----------------------------------------------------------------

func TestDeauth_SendsCorrectCommand(t *testing.T) {
	c, mp := newTestClient(Capabilities{})
	mp.Respond("wifi deauth aa:bb:cc:dd:ee:ff 6", "OK")

	if err := c.Deauth(context.Background(), "aa:bb:cc:dd:ee:ff", 6); err != nil {
		t.Fatalf("Deauth: %v", err)
	}
	seen := mp.LinesSeen()
	if len(seen) == 0 {
		t.Fatal("no command observed")
	}
	if seen[0] != "wifi deauth aa:bb:cc:dd:ee:ff 6" {
		t.Errorf("command: got %q, want %q", seen[0], "wifi deauth aa:bb:cc:dd:ee:ff 6")
	}
}

// --- EvilTwin ---------------------------------------------------------------

func TestEvilTwin_SendsCorrectCommand(t *testing.T) {
	c, mp := newTestClient(Capabilities{})
	mp.Respond("wifi evil CorpWLAN aa:bb:cc:dd:ee:ff", "")

	if err := c.EvilTwin(context.Background(), "CorpWLAN", "aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatalf("EvilTwin: %v", err)
	}
	seen := mp.LinesSeen()
	if len(seen) == 0 {
		t.Fatal("no command observed")
	}
	if seen[0] != "wifi evil CorpWLAN aa:bb:cc:dd:ee:ff" {
		t.Errorf("command: got %q", seen[0])
	}
}

// --- ZigbeeScan -------------------------------------------------------------

func TestZigbeeScan_CapabilityPresent(t *testing.T) {
	c, mp := newTestClient(Capabilities{HasZigbee: true})
	mp.Respond("rf zigbee scan", "PAN ID: 0x1234, Addr: 0x0001, Ch: 15")

	peers, err := c.ZigbeeScan(context.Background())
	if err != nil {
		t.Fatalf("ZigbeeScan: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].PANID != "0x1234" {
		t.Errorf("PANID: got %q", peers[0].PANID)
	}
}

func TestZigbeeScan_CapabilityMissing(t *testing.T) {
	c, _ := newTestClient(Capabilities{HasZigbee: false})
	_, err := c.ZigbeeScan(context.Background())
	if err != ErrCapabilityNotAvailable {
		t.Errorf("expected ErrCapabilityNotAvailable, got %v", err)
	}
}

// --- LoRaScan ---------------------------------------------------------------

func TestLoRaScan_CapabilityPresent(t *testing.T) {
	c, mp := newTestClient(Capabilities{HasLoRa: true})
	mp.Respond("rf lora scan 433.920", "")

	if err := c.LoRaScan(context.Background(), 433.920); err != nil {
		t.Fatalf("LoRaScan: %v", err)
	}
	seen := mp.LinesSeen()
	if len(seen) == 0 || !strings.HasPrefix(seen[0], "rf lora scan") {
		t.Errorf("unexpected command: %v", seen)
	}
}

func TestLoRaScan_CapabilityMissing(t *testing.T) {
	c, _ := newTestClient(Capabilities{HasLoRa: false})
	if err := c.LoRaScan(context.Background(), 433.0); err != ErrCapabilityNotAvailable {
		t.Errorf("expected ErrCapabilityNotAvailable, got %v", err)
	}
}

// --- IRSend -----------------------------------------------------------------

func TestIRSend_CapabilityPresent(t *testing.T) {
	c, mp := newTestClient(Capabilities{HasIR: true})
	mp.Respond("ir send NEC 0xDEADBEEF", "OK")

	if err := c.IRSend(context.Background(), "NEC", "0xDEADBEEF"); err != nil {
		t.Fatalf("IRSend: %v", err)
	}
	seen := mp.LinesSeen()
	if len(seen) == 0 || seen[0] != "ir send NEC 0xDEADBEEF" {
		t.Errorf("unexpected command: %v", seen)
	}
}

func TestIRSend_CapabilityMissing(t *testing.T) {
	c, _ := newTestClient(Capabilities{HasIR: false})
	if err := c.IRSend(context.Background(), "NEC", "0x01"); err != ErrCapabilityNotAvailable {
		t.Errorf("expected ErrCapabilityNotAvailable, got %v", err)
	}
}

// --- IRReceive --------------------------------------------------------------

func TestIRReceive_CapabilityPresent(t *testing.T) {
	c, mp := newTestClient(Capabilities{HasIR: true})
	mp.Respond("ir receive", "Protocol: NEC\nCode: 0xABCD\n")

	cap, err := c.IRReceive(context.Background())
	if err != nil {
		t.Fatalf("IRReceive: %v", err)
	}
	if cap.Protocol != "NEC" {
		t.Errorf("Protocol: got %q, want NEC", cap.Protocol)
	}
}

func TestIRReceive_CapabilityMissing(t *testing.T) {
	c, _ := newTestClient(Capabilities{HasIR: false})
	_, err := c.IRReceive(context.Background())
	if err != ErrCapabilityNotAvailable {
		t.Errorf("expected ErrCapabilityNotAvailable, got %v", err)
	}
}

// --- BadUSBRun --------------------------------------------------------------

func TestBadUSBRun_SendsCorrectCommand(t *testing.T) {
	c, mp := newTestClient(Capabilities{})
	mp.Respond("badusb run payload.txt", "Running")

	if err := c.BadUSBRun(context.Background(), "payload.txt"); err != nil {
		t.Fatalf("BadUSBRun: %v", err)
	}
	seen := mp.LinesSeen()
	if len(seen) == 0 || seen[0] != "badusb run payload.txt" {
		t.Errorf("unexpected command: %v", seen)
	}
}

// --- NFCRead ----------------------------------------------------------------

func TestNFCRead_CapabilityPresent(t *testing.T) {
	c, mp := newTestClient(Capabilities{HasNFC: true})
	mp.Respond("nfc read", "UID: 04 5A 3B FF\nATQA: 0004\nSAK: 08")

	card, err := c.NFCRead(context.Background())
	if err != nil {
		t.Fatalf("NFCRead: %v", err)
	}
	if card.UID != "04 5A 3B FF" {
		t.Errorf("UID: got %q, want %q", card.UID, "04 5A 3B FF")
	}
}

func TestNFCRead_CapabilityMissing(t *testing.T) {
	c, _ := newTestClient(Capabilities{HasNFC: false})
	_, err := c.NFCRead(context.Background())
	if err != ErrCapabilityNotAvailable {
		t.Errorf("expected ErrCapabilityNotAvailable, got %v", err)
	}
}

// --- RawCommand -------------------------------------------------------------

func TestRawCommand_ReturnsResponse(t *testing.T) {
	c, mp := newTestClient(Capabilities{})
	mp.Respond("custom cmd", "custom output")

	out, err := c.RawCommand(context.Background(), "custom cmd")
	if err != nil {
		t.Fatalf("RawCommand: %v", err)
	}
	if !strings.Contains(out, "custom output") {
		t.Errorf("expected 'custom output' in response, got: %q", out)
	}
}

func TestRawCommand_UnscriptedDoesNotHang(t *testing.T) {
	c, _ := newTestClient(Capabilities{})
	// No response registered; should return quickly with empty output.
	out, err := c.RawCommand(context.Background(), "unscripted cmd")
	if err != nil {
		t.Fatalf("RawCommand unscripted: %v", err)
	}
	// We just care it doesn't hang; output may be empty.
	_ = out
}
