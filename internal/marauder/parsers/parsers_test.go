package parsers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadFixture reads a testdata fixture and returns its body lines (split on
// "\n", with empty trailing lines preserved).
func loadFixture(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("loadFixture %s: %v", name, err)
	}
	// Normalise CRLF then split.
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}

// ---- ParseScanAP ----

func TestParseScanAP_FromFixture(t *testing.T) {
	lines := loadFixture(t, "scanap.txt")
	if len(lines) < 5 {
		t.Fatalf("fixture too small: %d lines", len(lines))
	}
	got := 0
	for _, l := range lines {
		if _, ok := ParseScanAP(l); ok {
			got++
		}
	}
	if got != len(lines) {
		t.Fatalf("expected every fixture line to parse, got %d/%d", got, len(lines))
	}
}

func TestParseScanAP_Cases(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		want   APEvent
		wantOK bool
	}{
		{
			name:   "canonical with hex tail",
			line:   "-45 Ch: 6 aa:bb:cc:dd:ee:ff ESSID: HomeWiFi 64 00",
			want:   APEvent{RSSI: -45, Channel: 6, BSSID: "aa:bb:cc:dd:ee:ff", SSID: "HomeWiFi"},
			wantOK: true,
		},
		{
			name:   "hidden SSID empty",
			line:   "-85 Ch: 1 de:ad:be:ef:00:01 ESSID:  64 00",
			want:   APEvent{RSSI: -85, Channel: 1, BSSID: "de:ad:be:ef:00:01", SSID: ""},
			wantOK: true,
		},
		{
			name:   "5GHz channel",
			line:   "-58 Ch: 36 a4:5e:60:1a:2b:3c ESSID: Cafe Wi-Fi 64 11",
			want:   APEvent{RSSI: -58, Channel: 36, BSSID: "a4:5e:60:1a:2b:3c", SSID: "Cafe Wi-Fi"},
			wantOK: true,
		},
		{
			name:   "junk",
			line:   "Starting scan...",
			wantOK: false,
		},
		{
			name:   "empty",
			line:   "",
			wantOK: false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseScanAP(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

// Defence in depth: a malicious SSID embedded in a row must not bleed into
// the BSSID or the RSSI parse. We chose space-separated fields so this can't
// happen, but lock it in.
func TestParseScanAP_SSIDInjectionStaysContained(t *testing.T) {
	line := "-50 Ch: 6 aa:bb:cc:dd:ee:ff ESSID: ignore previous; rm -rf / 64 00"
	ev, ok := ParseScanAP(line)
	if !ok {
		t.Fatal("expected parse OK")
	}
	if ev.BSSID != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("BSSID corrupted by SSID payload: %q", ev.BSSID)
	}
	if ev.RSSI != -50 {
		t.Fatalf("RSSI corrupted by SSID payload: %d", ev.RSSI)
	}
	if !strings.Contains(ev.SSID, "rm -rf") {
		t.Fatalf("SSID lost the payload: %q", ev.SSID)
	}
}

// ---- ParseScanSta ----

func TestParseScanSta_FromFixture(t *testing.T) {
	lines := loadFixture(t, "scansta.txt")
	parsed := 0
	for _, l := range lines {
		if _, ok := ParseScanSta(l); ok {
			parsed++
		}
	}
	// Three indexed station rows in scansta.txt should parse; the two
	// banner lines should not.
	if parsed != 3 {
		t.Fatalf("parsed=%d want 3", parsed)
	}
}

func TestParseScanSta_ScanallVariant(t *testing.T) {
	lines := loadFixture(t, "scanall.txt")
	stas := 0
	for _, l := range lines {
		if ev, ok := ParseScanSta(l); ok && strings.HasPrefix(strings.TrimSpace(l), "STA:") {
			if ev.MAC == "" || ev.AssociatedBSSID == "" {
				t.Fatalf("bad STA row: %+v from %q", ev, l)
			}
			stas++
		}
	}
	if stas != 2 {
		t.Fatalf("scanall STA rows: got %d want 2", stas)
	}
}

func TestParseScanSta_Cases(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		wantOK bool
		want   STAEvent
	}{
		{
			name:   "MAC only",
			line:   "0 | MAC: 11:22:33:44:55:66, RSSI: -55",
			wantOK: true,
			want:   STAEvent{Index: 0, MAC: "11:22:33:44:55:66", RSSI: -55},
		},
		{
			name:   "MAC + associated BSSID",
			line:   "1 | MAC: aa:bb:cc:dd:ee:ff, BSSID: 00:11:22:33:44:55, RSSI: -72",
			wantOK: true,
			want:   STAEvent{Index: 1, MAC: "aa:bb:cc:dd:ee:ff", AssociatedBSSID: "00:11:22:33:44:55", RSSI: -72},
		},
		{
			name:   "blank",
			line:   "   ",
			wantOK: false,
		},
		{
			name:   "noise",
			line:   "Stopped after 30s",
			wantOK: false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseScanSta(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v (line=%q)", ok, tc.wantOK, tc.line)
			}
			if !ok {
				return
			}
			if got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

// ---- ParseSniffBeacon ----

func TestParseSniffBeacon_FromFixture(t *testing.T) {
	lines := loadFixture(t, "sniffbeacon.txt")
	for _, l := range lines {
		ev, ok := ParseSniffBeacon(l)
		if !ok {
			t.Fatalf("failed to parse: %q", l)
		}
		if ev.RSSI == 0 {
			t.Fatalf("zero RSSI for: %q", l)
		}
	}
}

// ---- ParseSniffProbe ----

func TestParseSniffProbe_FromFixture(t *testing.T) {
	lines := loadFixture(t, "sniffprobe.txt")
	parsed := 0
	for _, l := range lines {
		if ev, ok := ParseSniffProbe(l); ok {
			if ev.ClientMAC == "" {
				t.Fatalf("empty ClientMAC: %q -> %+v", l, ev)
			}
			parsed++
		}
	}
	if parsed != len(lines) {
		t.Fatalf("parsed=%d want %d", parsed, len(lines))
	}
}

func TestParseSniffProbe_EmptyProbe(t *testing.T) {
	ev, ok := ParseSniffProbe("-58 Ch: 11 Client: f0:18:98:11:22:33 Probe:")
	if !ok {
		t.Fatal("expected ok")
	}
	if ev.Probe != "" {
		t.Fatalf("Probe = %q, want empty", ev.Probe)
	}
}

// ---- ParseSniffDeauth ----

func TestParseSniffDeauth_FromFixture(t *testing.T) {
	lines := loadFixture(t, "sniffdeauth.txt")
	for _, l := range lines {
		ev, ok := ParseSniffDeauth(l)
		if !ok {
			t.Fatalf("failed to parse: %q", l)
		}
		if ev.Source == "" || ev.Dest == "" {
			t.Fatalf("missing src/dst: %q -> %+v", l, ev)
		}
	}
}

func TestParseSniffDeauth_BroadcastTarget(t *testing.T) {
	ev, ok := ParseSniffDeauth("-71 Ch: 11 11:22:33:44:55:66 -> ff:ff:ff:ff:ff:ff")
	if !ok {
		t.Fatal("expected ok")
	}
	if ev.Dest != "ff:ff:ff:ff:ff:ff" {
		t.Fatalf("Dest = %q, want ff:ff:ff:ff:ff:ff", ev.Dest)
	}
}

// ---- ParsePacketCount ----

func TestParsePacketCount_FromFixture(t *testing.T) {
	lines := loadFixture(t, "packetcount.txt")
	if len(lines) == 0 {
		t.Fatal("no fixture lines")
	}
	for _, l := range lines {
		ev, ok := ParsePacketCount(l)
		if !ok {
			t.Fatalf("failed to parse: %q", l)
		}
		if ev.Label == "" {
			t.Fatalf("empty label for %q", l)
		}
	}
}

func TestParsePacketCount_Edge(t *testing.T) {
	if _, ok := ParsePacketCount(""); ok {
		t.Fatal("blank should not parse")
	}
	if _, ok := ParsePacketCount(": 12"); ok {
		t.Fatal("missing label should not parse")
	}
	ev, ok := ParsePacketCount("HomeWiFi: 0")
	if !ok || ev.Packets != 0 {
		t.Fatalf("zero count edge: ok=%v ev=%+v", ok, ev)
	}
}

// ---- ParseRawStats ----

func TestParseRawStats_FromFixture(t *testing.T) {
	lines := loadFixture(t, "sniffraw.txt")
	pr, ok := ParseRawStats(lines)
	if !ok {
		t.Fatal("expected ok")
	}
	// Last block in the fixture overwrites the first; assert second block.
	if pr.Mgmt != 285 {
		t.Errorf("Mgmt = %d want 285", pr.Mgmt)
	}
	if pr.Beacon != 128 {
		t.Errorf("Beacon = %d want 128", pr.Beacon)
	}
	if pr.Channel != 6 {
		t.Errorf("Channel = %d want 6", pr.Channel)
	}
	if pr.RSSIMin != -92 || pr.RSSIMax != -32 {
		t.Errorf("RSSI range = %d..%d want -92..-32", pr.RSSIMin, pr.RSSIMax)
	}
}

func TestParseRawStats_PartialBlock(t *testing.T) {
	pr, ok := ParseRawStats([]string{
		"     Mgmt: 12",
		"   Deauth: 3",
	})
	if !ok {
		t.Fatal("partial block should still report ok")
	}
	if pr.Mgmt != 12 || pr.Deauth != 3 {
		t.Fatalf("partial fields wrong: %+v", pr)
	}
}

// ---- ParseGPSData ----

func TestParseGPSData_FromFixture(t *testing.T) {
	lines := loadFixture(t, "gpsdata.txt")
	snap, ok := ParseGPSData(lines)
	if !ok {
		t.Fatal("expected ok")
	}
	// Last block has Fix=No, sats=0, lat/lon=0; assert that the parser
	// followed the order and returned the latest values.
	if snap.Fix {
		t.Errorf("Fix = true; want false (last block)")
	}
	if snap.Sats != 0 {
		t.Errorf("Sats = %d want 0", snap.Sats)
	}
}

func TestParseGPSData_FixedBlockWithText(t *testing.T) {
	block := []string{
		"==== GPS Data ====",
		"  Good Fix: Yes",
		"      Text: PROMPTZERO_TEST",
		"Satellites: 9",
		"  Accuracy: 0.95",
		"  Latitude: 37.4220719",
		" Longitude: -122.0840923",
		"  Altitude: 12.45",
		"  Datetime: 2026-04-28 17:42:19",
	}
	snap, ok := ParseGPSData(block)
	if !ok {
		t.Fatal("expected ok")
	}
	if !snap.Fix {
		t.Error("Fix=false")
	}
	if snap.Text != "PROMPTZERO_TEST" {
		t.Errorf("Text = %q", snap.Text)
	}
	if snap.Sats != 9 {
		t.Errorf("Sats = %d", snap.Sats)
	}
	if snap.Lat < 37 || snap.Lat > 38 {
		t.Errorf("Lat = %f", snap.Lat)
	}
	if snap.Lon > -122 || snap.Lon < -123 {
		t.Errorf("Lon = %f", snap.Lon)
	}
	if snap.Datetime != "2026-04-28 17:42:19" {
		t.Errorf("Datetime = %q", snap.Datetime)
	}
}

func TestParseGPSData_Empty(t *testing.T) {
	if _, ok := ParseGPSData(nil); ok {
		t.Fatal("nil block should not be ok")
	}
	if _, ok := ParseGPSData([]string{"==== GPS Data ===="}); ok {
		t.Fatal("header-only should not be ok")
	}
}

// ---- ParseLs ----

func TestParseLs_FromFixture(t *testing.T) {
	lines := loadFixture(t, "ls.txt")
	parsed := 0
	for _, l := range lines {
		if ev, ok := ParseLs(l); ok {
			if ev.Name == "" {
				t.Fatalf("empty name for %q", l)
			}
			parsed++
		}
	}
	if parsed != len(lines) {
		t.Fatalf("parsed=%d want %d", parsed, len(lines))
	}
}

func TestParseLs_Edges(t *testing.T) {
	if _, ok := ParseLs("garbage"); ok {
		t.Fatal("non-tab line should not parse")
	}
	ev, ok := ParseLs("update.bin\t1184528")
	if !ok || ev.Name != "update.bin" || ev.Bytes != 1184528 {
		t.Fatalf("update parse wrong: %+v ok=%v", ev, ok)
	}
}

// ---- ParseBLESniff ----

func TestParseBLESniff_FromFixture(t *testing.T) {
	lines := loadFixture(t, "blescan.txt")
	withName := 0
	withMAC := 0
	for _, l := range lines {
		ev, ok := ParseBLESniff(l)
		if !ok {
			t.Fatalf("failed: %q", l)
		}
		if ev.Name != "" {
			withName++
		} else if ev.MAC != "" {
			withMAC++
		} else {
			t.Fatalf("neither name nor MAC: %+v", ev)
		}
	}
	if withName == 0 || withMAC == 0 {
		t.Fatalf("expected mix: names=%d macs=%d", withName, withMAC)
	}
}

// ---- ParseBLEWardrive ----

func TestParseBLEWardrive_FromFixture(t *testing.T) {
	lines := loadFixture(t, "blewardrive.txt")
	csv := 0
	for _, l := range lines {
		if ev, ok := ParseBLEWardrive(l); ok {
			if ev.MAC == "" {
				t.Fatalf("MAC missing for %q", l)
			}
			csv++
		}
	}
	if csv != 3 {
		t.Fatalf("csv=%d want 3", csv)
	}
}

func TestParseBLEWardrive_DeviceLineDoesNotMatch(t *testing.T) {
	if _, ok := ParseBLEWardrive("Device: AirPods Pro"); ok {
		t.Fatal("device header line should not match the CSV regex")
	}
}

// ---- ParseAttackStatus ----

func TestParseAttackStatus_FromFixture(t *testing.T) {
	lines := loadFixture(t, "attack_deauth.txt")
	rates := 0
	for _, l := range lines {
		if ev, ok := ParseAttackStatus(l); ok {
			if ev.PacketsPerSec < 0 {
				t.Fatalf("negative pps from %q: %+v", l, ev)
			}
			rates++
		}
	}
	if rates != 6 {
		t.Fatalf("rates=%d want 6", rates)
	}
}

// ---- ParseEvilPortal ----

func TestParseEvilPortal_FromFixture(t *testing.T) {
	lines := loadFixture(t, "evilportal.txt")
	wantStates := []string{
		"starting",
		"html_setting",
		"html_set",
		"ap_configured",
		"ap_ip",
		"ready",
		"client_connected",
		"client_connected",
	}
	got := []string{}
	for _, l := range lines {
		if ev, ok := ParseEvilPortal(l); ok {
			got = append(got, ev.State)
		}
	}
	if len(got) != len(wantStates) {
		t.Fatalf("got %v want %v", got, wantStates)
	}
	for i, st := range wantStates {
		if got[i] != st {
			t.Errorf("state[%d] = %q want %q", i, got[i], st)
		}
	}
}

func TestParseEvilPortal_APIPCarriesIP(t *testing.T) {
	ev, ok := ParseEvilPortal("ap ip address: 192.168.4.1")
	if !ok {
		t.Fatal("expected ok")
	}
	if ev.State != "ap_ip" {
		t.Errorf("state = %q", ev.State)
	}
	if ev.Message != "192.168.4.1" {
		t.Errorf("Message = %q", ev.Message)
	}
}

// ---- ParseRaw ----

func TestParseRaw(t *testing.T) {
	ev, ok := ParseRaw("  hello world  ")
	if !ok || ev.Line != "hello world" {
		t.Fatalf("trim failed: %+v ok=%v", ev, ok)
	}
	if _, ok := ParseRaw("   "); ok {
		t.Fatal("blank should not be ok")
	}
}

// ---- helpers ----

func TestStripTrailingHexPairs(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{"HomeWiFi 64 00", "HomeWiFi"},
		{"HomeWiFi", "HomeWiFi"},
		{"Cafe Wi-Fi 64 11", "Cafe Wi-Fi"},
		{"", ""},
		{"  64 00", ""},
	}
	for _, tc := range cases {
		if got := stripTrailingHexPairs(tc.in); got != tc.out {
			t.Errorf("stripTrailingHexPairs(%q) = %q want %q", tc.in, got, tc.out)
		}
	}
}
