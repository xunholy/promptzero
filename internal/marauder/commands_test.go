package marauder

import (
	"context"
	"strings"
	"testing"
	"time"
)

// commands_test.go — happy-path wire-form tests for every simple
// `m.Exec(cmd, …)` wrapper in commands.go. The motivation is
// regression protection against accidental command-name typos that
// would silently break firmware comms (the underlying Marauder
// firmware ignores unknown tokens without feedback over CLI). The
// table-driven shape keeps the per-method overhead low so adding a
// new wrapper is a one-line entry rather than a copy-paste of the
// fakePort scaffolding.
//
// Validation-bearing wrappers (BLESpam, SniffPMKID, SetSetting,
// LEDSetHex, etc.) are NOT covered here — their error paths and
// allowlists need bespoke assertions and live in their own test
// blocks.

// commandsWireFormCases is the table of simple-wrapper command
// fixtures. Each fn invokes the wrapper with realistic args and
// returns whatever (string, error) the method returns; the test
// harness extracts the first line from the fake port and asserts
// it equals want. dt is the timeout the wrapper passes to Exec —
// passed in from the test rather than hardcoded so a future
// refactor that changes a wrapper's hardcoded timeout doesn't
// silently break this test.
type commandsWireFormCase struct {
	name string
	want string
	fn   func(*Marauder) (string, error)
}

func commandsWireFormCases() []commandsWireFormCase {
	const dt = 200 * time.Millisecond
	return []commandsWireFormCase{
		// --- Scanning ---
		{"ScanAP", "scanap", func(m *Marauder) (string, error) { return m.ScanAP(dt) }},
		{"ScanAll", "scanall", func(m *Marauder) (string, error) { return m.ScanAll(dt) }},
		{"StopScan", "stopscan", func(m *Marauder) (string, error) { return m.StopScan() }},

		// --- Selection ---
		{"SelectAP_indices", "select -a 0,1,2", func(m *Marauder) (string, error) { return m.SelectAP("0,1,2") }},
		{"SelectAP_all", "select -a all", func(m *Marauder) (string, error) { return m.SelectAP("all") }},
		{"SelectStation_indices", "select -c 3", func(m *Marauder) (string, error) { return m.SelectStation("3") }},
		{"SelectSSID_all", "select -s all", func(m *Marauder) (string, error) { return m.SelectSSID("all") }},

		// --- Lists ---
		{"ListAPs", "list -a", func(m *Marauder) (string, error) { return m.ListAPs() }},
		{"ListSSIDs", "list -s", func(m *Marauder) (string, error) { return m.ListSSIDs() }},
		{"ListStations", "list -c", func(m *Marauder) (string, error) { return m.ListStations() }},
		{"ClearAPs", "clearlist -a", func(m *Marauder) (string, error) { return m.ClearAPs() }},
		{"ClearSSIDs", "clearlist -s", func(m *Marauder) (string, error) { return m.ClearSSIDs() }},
		{"ClearStations", "clearlist -c", func(m *Marauder) (string, error) { return m.ClearStations() }},

		// --- Attacks ---
		{"DeauthAttack", "attack -t deauth", func(m *Marauder) (string, error) { return m.DeauthAttack(dt) }},
		{"DeauthToStationList", "attack -t deauth -c", func(m *Marauder) (string, error) { return m.DeauthToStationList(dt) }},
		{"BeaconSpamList", "attack -t beacon -l", func(m *Marauder) (string, error) { return m.BeaconSpamList(dt) }},
		{"BeaconSpamRandom", "attack -t beacon -r", func(m *Marauder) (string, error) { return m.BeaconSpamRandom(dt) }},
		{"BeaconSpamClone", "attack -t beacon -a", func(m *Marauder) (string, error) { return m.BeaconSpamClone(dt) }},
		{"BeaconSpamRickroll", "attack -t rickroll", func(m *Marauder) (string, error) { return m.BeaconSpamRickroll(dt) }},
		{"BeaconSpamFunny", "attack -t funny", func(m *Marauder) (string, error) { return m.BeaconSpamFunny(dt) }},
		{"ProbeFlood", "attack -t probe", func(m *Marauder) (string, error) { return m.ProbeFlood(dt) }},
		{"CSAAttack", "attack -t csa", func(m *Marauder) (string, error) { return m.CSAAttack(dt) }},
		{"SAEFlood", "attack -t sae", func(m *Marauder) (string, error) { return m.SAEFlood(dt) }},

		// --- Sniffing ---
		{"SniffBeacon", "sniffbeacon", func(m *Marauder) (string, error) { return m.SniffBeacon(dt) }},
		{"SniffDeauth", "sniffdeauth", func(m *Marauder) (string, error) { return m.SniffDeauth(dt) }},
		{"SniffProbe", "sniffprobe", func(m *Marauder) (string, error) { return m.SniffProbe(dt) }},
		{"SniffPwnagotchi", "sniffpwn", func(m *Marauder) (string, error) { return m.SniffPwnagotchi(dt) }},
		{"SniffRaw", "sniffraw", func(m *Marauder) (string, error) { return m.SniffRaw(dt) }},
		{"SniffSkimmer", "sniffskim", func(m *Marauder) (string, error) { return m.SniffSkimmer(dt) }},

		// --- SniffPMKID flag combinations (validation passes through here) ---
		{"SniffPMKID_default", "sniffpmkid", func(m *Marauder) (string, error) { return m.SniffPMKID(0, false, false, dt) }},
		{"SniffPMKID_channel", "sniffpmkid -c 6", func(m *Marauder) (string, error) { return m.SniffPMKID(6, false, false, dt) }},
		{"SniffPMKID_deauth", "sniffpmkid -d", func(m *Marauder) (string, error) { return m.SniffPMKID(0, true, false, dt) }},
		{"SniffPMKID_listOnly", "sniffpmkid -l", func(m *Marauder) (string, error) { return m.SniffPMKID(0, false, true, dt) }},
		{"SniffPMKID_all", "sniffpmkid -c 1 -d -l", func(m *Marauder) (string, error) { return m.SniffPMKID(1, true, true, dt) }},

		// --- Channel ---
		{"SetChannel", "channel -s 6", func(m *Marauder) (string, error) { return m.SetChannel(6) }},
		{"GetChannel", "channel", func(m *Marauder) (string, error) { return m.GetChannel() }},

		// --- SSID ---
		{"GenerateSSIDs", "ssid -a -g 5", func(m *Marauder) (string, error) { return m.GenerateSSIDs(5) }},
		{"RemoveSSID", "ssid -r 2", func(m *Marauder) (string, error) { return m.RemoveSSID(2) }},

		// --- Network recon ---
		{"PingScan", "pingscan", func(m *Marauder) (string, error) { return m.PingScan(dt) }},
		{"ARPScan", "arpscan", func(m *Marauder) (string, error) { return m.ARPScan(dt) }},
		{"PortScan", "portscan -a -t 0", func(m *Marauder) (string, error) { return m.PortScan(0, dt) }},

		// --- MAC ---
		{"RandomAPMAC", "randapmac", func(m *Marauder) (string, error) { return m.RandomAPMAC() }},
		{"RandomStaMAC", "randstamac", func(m *Marauder) (string, error) { return m.RandomStaMAC() }},
		{"CloneAPMAC", "cloneapmac -a 4", func(m *Marauder) (string, error) { return m.CloneAPMAC(4) }},

		// --- Save/Load ---
		{"SaveAPs", "save -a", func(m *Marauder) (string, error) { return m.SaveAPs() }},
		{"SaveSSIDs", "save -s", func(m *Marauder) (string, error) { return m.SaveSSIDs() }},
		{"LoadAPs", "load -a", func(m *Marauder) (string, error) { return m.LoadAPs() }},
		{"LoadSSIDs", "load -s", func(m *Marauder) (string, error) { return m.LoadSSIDs() }},

		// --- Settings (no-arg) ---
		{"Settings", "settings", func(m *Marauder) (string, error) { return m.Settings() }},

		// --- System ---
		{"Info", "info", func(m *Marauder) (string, error) { return m.Info() }},
		{"Reboot", "reboot", func(m *Marauder) (string, error) { return m.Reboot() }},
		{"Update", "update -s", func(m *Marauder) (string, error) { return m.Update() }},

		// --- GPS ---
		{"GPSData", "gpsdata", func(m *Marauder) (string, error) { return m.GPSData() }},
		{"NMEA", "nmea", func(m *Marauder) (string, error) { return m.NMEA(dt) }},

		// --- GPSField with allowlist ---
		{"GPSField_lat", "gps -g lat", func(m *Marauder) (string, error) { return m.GPSField("lat", "") }},
		{"GPSField_lon_with_nav", "gps -g lon -n gps", func(m *Marauder) (string, error) { return m.GPSField("lon", "gps") }},

		// --- Device-local ---
		{"PacketCount", "packetcount", func(m *Marauder) (string, error) { return m.PacketCount() }},
		{"StorageLS_root", `ls "/"`, func(m *Marauder) (string, error) { return m.StorageLS("") }},
		{"StorageLS_path", `ls "/some/dir"`, func(m *Marauder) (string, error) { return m.StorageLS("/some/dir") }},

		// --- LED ---
		{"LEDSetHex_lower", "led -s ff0000", func(m *Marauder) (string, error) { return m.LEDSetHex("ff0000") }},
		{"LEDSetHex_with_hash", "led -s 00ff00", func(m *Marauder) (string, error) { return m.LEDSetHex("#00ff00") }},
		{"LEDSetHex_with_0x", "led -s 0000ff", func(m *Marauder) (string, error) { return m.LEDSetHex("0x0000ff") }},
		{"LEDRainbow", "led -p rainbow", func(m *Marauder) (string, error) { return m.LEDRainbow() }},

		// --- Evil portal (basic shapes) ---
		{"EvilPortalStart_default", "evilportal -c start", func(m *Marauder) (string, error) { return m.EvilPortalStart("") }},
		{"EvilPortalStart_filename", `evilportal -c start -w "page.html"`, func(m *Marauder) (string, error) { return m.EvilPortalStart("page.html") }},
		{"EvilPortalSetHTMLStr", "evilportal -c sethtmlstr", func(m *Marauder) (string, error) { return m.EvilPortalSetHTMLStr() }},
	}
}

// TestCommandsWireForm pins the wire form of every simple command
// wrapper. A failure here means a wrapper stopped sending the bytes
// the firmware expects — usually a typo in the command string or an
// accidental flag rename. Catching this at compile-test time is much
// cheaper than catching it the next time the operator plugs in a
// real Marauder.
func TestCommandsWireForm(t *testing.T) {
	for _, tc := range commandsWireFormCases() {
		tc := tc // capture for parallel safety
		t.Run(tc.name, func(t *testing.T) {
			got, err := wireCmd(t, tc.fn)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if got != tc.want {
				t.Errorf("wire = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestValidationGuardedWrappers pins the allowlist-bearing wrappers
// that 0%-coverage previously hid: BLESpam, SniffBT,
// PortScanService, SetSetting. Each rejects unknown values at the
// Go layer instead of forwarding them as silent firmware no-ops.
// The valid-path also checks the dispatched bytes so the
// command-name + flag-shape regression catch from
// TestCommandsWireForm extends here too.
func TestValidationGuardedWrappers(t *testing.T) {
	t.Run("BLESpam_valid", func(t *testing.T) {
		got, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.BLESpam("apple", 100*time.Millisecond)
		})
		if err != nil {
			t.Fatalf("BLESpam(apple): %v", err)
		}
		if got != "blespam -t apple" {
			t.Errorf("BLESpam wire = %q, want blespam -t apple", got)
		}
	})
	t.Run("BLESpam_invalid_mode", func(t *testing.T) {
		_, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.BLESpam("nonsense", 100*time.Millisecond)
		})
		if err == nil {
			t.Error("BLESpam(nonsense) should error on invalid mode")
		}
	})
	t.Run("BLESpamCtx_valid", func(t *testing.T) {
		got, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.BLESpamCtx(context.Background(), "google", 100*time.Millisecond)
		})
		if err != nil {
			t.Fatalf("BLESpamCtx: %v", err)
		}
		if got != "blespam -t google" {
			t.Errorf("BLESpamCtx wire = %q", got)
		}
	})

	t.Run("SniffBT_valid", func(t *testing.T) {
		got, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.SniffBT("airtag", 100*time.Millisecond)
		})
		if err != nil {
			t.Fatalf("SniffBT(airtag): %v", err)
		}
		if got != "sniffbt -t airtag" {
			t.Errorf("SniffBT wire = %q, want sniffbt -t airtag", got)
		}
	})
	t.Run("SniffBT_invalid_target", func(t *testing.T) {
		_, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.SniffBT("nonsense", 100*time.Millisecond)
		})
		if err == nil {
			t.Error("SniffBT(nonsense) should error on invalid target")
		}
	})
	t.Run("SniffBTCtx_valid", func(t *testing.T) {
		got, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.SniffBTCtx(context.Background(), "flipper", 100*time.Millisecond)
		})
		if err != nil {
			t.Fatalf("SniffBTCtx: %v", err)
		}
		if got != "sniffbt -t flipper" {
			t.Errorf("SniffBTCtx wire = %q", got)
		}
	})

	t.Run("PortScanService_valid", func(t *testing.T) {
		got, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.PortScanService(2, "http", 100*time.Millisecond)
		})
		if err != nil {
			t.Fatalf("PortScanService(2, http): %v", err)
		}
		if got != "portscan -s http -t 2" {
			t.Errorf("PortScanService wire = %q", got)
		}
	})
	t.Run("PortScanService_invalid", func(t *testing.T) {
		_, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.PortScanService(0, "nonsense-svc", 100*time.Millisecond)
		})
		if err == nil {
			t.Error("PortScanService(nonsense-svc) should error")
		}
	})
	t.Run("PortScanServiceCtx_valid", func(t *testing.T) {
		got, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.PortScanServiceCtx(context.Background(), 5, "ssh", 100*time.Millisecond)
		})
		if err != nil {
			t.Fatalf("PortScanServiceCtx: %v", err)
		}
		if got != "portscan -s ssh -t 5" {
			t.Errorf("PortScanServiceCtx wire = %q", got)
		}
	})

	t.Run("SetSetting_valid", func(t *testing.T) {
		got, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.SetSetting("EnableLED", "enable")
		})
		if err != nil {
			t.Fatalf("SetSetting: %v", err)
		}
		if got != "settings -s EnableLED enable" {
			t.Errorf("SetSetting wire = %q", got)
		}
	})
	t.Run("SetSetting_invalid_name", func(t *testing.T) {
		_, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.SetSetting("UnknownSetting", "enable")
		})
		if err == nil {
			t.Error("SetSetting with invalid name should error")
		}
	})
	t.Run("SetSetting_invalid_value", func(t *testing.T) {
		_, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.SetSetting("EnableLED", "maybe") // must be enable/disable
		})
		if err == nil {
			t.Error("SetSetting with non-enable/disable value should error")
		}
	})

	t.Run("EvilPortalSetHTML_filename", func(t *testing.T) {
		got, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.EvilPortalSetHTML("starbucks.html")
		})
		if err != nil {
			t.Fatalf("EvilPortalSetHTML: %v", err)
		}
		if got != `evilportal -c sethtml "starbucks.html"` {
			t.Errorf("EvilPortalSetHTML wire = %q", got)
		}
	})
}

// TestScanStation_StubbedError pins the ScanStation back-compat
// shim — the underlying `scansta` command was removed in
// Marauder v1.11.1 with no replacement, so the wrapper returns a
// clear "use ScanAll instead" error instead of silently timing
// out on a no-op.
func TestScanStation_StubbedError(t *testing.T) {
	fp := newFakePort()
	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })

	_, err := m.ScanStation(100 * time.Millisecond)
	if err == nil {
		t.Fatal("ScanStation should return the v1.11.1+ removal error")
	}
	if !strings.Contains(err.Error(), "ScanAll") {
		t.Errorf("ScanStation error = %q, want pointer to ScanAll", err)
	}
}

// TestScanAPParsed_Roundtrip pins the parsed wrapper: calls
// ScanAPParsed, the fake serves a single-AP scanap response, and
// the parsed ScanResult.APs slice contains the AP. Catches a
// regression in the Exec → ParseAPList wiring (the legacy blocking
// entry point that v0.60+ ctx-threading still delegates through).
func TestScanAPParsed_Roundtrip(t *testing.T) {
	fp := newFakePort()
	fp.respond("scanap", "0 SSID=HomeWifi BSSID=AA:BB:CC:DD:EE:FF CH=6 ENC=WPA2 RSSI=-55")
	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })

	res, err := m.ScanAPParsed(500 * time.Millisecond)
	if err != nil {
		t.Fatalf("ScanAPParsed: %v", err)
	}
	if res.Count != 1 || len(res.APs) != 1 {
		t.Fatalf("ScanAPParsed: APs=%d Count=%d, want 1/1 (%#v)", len(res.APs), res.Count, res)
	}
	if res.APs[0].SSID != "HomeWifi" {
		t.Errorf("APs[0].SSID = %q, want HomeWifi", res.APs[0].SSID)
	}
	if !strings.EqualFold(res.APs[0].BSSID, "AA:BB:CC:DD:EE:FF") {
		t.Errorf("APs[0].BSSID = %q, want AA:BB:CC:DD:EE:FF", res.APs[0].BSSID)
	}
	if res.APs[0].Channel != 6 {
		t.Errorf("APs[0].Channel = %d, want 6", res.APs[0].Channel)
	}
	if res.APs[0].RSSI != -55 {
		t.Errorf("APs[0].RSSI = %d, want -55", res.APs[0].RSSI)
	}

	// Ctx variant should produce the same parsed shape.
	fp2 := newFakePort()
	fp2.respond("scanap", "0 SSID=HomeWifi BSSID=AA:BB:CC:DD:EE:FF CH=6 ENC=WPA2 RSSI=-55")
	m2 := newMarauderWithPort(fp2)
	t.Cleanup(func() { _ = m2.Close() })
	resCtx, err := m2.ScanAPParsedCtx(context.Background(), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("ScanAPParsedCtx: %v", err)
	}
	if len(resCtx.APs) != 1 || resCtx.APs[0].SSID != "HomeWifi" {
		t.Errorf("ScanAPParsedCtx APs = %+v, want HomeWifi", resCtx.APs)
	}
}

// TestListAPsParsedAndListStationsParsed pins the two list-parsed
// helpers via the standard Exec → parser pipeline.
func TestListAPsParsedAndListStationsParsed(t *testing.T) {
	t.Run("APs", func(t *testing.T) {
		fp := newFakePort()
		fp.respond("list -a", "0 SSID=HomeWifi BSSID=AA:BB:CC:DD:EE:FF CH=6 ENC=WPA2 RSSI=-55")
		m := newMarauderWithPort(fp)
		t.Cleanup(func() { _ = m.Close() })
		res, err := m.ListAPsParsed()
		if err != nil {
			t.Fatalf("ListAPsParsed: %v", err)
		}
		if len(res.APs) != 1 || res.APs[0].SSID != "HomeWifi" {
			t.Errorf("ListAPsParsed APs = %+v, want HomeWifi", res.APs)
		}
	})
	t.Run("Stations", func(t *testing.T) {
		fp := newFakePort()
		fp.respond("list -c", "0 MAC=11:22:33:44:55:66 vendor=Apple")
		m := newMarauderWithPort(fp)
		t.Cleanup(func() { _ = m.Close() })
		res, err := m.ListStationsParsed()
		if err != nil {
			t.Fatalf("ListStationsParsed: %v", err)
		}
		if len(res.Stations) != 1 {
			t.Fatalf("ListStationsParsed: %d stations, want 1 (%#v)", len(res.Stations), res)
		}
		if !strings.EqualFold(res.Stations[0].MAC, "11:22:33:44:55:66") {
			t.Errorf("Stations[0].MAC = %q, want 11:22:33:44:55:66", res.Stations[0].MAC)
		}
	})
}
