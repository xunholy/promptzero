package marauder

import (
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
