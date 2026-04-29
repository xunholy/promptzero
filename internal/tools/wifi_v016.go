package tools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xunholy/promptzero/internal/risk"
)

// v0.16 Marauder additions — close audit gaps from
// ~/ObsidianVault/agent/integration-coverage-and-skills.md §2 and §3.
// All wire commands live on the Marauder client in commands_v016.go.

//nolint:gochecknoinits
func init() {
	// --- Tune-ups: companion methods for existing Specs ---

	Register(Spec{
		Name:        "wifi_clone_sta_mac",
		Description: "Clone a discovered station's MAC address for spoofing. Companion to wifi_clone_mac (which clones APs).",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"station_index":{"type":"integer","description":"Index of the station whose MAC to clone (from wifi_list_stations)"}}}`),
		Required:  []string{"station_index"},
		Risk:      risk.Medium,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.CloneStaMAC(intOr(p, "station_index", 0))
		},
	})

	Register(Spec{
		Name:        "wifi_info_ap",
		Description: "Get detailed info on a specific access point from the most-recent scan, by index. Returns BSSID, channel, encryption, RSSI history.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"ap_index":{"type":"integer","description":"AP index (from wifi_list_aps)"}}}`),
		Required:  []string{"ap_index"},
		Risk:      risk.Low,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.InfoAP(intOr(p, "ap_index", 0))
		},
	})

	// --- Passive sniffers (medium risk) ---

	Register(Spec{
		Name:        "wifi_mactrack",
		Description: "Track MAC addresses across channels — useful for detecting follower/probing devices in physical pentests. Passive, no transmit.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 60)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.MacTrack(time.Duration(intOr(p, "duration_seconds", 60)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_sigmon",
		Description: "RSSI signal-strength monitor for selected APs. Useful for direction-finding or rough triangulation. Passive.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 60)"}}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.Sigmon(time.Duration(intOr(p, "duration_seconds", 60)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_sniff_pinescan",
		Description: "Detect Pineapple-style deauth attacks in the area. Passive monitoring for known Hak5 fingerprints.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 60)"}}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SniffPineScan(time.Duration(intOr(p, "duration_seconds", 60)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_sniff_multissid",
		Description: "Detect rogue APs broadcasting multiple SSIDs from a single radio. Passive.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 60)"}}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SniffMultiSSID(time.Duration(intOr(p, "duration_seconds", 60)) * time.Second)
		},
	})

	// --- Wardrive (GPS-tagged AP capture) ---

	Register(Spec{
		Name:        "wifi_wardrive_start",
		Description: "Start a wardrive capture — logs APs to a Wigle-format CSV with GPS coordinates as the operator moves through space. Requires a GPS fix.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Capture duration in seconds (default 600 = 10 min)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.WardriveStart(time.Duration(intOr(p, "duration_seconds", 600)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_wardrive_stop",
		Description: "Stop the active wardrive capture and close the CSV.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.WardriveStop()
		},
	})

	Register(Spec{
		Name:        "wifi_wardrive_poi",
		Description: "Mark a point-of-interest in the active wardrive log with a label.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"label":{"type":"string","description":"Label for this POI (free text, no embedded quotes)"}}}`),
		Required:  []string{"label"},
		Risk:      risk.Low,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.WardrivePOI(str(p, "label"))
		},
	})

	// --- GPS tracker / POI session ---

	Register(Spec{
		Name:        "gps_tracker_start",
		Description: "Start a GPS tracker session — accumulates a track log to the SD card.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Tracking duration in seconds (default 600)"}}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.GpsTrackerStart(time.Duration(intOr(p, "duration_seconds", 600)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "gps_tracker_stop",
		Description: "Stop the active GPS tracker session and close the log.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.GpsTrackerStop()
		},
	})

	Register(Spec{
		Name:        "gps_poi",
		Description: "Manage GPS points-of-interest within a tracker session. action='start' opens a POI session, action='mark' adds a labelled point, action='end' closes the session.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"action":{"type":"string","enum":["start","mark","end"],"description":"POI session action"},` +
			`"label":{"type":"string","description":"Label for the POI (only used with action='mark'; ignored for start/end)"}}}`),
		Required:  []string{"action"},
		Risk:      risk.Low,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.GpsPoi(str(p, "action"), str(p, "label"))
		},
	})

	// --- List manipulation: manual injection ---

	Register(Spec{
		Name:        "wifi_add_ap",
		Description: "Inject a manually-specified AP into the Marauder's working list. Useful when targets are known in advance (e.g. from prior recon) and don't need to be re-scanned.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"bssid":{"type":"string","description":"BSSID of the AP, e.g. AA:BB:CC:DD:EE:FF"},` +
			`"channel":{"type":"string","description":"Channel number as a string, e.g. \"6\""},` +
			`"essid":{"type":"string","description":"ESSID/SSID of the network"}}}`),
		Required:  []string{"bssid", "channel", "essid"},
		Risk:      risk.Medium,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.AddAP(str(p, "bssid"), str(p, "channel"), str(p, "essid"))
		},
	})

	Register(Spec{
		Name:        "wifi_add_station",
		Description: "Inject a manually-specified client station into the Marauder's working list, associated with an AP index.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"bssid":{"type":"string","description":"Station MAC, e.g. AA:BB:CC:DD:EE:FF"},` +
			`"ap_index":{"type":"integer","description":"Index of the AP this station is associated with (from wifi_list_aps)"}}}`),
		Required:  []string{"bssid", "ap_index"},
		Risk:      risk.Medium,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.AddStation(str(p, "bssid"), intOr(p, "ap_index", 0))
		},
	})

	// --- BLE / AirTag spoofing (high risk: TX) ---

	Register(Spec{
		Name:        "wifi_bt_spoof_airtag",
		Description: "Spoof a discovered AirTag by index, broadcasting its identity from the Marauder. RF transmit; can affect Apple's FindMy network.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"airtag_index":{"type":"integer","description":"Index of the AirTag from wifi_sniff_bt -t airtag results"}}}`),
		Required:  []string{"airtag_index"},
		Risk:      risk.High,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.BTSpoofAirtag(intOr(p, "airtag_index", 0))
		},
	})

	// --- Karma (rogue AP exploitation) ---

	Register(Spec{
		Name:        "wifi_karma",
		Description: "Karma attack — respond to client probe requests as the requested SSID, luring them onto the Marauder. RF transmit; disruptive.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"probe_index":{"type":"integer","description":"Probe index (from sniffprobe / list -p) to respond to"}}}`),
		Required:  []string{"probe_index"},
		Risk:      risk.Critical,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.Karma(intOr(p, "probe_index", 0))
		},
	})

	// --- WPA3-era / disruptive attacks (critical risk) ---

	Register(Spec{
		Name:        "wifi_attack_quiet",
		Description: "Send 802.11 Quiet IE frames to silence nearby APs — disrupts WiFi for everyone in range. WPA3-era.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Attack duration (default 60)"}}}`),
		Required:    nil,
		Risk:        risk.Critical,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.AttackQuiet(time.Duration(intOr(p, "duration_seconds", 60)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_attack_badmsg",
		Description: "Send malformed 802.11 frames that crash some access points. Critical — disruptive and potentially destructive to bugged firmwares.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"targeted":{"type":"boolean","description":"If true, target only selected APs (-c flag); if false, broadcast to all in range"},` +
			`"duration_seconds":{"type":"number","description":"Attack duration (default 60)"}}}`),
		Required:  nil,
		Risk:      risk.Critical,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.AttackBadmsg(
				boolOr(p, "targeted", false),
				time.Duration(intOr(p, "duration_seconds", 60))*time.Second,
			)
		},
	})

	Register(Spec{
		Name:        "wifi_attack_sleep",
		Description: "Send 802.11 sleep-mode frames forcing clients into low-power state. Disrupts active connections.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"targeted":{"type":"boolean","description":"If true, target only selected APs (-c flag); else broadcast"},` +
			`"duration_seconds":{"type":"number","description":"Attack duration (default 60)"}}}`),
		Required:  nil,
		Risk:      risk.Critical,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.AttackSleep(
				boolOr(p, "targeted", false),
				time.Duration(intOr(p, "duration_seconds", 60))*time.Second,
			)
		},
	})

	// --- Evil Portal subverbs (companion to existing wifi_evil_portal_start/stop) ---

	Register(Spec{
		Name:        "wifi_evil_portal_set_html",
		Description: "Configure the evil portal to serve a named HTML file from the Marauder SD card. Pair with wifi_evil_portal_start to launch.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"name":{"type":"string","description":"HTML filename on Marauder SD (e.g. starbucks.html)"}}}`),
		Required:  []string{"name"},
		Risk:      risk.High,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.EvilPortalSetHTML(str(p, "name"))
		},
	})

	Register(Spec{
		Name:        "wifi_evil_portal_set_ap",
		Description: "Configure the evil portal to clone the AP at the given index as the rogue access point.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"ap_index":{"type":"integer","description":"AP index from wifi_list_aps"}}}`),
		Required:  []string{"ap_index"},
		Risk:      risk.High,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.EvilPortalSetAP(intOr(p, "ap_index", 0))
		},
	})

	Register(Spec{
		Name:        "wifi_evil_portal_reset",
		Description: "Reset the evil portal configuration to firmware defaults (clears HTML, AP, captured creds).",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.EvilPortalReset()
		},
	})

	Register(Spec{
		Name:        "wifi_evil_portal_ack",
		Description: "Acknowledge a pending captive-portal credential capture so the portal accepts the next connection. Drains queued credentials.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.EvilPortalAck()
		},
	})
}
