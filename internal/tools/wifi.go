package tools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/streaming"
)

//nolint:gochecknoinits
func init() {
	// --- WiFi Scanning ---

	Register(Spec{
		Name:        "wifi_scan_ap",
		Description: "Scan for nearby WiFi access points. Returns SSIDs, BSSIDs, channels, signal strength, and encryption type. Uses the ESP32 Marauder WiFi devboard.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Scan duration in seconds (default 15)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		// Streaming opt-in: each scanap line emitted by the Marauder
		// (typically one per detected AP) lands at the host's stream
		// callback as a frame in real time. First Marauder-backed
		// streaming tool — bridges the channel-based Marauder.Stream
		// API to the same StreamHandler shape used for Flipper
		// streaming tools via the new Marauder.StreamLines wrapper.
		Streams: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			// ScanAPParsedCtx threads ctx all the way to the
			// Marauder read loop so a turn-level cancel (Ctrl+C)
			// aborts mid-scan instead of blocking until timeout.
			res, err := d.Marauder.ScanAPParsedCtx(ctx, time.Duration(intOr(p, "duration_seconds", 15))*time.Second)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(res)
			return string(b), nil
		},
		StreamHandler: func(ctx context.Context, d *Deps, p map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			timeout := time.Duration(intOr(p, "duration_seconds", 15)) * time.Second
			res, err := d.Marauder.ScanAPParsedStream(ctx, timeout, func(line string) (stop bool) {
				sink.Send([]byte(line))
				return sink.IsAborted()
			})
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(res)
			return string(b), nil
		},
	})

	Register(Spec{
		Name:        "wifi_scan_all",
		Description: "Scan for both WiFi access points and client stations simultaneously.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Scan duration in seconds (default 15)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		// Streaming opt-in: each scanall line lands at the host's
		// stream callback as a frame in real time. Same Marauder
		// streaming path as wifi_scan_ap, just without the
		// AP-list parse layer — scanall's mixed AP+station output
		// is returned as raw text on both blocking and streaming
		// paths.
		Streams: true,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.ScanAll(time.Duration(intOr(p, "duration_seconds", 15)) * time.Second)
		},
		StreamHandler: func(ctx context.Context, d *Deps, p map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			timeout := time.Duration(intOr(p, "duration_seconds", 15)) * time.Second
			return d.Marauder.StreamLines(ctx, "scanall", timeout, func(line string) (stop bool) {
				sink.Send([]byte(line))
				return sink.IsAborted()
			})
		},
	})

	Register(Spec{
		Name:        "wifi_stop_scan",
		Description: "Stop any running WiFi scan or attack.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.StopScan()
		},
	})

	// --- Target Selection ---

	Register(Spec{
		Name:        "wifi_select_ap",
		Description: "Select specific access points by index number (from scan results) as attack targets. Use 'all' to select everything.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"indices":{"type":"string","description":"Comma-separated AP indices e.g. '0,1,3', or 'all'"}}}`),
		Required:    []string{"indices"},
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SelectAP(str(p, "indices"))
		},
	})

	Register(Spec{
		Name:        "wifi_select_station",
		Description: "Select specific stations by index as targets. Use 'all' to select everything.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"indices":{"type":"string","description":"Comma-separated station indices, or 'all'"}}}`),
		Required:    []string{"indices"},
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SelectStation(str(p, "indices"))
		},
	})

	Register(Spec{
		Name:        "wifi_select_ssid",
		Description: "Select specific SSIDs by index as targets. Use 'all' to select everything.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"indices":{"type":"string","description":"Comma-separated SSID indices, or 'all'"}}}`),
		Required:    []string{"indices"},
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SelectSSID(str(p, "indices"))
		},
	})

	// --- List ---

	Register(Spec{
		Name:        "wifi_list_aps",
		Description: "List all discovered access points from the most recent scan.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			res, err := d.Marauder.ListAPsParsed()
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(res)
			return string(b), nil
		},
	})

	Register(Spec{
		Name:        "wifi_list_ssids",
		Description: "List SSIDs configured for beacon spam attacks.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.ListSSIDs()
		},
	})

	Register(Spec{
		Name:        "wifi_list_stations",
		Description: "List all discovered client stations from the most recent scan.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			res, err := d.Marauder.ListStationsParsed()
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(res)
			return string(b), nil
		},
	})

	// --- Clear ---

	Register(Spec{
		Name:        "wifi_clear_aps",
		Description: "Clear the list of discovered access points.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.ClearAPs()
		},
	})

	Register(Spec{
		Name:        "wifi_clear_ssids",
		Description: "Clear the SSID list used for beacon spam.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.ClearSSIDs()
		},
	})

	Register(Spec{
		Name:        "wifi_clear_stations",
		Description: "Clear the list of discovered client stations.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.ClearStations()
		},
	})

	// --- Attacks ---

	Register(Spec{
		Name:        "wifi_deauth",
		Description: "Launch a deauthentication attack against selected targets. Disconnects clients from their access points. Select targets first with wifi_select_* tools. AUTHORIZED LAB/PENTEST USE ONLY.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Attack duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Critical,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.DeauthAttack(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_deauth_station_list",
		Description: "Launch a deauthentication attack on the currently-selected station list. Populate the list with wifi_scan_all + wifi_select_station first; otherwise the attack finds no targets.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Attack duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Critical,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.DeauthToStationList(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_beacon_spam",
		Description: "Broadcast fake WiFi network names (beacon frames) from the current SSID list. Floods the area with phantom SSIDs.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Spam duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.BeaconSpamList(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_beacon_random",
		Description: "Broadcast beacon frames with randomly generated SSIDs.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.BeaconSpamRandom(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_beacon_clone",
		Description: "Clone SSIDs from nearby access points and spam them as beacon frames.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.BeaconSpamClone(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_beacon_rickroll",
		Description: "Broadcast WiFi beacons that spell out Rick Astley lyrics as SSIDs.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.BeaconSpamRickroll(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_beacon_funny",
		Description: "Broadcast beacon frames using a built-in set of funny SSIDs.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.BeaconSpamFunny(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_probe_flood",
		Description: "Flood the area with probe request frames using random MACs and SSIDs.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.ProbeFlood(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_csa_attack",
		Description: "Send Channel Switch Announcement frames to selected APs, forcing clients to switch channels.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Critical,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.CSAAttack(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_sae_flood",
		Description: "Flood selected APs with SAE (WPA3) authentication frames.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Critical,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SAEFlood(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
	})

	// --- Sniffing / Capture ---

	Register(Spec{
		Name:        "wifi_sniff_pmkid",
		Description: "Capture PMKID hashes from WPA2 access points (offline crack candidates). Passive — no deauth needed. Pair with wifi_deauth to coerce reconnects and improve yield.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"channel":{"type":"number","description":"Specific WiFi channel (0 = all channels, default 0)"},` +
			`"deauth":{"type":"boolean","description":"Trigger deauth frames to coerce handshakes"},` +
			`"list_only":{"type":"boolean","description":"Limit capture to the currently-loaded AP list"},` +
			`"duration_seconds":{"type":"number","description":"Capture duration in seconds (default 60)"}}}`),
		Required:  nil,
		Risk:      risk.High,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SniffPMKID(
				intOr(p, "channel", 0),
				boolOr(p, "deauth", false),
				boolOr(p, "list_only", false),
				time.Duration(intOr(p, "duration_seconds", 60))*time.Second,
			)
		},
	})

	Register(Spec{
		Name:        "wifi_sniff_beacon",
		Description: "Capture and log beacon frames from nearby access points.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		// Streaming opt-in: each captured beacon frame lands at the
		// host's stream callback in real time. Same Marauder.StreamLines
		// path as wifi_scan_ap / wifi_scan_all.
		Streams: true,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SniffBeacon(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
		StreamHandler: func(ctx context.Context, d *Deps, p map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			timeout := time.Duration(intOr(p, "duration_seconds", 30)) * time.Second
			return d.Marauder.StreamLines(ctx, "sniffbeacon", timeout, func(line string) (stop bool) {
				sink.Send([]byte(line))
				return sink.IsAborted()
			})
		},
	})

	Register(Spec{
		Name:        "wifi_sniff_deauth",
		Description: "Monitor for deauthentication frames in the area. Detects active attacks.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		// Streaming opt-in: each detected deauth frame surfaces in
		// real time so the operator can see active attacks land
		// without waiting for the full duration.
		Streams: true,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SniffDeauth(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
		StreamHandler: func(ctx context.Context, d *Deps, p map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			timeout := time.Duration(intOr(p, "duration_seconds", 30)) * time.Second
			return d.Marauder.StreamLines(ctx, "sniffdeauth", timeout, func(line string) (stop bool) {
				sink.Send([]byte(line))
				return sink.IsAborted()
			})
		},
	})

	Register(Spec{
		Name:        "wifi_sniff_probe",
		Description: "Capture probe requests from nearby devices. Reveals what networks devices are looking for.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		// Streaming opt-in: each probe-request frame lands at the
		// host's stream callback as it arrives — useful for
		// real-time visibility into what nearby devices are
		// looking for.
		Streams: true,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SniffProbe(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
		StreamHandler: func(ctx context.Context, d *Deps, p map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			timeout := time.Duration(intOr(p, "duration_seconds", 30)) * time.Second
			return d.Marauder.StreamLines(ctx, "sniffprobe", timeout, func(line string) (stop bool) {
				sink.Send([]byte(line))
				return sink.IsAborted()
			})
		},
	})

	Register(Spec{
		Name:        "wifi_sniff_pwnagotchi",
		Description: "Detect and capture pwnagotchi handshake advertisements nearby.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SniffPwnagotchi(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_sniff_raw",
		Description: "Capture all raw WiFi packets on the current channel. Also the tool of record for WPA3/SAE material: wifi_set_channel → wifi_deauth → wifi_sniff_raw captures the SAE Commit/Confirm. PCAP lands on the Marauder SD card.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SniffRaw(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_sniff_sae",
		Description: "Alias for wifi_sniff_raw scoped to a WPA3/SAE target. Select the AP with wifi_select_ap, then call this — it runs sniff_raw with a 60s default and documents the deauth→reconnect recipe in the tool result.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 60)"}}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			// SAE capture is raw sniff with a 60s default — the Commit /
			// Confirm exchange tends to be sparse, so the extra dwell
			// noticeably improves yield.
			out, err := d.Marauder.SniffRaw(time.Duration(intOr(p, "duration_seconds", 60)) * time.Second)
			if err != nil {
				return out, err
			}
			return "sae capture via raw sniff:\n" + out + "\n\nExtract SAE Commit/Confirm frames from the resulting PCAP on the Marauder SD card. Pair with a fresh wifi_deauth if no material was captured.", nil
		},
	})

	// --- BLE / Bluetooth ---

	Register(Spec{
		Name:        "wifi_ble_spam",
		Description: "BLE advertisement spam via the ESP32 Marauder devboard. Floods nearby Bluetooth devices with phantom advertisements. Valid modes: apple, google, samsung, windows, flipper, all.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"mode":{"type":"string","description":"BLE spam mode: apple, google, samsung, windows, flipper, all"},` +
			`"duration_seconds":{"type":"number","description":"Spam duration in seconds (default 30)"}}}`),
		Required:  []string{"mode"},
		Risk:      risk.High,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.BLESpam(str(p, "mode"), time.Duration(intOr(p, "duration_seconds", 30))*time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_sniff_bt",
		Description: "Sniff for specific Bluetooth device advertisements. Valid target types: airtag, flipper, flock, meta.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"target_type":{"type":"string","description":"Target device type: airtag, flipper, flock, meta"},` +
			`"duration_seconds":{"type":"number","description":"Duration in seconds (default 30)"}}}`),
		Required:  []string{"target_type"},
		Risk:      risk.Medium,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SniffBT(str(p, "target_type"), time.Duration(intOr(p, "duration_seconds", 30))*time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_sniff_skimmer",
		Description: "Sniff for Bluetooth credit card skimmers nearby.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SniffSkimmer(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
	})

	// --- Evil Portal ---

	Register(Spec{
		Name: "wifi_evil_portal_start",
		Description: "Start an evil captive portal. Creates a fake WiFi hotspot that serves a phishing page to capture credentials. Optionally specify an HTML filename on the SD card.\n\nExamples:\n" +
			`- {}  — serve the Marauder default evil-portal page (auto-detected)` + "\n" +
			`- {"filename":"starbucks.html"}  — serve a generated portal deployed via generate_evil_portal`,
		Schema:    json.RawMessage(`{"type":"object","properties":{"filename":{"type":"string","description":"HTML filename on SD card to serve (empty for default page)"}}}`),
		Required:  nil,
		Risk:      risk.High,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.EvilPortalStart(str(p, "filename"))
		},
	})

	Register(Spec{
		Name:        "wifi_evil_portal_stop",
		Description: "Stop the evil portal.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		// Stop verb only — terminates the active TX. Treated as low risk
		// (de-escalation), in contrast to wifi_evil_portal_start which is
		// rightly High.
		Risk:      risk.Low,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		// wifi_evil_portal_stop maps to StopScan — there is no dedicated
		// stop verb on Marauder firmware (§A.1 of the migration runbook).
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.StopScan()
		},
	})

	// --- SSID Management ---

	Register(Spec{
		Name:        "wifi_add_ssid",
		Description: "Add an SSID to the beacon spam list.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"name":{"type":"string","description":"SSID name to add"}}}`),
		Required:    []string{"name"},
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.AddSSID(str(p, "name"))
		},
	})

	Register(Spec{
		Name:        "wifi_remove_ssid",
		Description: "Remove an SSID from the beacon spam list by index.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"index":{"type":"integer","description":"Index of the SSID to remove (from wifi_list_ssids)"}}}`),
		Required:    []string{"index"},
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.RemoveSSID(intOr(p, "index", 0))
		},
	})

	Register(Spec{
		Name:        "wifi_generate_ssids",
		Description: "Generate random SSIDs and add them to the beacon spam list.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"count":{"type":"integer","description":"Number of SSIDs to generate (default 10)"}}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.GenerateSSIDs(intOr(p, "count", 10))
		},
	})

	// --- Network Recon (requires joining a network) ---

	Register(Spec{
		Name:        "wifi_join",
		Description: "Join a WiFi access point by index with the provided password.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"ap_index":{"type":"integer","description":"Index of the AP to join (from wifi_list_aps)"},` +
			`"password":{"type":"string","description":"WiFi password (empty for open networks)"}}}`),
		Required:  []string{"ap_index"},
		Risk:      risk.High,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.Join(intOr(p, "ap_index", 0), str(p, "password"))
		},
	})

	Register(Spec{
		Name:        "wifi_ping_scan",
		Description: "Perform an ICMP ping sweep of the joined network to discover live hosts.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Scan duration in seconds (default 30)"}}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.PingScan(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_arp_scan",
		Description: "Perform an ARP scan of the joined network to discover live hosts and MACs.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"Scan duration in seconds (default 15)"}}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.ARPScan(time.Duration(intOr(p, "duration_seconds", 15)) * time.Second)
		},
	})

	Register(Spec{
		Name:        "wifi_port_scan",
		Description: "Perform a full-port scan against a discovered host by IP index. Requires a prior wifi_join and ping/arp scan.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"ip_index":{"type":"integer","description":"Index of the target IP (from ping/arp scan results)"},` +
			`"duration_seconds":{"type":"number","description":"Scan duration in seconds (default 30)"}}}`),
		Required:  []string{"ip_index"},
		Risk:      risk.High,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.PortScan(intOr(p, "ip_index", 0), time.Duration(intOr(p, "duration_seconds", 30))*time.Second)
		},
	})

	// --- MAC Manipulation ---

	Register(Spec{
		Name:        "wifi_random_mac",
		Description: "Randomise the ESP32 MAC address. Pass target='ap' (default) to randomise the AP-mode MAC, or target='sta' to randomise the station-mode MAC.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"target":{"type":"string","enum":["ap","sta"],"description":"Which MAC to randomise — 'ap' (default) or 'sta'"}}}`),
		Required:  nil,
		Risk:      risk.Medium,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			switch str(p, "target") {
			case "sta":
				return d.Marauder.RandomStaMAC()
			default: // "" or "ap"
				return d.Marauder.RandomAPMAC()
			}
		},
	})

	Register(Spec{
		Name:        "wifi_clone_mac",
		Description: "Clone the MAC address of a discovered AP by index.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"ap_index":{"type":"integer","description":"Index of the AP whose MAC to clone (from wifi_list_aps)"}}}`),
		Required:    []string{"ap_index"},
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.CloneAPMAC(intOr(p, "ap_index", 0))
		},
	})

	// --- Save / Load ---

	Register(Spec{
		Name:        "wifi_save_aps",
		Description: "Save the current list of discovered APs to the SD card.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SaveAPs()
		},
	})

	Register(Spec{
		Name:        "wifi_save_ssids",
		Description: "Save the current SSID list to the SD card.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SaveSSIDs()
		},
	})

	Register(Spec{
		Name:        "wifi_load_aps",
		Description: "Load a previously saved AP list from the SD card.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.LoadAPs()
		},
	})

	Register(Spec{
		Name:        "wifi_load_ssids",
		Description: "Load a previously saved SSID list from the SD card.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.LoadSSIDs()
		},
	})

	// --- Settings ---

	Register(Spec{
		Name:        "wifi_settings",
		Description: "Get all current ESP32 Marauder device settings.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.Settings()
		},
	})

	Register(Spec{
		Name:        "wifi_set_setting",
		Description: "Update a single ESP32 Marauder device setting by name and value.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"name":{"type":"string","description":"Setting name (ForcePMKID|ForceProbe|SavePCAP|SaveLog|SavePMKID|EnableLED|RandomBLEMac|EnableWeb|SDCard|WebAuth)"},` +
			`"value":{"type":"string","description":"New value: enable or disable"}}}`),
		Required:  []string{"name", "value"},
		Risk:      risk.Medium,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SetSetting(str(p, "name"), str(p, "value"))
		},
	})

	Register(Spec{
		Name:        "wifi_set_channel",
		Description: "Set the active WiFi channel (1–14).",
		Schema:      json.RawMessage(`{"type":"object","properties":{"channel":{"type":"integer","description":"WiFi channel number 1–14"}}}`),
		Required:    []string{"channel"},
		Risk:        risk.Medium,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.SetChannel(intOr(p, "channel", 1))
		},
	})

	// --- System ---

	Register(Spec{
		Name:        "wifi_info",
		Description: "Get ESP32 Marauder WiFi devboard info: firmware version, MAC, status.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.Info()
		},
	})

	Register(Spec{
		Name:        "wifi_reboot",
		Description: "Reboot the WiFi devboard.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Critical,
		Group:       GroupMarauderWiFi,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.Reboot()
		},
	})

	// --- Named-service portscan (requires Join) ---
	// MCP-only in prior architecture; unified here so the agent can
	// also issue named-service scans (coverage drift fix per §A.4).

	Register(Spec{
		Name:        "wifi_portscan_service",
		Description: "Scan the host at the given IP index for a named service (ssh, http, ...). Requires a prior wifi_join. Valid services: ssh, http, https, ftp, smb, rdp, dns, smtp, pop3, imap, mysql, psql, mssql, redis, vnc.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"ip_index":{"type":"integer","description":"IP list index from ping/arp scan"},` +
			`"service":{"type":"string","description":"Service token: ssh|http|https|ftp|smb|rdp|dns|smtp|pop3|imap|mysql|psql|mssql|redis|vnc"},` +
			`"duration_seconds":{"type":"number","description":"Scan duration in seconds (default 30)"}}}`),
		Required:  []string{"ip_index", "service"},
		Risk:      risk.High,
		Group:     GroupMarauderWiFi,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireMarauder(); err != nil {
				return "", err
			}
			return d.Marauder.PortScanService(
				intOr(p, "ip_index", 0),
				str(p, "service"),
				time.Duration(intOr(p, "duration_seconds", 30))*time.Second,
			)
		},
	})
}
