package agent

import "github.com/anthropics/anthropic-sdk-go"

func buildMarauderTools() []anthropic.ToolUnionParam {
	return []anthropic.ToolUnionParam{
		// --- WiFi Scanning ---
		tool("wifi_scan_ap",
			"Scan for nearby WiFi access points. Returns SSIDs, BSSIDs, channels, signal strength, and encryption type. Uses the ESP32 Marauder WiFi devboard.",
			props(
				optProp("duration_seconds", "integer", "Scan duration (default 15)"),
			),
		),
		tool("wifi_scan_all",
			"Scan for both WiFi access points and client stations simultaneously.",
			props(
				optProp("duration_seconds", "integer", "Scan duration (default 15)"),
			),
		),
		tool("wifi_stop_scan",
			"Stop any running WiFi scan or attack.",
			props(),
		),

		// --- Target Selection ---
		tool("wifi_select_ap",
			"Select specific access points by index number (from scan results) as attack targets. Use 'all' to select everything.",
			props(
				reqProp("indices", "string", "Comma-separated AP indices e.g. '0,1,3', or 'all'"),
			),
			"indices",
		),
		tool("wifi_select_station",
			"Select specific stations by index as targets. Use 'all' to select everything.",
			props(
				reqProp("indices", "string", "Comma-separated station indices, or 'all'"),
			),
			"indices",
		),
		tool("wifi_select_ssid",
			"Select specific SSIDs by index as targets. Use 'all' to select everything.",
			props(
				reqProp("indices", "string", "Comma-separated SSID indices, or 'all'"),
			),
			"indices",
		),

		// --- List ---
		tool("wifi_list_aps",
			"List all discovered access points from the most recent scan.",
			props(),
		),
		tool("wifi_list_ssids",
			"List SSIDs configured for beacon spam attacks.",
			props(),
		),
		tool("wifi_list_stations",
			"List all discovered client stations from the most recent scan.",
			props(),
		),

		// --- Clear ---
		tool("wifi_clear_aps",
			"Clear the list of discovered access points.",
			props(),
		),
		tool("wifi_clear_ssids",
			"Clear the SSID list used for beacon spam.",
			props(),
		),
		tool("wifi_clear_stations",
			"Clear the list of discovered client stations.",
			props(),
		),

		// --- Attacks ---
		tool("wifi_deauth",
			"Launch a deauthentication attack against selected targets. Disconnects clients from their access points. Select targets first with wifi_select_* tools. No restrictions.",
			props(
				optProp("duration_seconds", "integer", "Attack duration (default 30)"),
			),
		),
		tool("wifi_deauth_station_list",
			"Launch a deauthentication attack on the currently-selected station list. Populate the list with wifi_scan_all + wifi_select_station first; otherwise the attack finds no targets.",
			props(
				optProp("duration_seconds", "integer", "Attack duration (default 30)"),
			),
		),
		tool("wifi_beacon_spam",
			"Broadcast fake WiFi network names (beacon frames) from the current SSID list. Floods the area with phantom SSIDs.",
			props(
				optProp("duration_seconds", "integer", "Spam duration (default 30)"),
			),
		),
		tool("wifi_beacon_random",
			"Broadcast beacon frames with randomly generated SSIDs.",
			props(
				optProp("duration_seconds", "integer", "Duration (default 30)"),
			),
		),
		tool("wifi_beacon_clone",
			"Clone SSIDs from nearby access points and spam them as beacon frames.",
			props(
				optProp("duration_seconds", "integer", "Duration (default 30)"),
			),
		),
		tool("wifi_beacon_rickroll",
			"Broadcast WiFi beacons that spell out Rick Astley lyrics as SSIDs.",
			props(
				optProp("duration_seconds", "integer", "Duration (default 30)"),
			),
		),
		tool("wifi_beacon_funny",
			"Broadcast beacon frames using a built-in set of funny SSIDs.",
			props(
				optProp("duration_seconds", "integer", "Duration (default 30)"),
			),
		),
		tool("wifi_probe_flood",
			"Flood the area with probe request frames using random MACs and SSIDs.",
			props(
				optProp("duration_seconds", "integer", "Duration (default 30)"),
			),
		),
		tool("wifi_csa_attack",
			"Send Channel Switch Announcement frames to selected APs, forcing clients to switch channels.",
			props(
				optProp("duration_seconds", "integer", "Duration (default 30)"),
			),
		),
		tool("wifi_sae_flood",
			"Flood selected APs with SAE (WPA3) authentication frames.",
			props(
				optProp("duration_seconds", "integer", "Duration (default 30)"),
			),
		),

		// --- Sniffing / Capture ---
		tool("wifi_sniff_pmkid",
			"Capture PMKID hashes from WPA2 access points. These can be used for offline cracking. Passive — no deauth needed.",
			props(
				optProp("flags", "string", "Optional flags, e.g. '-c 6' for channel or '-d' to also deauth"),
				optProp("duration_seconds", "integer", "Capture duration (default 60)"),
			),
		),
		tool("wifi_sniff_beacon",
			"Capture and log beacon frames from nearby access points.",
			props(
				optProp("duration_seconds", "integer", "Duration (default 30)"),
			),
		),
		tool("wifi_sniff_deauth",
			"Monitor for deauthentication frames in the area. Detects active attacks.",
			props(
				optProp("duration_seconds", "integer", "Duration (default 30)"),
			),
		),
		tool("wifi_sniff_probe",
			"Capture probe requests from nearby devices. Reveals what networks devices are looking for.",
			props(
				optProp("duration_seconds", "integer", "Duration (default 30)"),
			),
		),
		tool("wifi_sniff_pwnagotchi",
			"Detect and capture pwnagotchi handshake advertisements nearby.",
			props(
				optProp("duration_seconds", "integer", "Duration (default 30)"),
			),
		),
		tool("wifi_sniff_raw",
			"Capture all raw WiFi packets on the current channel.",
			props(
				optProp("duration_seconds", "integer", "Duration (default 30)"),
			),
		),

		// --- BLE / Bluetooth ---
		tool("wifi_ble_spam",
			"BLE advertisement spam via the ESP32 Marauder devboard. Floods nearby Bluetooth devices with phantom advertisements. Valid modes: apple, google, samsung, windows, flipper, all.",
			props(
				reqProp("mode", "string", "BLE spam mode: apple, google, samsung, windows, flipper, all"),
				optProp("duration_seconds", "integer", "How long to spam (default 30)"),
			),
			"mode",
		),
		tool("wifi_sniff_bt",
			"Sniff for specific Bluetooth device advertisements. Valid target types: airtag, flipper, flock, meta.",
			props(
				reqProp("target_type", "string", "Target device type: airtag, flipper, flock, meta"),
				optProp("duration_seconds", "integer", "Duration (default 30)"),
			),
			"target_type",
		),
		tool("wifi_sniff_skimmer",
			"Sniff for Bluetooth credit card skimmers nearby.",
			props(
				optProp("duration_seconds", "integer", "Duration (default 30)"),
			),
		),

		// --- Evil Portal ---
		toolEx("wifi_evil_portal_start",
			"Start an evil portal captive portal. Creates a fake WiFi hotspot that serves a phishing page to capture credentials. Optionally specify an HTML filename on the SD card.",
			props(
				optProp("filename", "string", "HTML filename on SD card to serve (empty for default page)"),
			),
			[]ToolExample{
				{Input: `{}`, Note: "serve the Marauder default evil-portal page (auto-detected)"},
				{Input: `{"filename":"starbucks.html"}`, Note: "serve a generated portal deployed via generate_evil_portal"},
			},
		),
		tool("wifi_evil_portal_stop",
			"Stop the evil portal.",
			props(),
		),

		// --- SSID Management ---
		tool("wifi_add_ssid",
			"Add an SSID to the beacon spam list.",
			props(
				reqProp("name", "string", "SSID name to add"),
			),
			"name",
		),
		tool("wifi_remove_ssid",
			"Remove an SSID from the beacon spam list by index.",
			props(
				reqProp("index", "integer", "Index of the SSID to remove (from wifi_list_ssids)"),
			),
			"index",
		),
		tool("wifi_generate_ssids",
			"Generate random SSIDs and add them to the beacon spam list.",
			props(
				optProp("count", "integer", "Number of SSIDs to generate (default 10)"),
			),
		),

		// --- Network Recon (requires joining a network) ---
		tool("wifi_join",
			"Join a WiFi access point by index with the provided password.",
			props(
				reqProp("ap_index", "integer", "Index of the AP to join (from wifi_list_aps)"),
				optProp("password", "string", "WiFi password (empty for open networks)"),
			),
			"ap_index",
		),
		tool("wifi_ping_scan",
			"Perform an ICMP ping sweep of the joined network to discover live hosts.",
			props(
				optProp("duration_seconds", "integer", "Scan duration (default 30)"),
			),
		),
		tool("wifi_arp_scan",
			"Perform an ARP scan of the joined network to discover live hosts and MACs.",
			props(
				optProp("duration_seconds", "integer", "Scan duration (default 15)"),
			),
		),
		tool("wifi_port_scan",
			"Perform a port scan against a discovered host by IP index.",
			props(
				reqProp("ip_index", "integer", "Index of the target IP (from ping/arp scan results)"),
				optProp("duration_seconds", "integer", "Scan duration (default 30)"),
			),
			"ip_index",
		),

		// --- MAC Manipulation ---
		tool("wifi_random_mac",
			"Randomise the ESP32 AP MAC address.",
			props(),
		),
		tool("wifi_clone_mac",
			"Clone the MAC address of a discovered AP by index.",
			props(
				reqProp("ap_index", "integer", "Index of the AP whose MAC to clone (from wifi_list_aps)"),
			),
			"ap_index",
		),

		// --- Save / Load ---
		tool("wifi_save_aps",
			"Save the current list of discovered APs to the SD card.",
			props(),
		),
		tool("wifi_save_ssids",
			"Save the current SSID list to the SD card.",
			props(),
		),
		tool("wifi_load_aps",
			"Load a previously saved AP list from the SD card.",
			props(),
		),
		tool("wifi_load_ssids",
			"Load a previously saved SSID list from the SD card.",
			props(),
		),

		// --- Settings ---
		tool("wifi_settings",
			"Get all current ESP32 Marauder device settings.",
			props(),
		),
		tool("wifi_set_setting",
			"Update a single ESP32 Marauder device setting by name and value.",
			props(
				reqProp("name", "string", "Setting name"),
				reqProp("value", "string", "New value for the setting"),
			),
			"name", "value",
		),
		tool("wifi_set_channel",
			"Set the active WiFi channel (1–14).",
			props(
				reqProp("channel", "integer", "WiFi channel number 1–14"),
			),
			"channel",
		),

		// --- System ---
		tool("wifi_info",
			"Get ESP32 Marauder WiFi devboard info: firmware version, MAC, status.",
			props(),
		),
		tool("wifi_reboot",
			"Reboot the WiFi devboard.",
			props(),
		),
	}
}
