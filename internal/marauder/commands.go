package marauder

import (
	"fmt"
	"time"
)

// --- WiFi Scanning ---

func (m *Marauder) ScanAP(timeout time.Duration) (string, error) {
	return m.Exec("scanap", timeout)
}

// ScanAll scans for both APs and stations simultaneously.
// (scansta is not available in Marauder v1.11.1; use scanall instead.)
func (m *Marauder) ScanAll(timeout time.Duration) (string, error) {
	return m.Exec("scanall", timeout)
}

func (m *Marauder) StopScan() (string, error) {
	return m.Exec("stopscan", 5*time.Second)
}

// --- Selection ---

// SelectAP selects APs by index list or "all".
func (m *Marauder) SelectAP(indices string) (string, error) {
	return m.Exec("select -a "+indices, 5*time.Second)
}

// SelectStation selects stations by index list or "all".
func (m *Marauder) SelectStation(indices string) (string, error) {
	return m.Exec("select -c "+indices, 5*time.Second)
}

// SelectSSID selects SSIDs by index list or "all".
func (m *Marauder) SelectSSID(indices string) (string, error) {
	return m.Exec("select -s "+indices, 5*time.Second)
}

// --- List ---

func (m *Marauder) ListAPs() (string, error) {
	return m.Exec("list -a", 5*time.Second)
}

func (m *Marauder) ListSSIDs() (string, error) {
	return m.Exec("list -s", 5*time.Second)
}

func (m *Marauder) ListStations() (string, error) {
	return m.Exec("list -c", 5*time.Second)
}

// --- Clear ---

func (m *Marauder) ClearAPs() (string, error) {
	return m.Exec("clearlist -a", 5*time.Second)
}

func (m *Marauder) ClearSSIDs() (string, error) {
	return m.Exec("clearlist -s", 5*time.Second)
}

func (m *Marauder) ClearStations() (string, error) {
	return m.Exec("clearlist -c", 5*time.Second)
}

// --- Attacks ---

// DeauthAttack sends deauth frames to all selected APs/stations.
func (m *Marauder) DeauthAttack(timeout time.Duration) (string, error) {
	return m.Exec("attack -t deauth", timeout)
}

// DeauthTargeted sends deauth frames to a specific channel.
func (m *Marauder) DeauthTargeted(channel int, timeout time.Duration) (string, error) {
	return m.Exec(fmt.Sprintf("attack -t deauth -c %d", channel), timeout)
}

// BeaconSpamList spams beacon frames from the current SSID list.
func (m *Marauder) BeaconSpamList(timeout time.Duration) (string, error) {
	return m.Exec("attack -t beacon -l", timeout)
}

// BeaconSpamRandom spams beacon frames with random SSIDs.
func (m *Marauder) BeaconSpamRandom(timeout time.Duration) (string, error) {
	return m.Exec("attack -t beacon -r", timeout)
}

// BeaconSpamClone clones nearby AP SSIDs and spams them as beacons.
func (m *Marauder) BeaconSpamClone(timeout time.Duration) (string, error) {
	return m.Exec("attack -t beacon -a", timeout)
}

// BeaconSpamRickroll spams Rick Astley-themed SSIDs as beacons.
func (m *Marauder) BeaconSpamRickroll(timeout time.Duration) (string, error) {
	return m.Exec("attack -t rickroll", timeout)
}

// BeaconSpamFunny spams a set of funny SSIDs as beacons.
func (m *Marauder) BeaconSpamFunny(timeout time.Duration) (string, error) {
	return m.Exec("attack -t funny", timeout)
}

// ProbeFlood floods the air with probe request frames.
func (m *Marauder) ProbeFlood(timeout time.Duration) (string, error) {
	return m.Exec("attack -t probe", timeout)
}

// CSAAttack sends Channel Switch Announcement frames to selected APs.
func (m *Marauder) CSAAttack(timeout time.Duration) (string, error) {
	return m.Exec("attack -t csa", timeout)
}

// SAEFlood floods selected APs with SAE (WPA3) authentication frames.
func (m *Marauder) SAEFlood(timeout time.Duration) (string, error) {
	return m.Exec("attack -t sae", timeout)
}

// --- Sniffing ---

// SniffPMKID captures PMKID handshakes. Optional channel (-c) and deauth flag (-d) may be passed via flags.
// Pass an empty string for flags to use defaults.
func (m *Marauder) SniffPMKID(flags string, timeout time.Duration) (string, error) {
	cmd := "sniffpmkid"
	if flags != "" {
		cmd += " " + flags
	}
	return m.Exec(cmd, timeout)
}

func (m *Marauder) SniffBeacon(timeout time.Duration) (string, error) {
	return m.Exec("sniffbeacon", timeout)
}

func (m *Marauder) SniffDeauth(timeout time.Duration) (string, error) {
	return m.Exec("sniffdeauth", timeout)
}

func (m *Marauder) SniffProbe(timeout time.Duration) (string, error) {
	return m.Exec("sniffprobe", timeout)
}

// SniffPwnagotchi sniffs for Pwnagotchi devices.
func (m *Marauder) SniffPwnagotchi(timeout time.Duration) (string, error) {
	return m.Exec("sniffpwn", timeout)
}

func (m *Marauder) SniffRaw(timeout time.Duration) (string, error) {
	return m.Exec("sniffraw", timeout)
}

// --- BLE Spam ---

// BLESpam sends BLE advertisement spam of the given type.
// Valid modes: apple, google, samsung, windows, flipper, all.
func (m *Marauder) BLESpam(mode string, timeout time.Duration) (string, error) {
	return m.Exec("blespam -t "+mode, timeout)
}

// --- Bluetooth Scanning ---

// SniffBT sniffs Bluetooth advertisements for specific device types.
// Valid targetType values: airtag, flipper, flock, meta.
func (m *Marauder) SniffBT(targetType string, timeout time.Duration) (string, error) {
	return m.Exec("sniffbt -t "+targetType, timeout)
}

// SniffSkimmer sniffs for Bluetooth credit card skimmers.
func (m *Marauder) SniffSkimmer(timeout time.Duration) (string, error) {
	return m.Exec("sniffskim", timeout)
}

// --- Evil Portal ---

// EvilPortalStart starts the evil portal captive portal.
// Pass an optional HTML filename, or empty string to use the default page.
func (m *Marauder) EvilPortalStart(filename string) (string, error) {
	cmd := "evilportal -c start"
	if filename != "" {
		cmd += " -w " + filename
	}
	return m.Exec(cmd, 10*time.Second)
}

// EvilPortalSetHTML sets the evil portal HTML page to the given filename on the SD card.
func (m *Marauder) EvilPortalSetHTML(filename string) (string, error) {
	return m.Exec("evilportal -c sethtml "+filename, 5*time.Second)
}

// EvilPortalSetHTMLStr tells Marauder to read the HTML page from serial input.
func (m *Marauder) EvilPortalSetHTMLStr() (string, error) {
	return m.Exec("evilportal -c sethtmlstr", 5*time.Second)
}

// EvilPortalStop stops the evil portal by issuing stopscan.
func (m *Marauder) EvilPortalStop() (string, error) {
	return m.Exec("stopscan", 5*time.Second)
}

// --- Channel ---

// SetChannel sets the WiFi channel (1–14).
func (m *Marauder) SetChannel(channel int) (string, error) {
	return m.Exec(fmt.Sprintf("channel -s %d", channel), 5*time.Second)
}

// GetChannel returns the current WiFi channel.
func (m *Marauder) GetChannel() (string, error) {
	return m.Exec("channel", 5*time.Second)
}

// --- SSID Management ---

// AddSSID adds a named SSID to the SSID list.
func (m *Marauder) AddSSID(name string) (string, error) {
	return m.Exec(fmt.Sprintf(`ssid -a -n "%s"`, name), 5*time.Second)
}

// GenerateSSIDs generates count random SSIDs and adds them to the list.
func (m *Marauder) GenerateSSIDs(count int) (string, error) {
	return m.Exec(fmt.Sprintf("ssid -a -g %d", count), 5*time.Second)
}

// RemoveSSID removes the SSID at the given index from the list.
func (m *Marauder) RemoveSSID(index int) (string, error) {
	return m.Exec(fmt.Sprintf("ssid -r %d", index), 5*time.Second)
}

// --- Network Recon (requires WiFi join) ---

// Join connects to the AP at the given index using the provided password.
func (m *Marauder) Join(apIndex int, password string) (string, error) {
	return m.Exec(fmt.Sprintf("join -a %d -p %s", apIndex, password), 15*time.Second)
}

// PingScan performs an ICMP ping sweep of the joined network.
func (m *Marauder) PingScan(timeout time.Duration) (string, error) {
	return m.Exec("pingscan", timeout)
}

// ARPScan performs an ARP scan of the joined network.
func (m *Marauder) ARPScan(timeout time.Duration) (string, error) {
	return m.Exec("arpscan", timeout)
}

// PortScan performs a port scan against the host at the given IP index.
func (m *Marauder) PortScan(ipIndex int, timeout time.Duration) (string, error) {
	return m.Exec(fmt.Sprintf("portscan -a -t %d", ipIndex), timeout)
}

// --- MAC Manipulation ---

// RandomAPMAC randomises the AP MAC address.
func (m *Marauder) RandomAPMAC() (string, error) {
	return m.Exec("randapmac", 5*time.Second)
}

// RandomStaMAC randomises the station MAC address.
func (m *Marauder) RandomStaMAC() (string, error) {
	return m.Exec("randstamac", 5*time.Second)
}

// CloneAPMAC clones the MAC address of the AP at the given index.
func (m *Marauder) CloneAPMAC(index int) (string, error) {
	return m.Exec(fmt.Sprintf("cloneapmac -a %d", index), 5*time.Second)
}

// --- Save / Load ---

func (m *Marauder) SaveAPs() (string, error) {
	return m.Exec("save -a", 5*time.Second)
}

func (m *Marauder) SaveSSIDs() (string, error) {
	return m.Exec("save -s", 5*time.Second)
}

func (m *Marauder) LoadAPs() (string, error) {
	return m.Exec("load -a", 5*time.Second)
}

func (m *Marauder) LoadSSIDs() (string, error) {
	return m.Exec("load -s", 5*time.Second)
}

// --- Settings ---

// Settings returns all current device settings.
func (m *Marauder) Settings() (string, error) {
	return m.Exec("settings", 5*time.Second)
}

// SetSetting updates a single device setting by name and value.
func (m *Marauder) SetSetting(name, value string) (string, error) {
	return m.Exec(fmt.Sprintf("settings -s %s %s", name, value), 5*time.Second)
}

// --- System ---

// Info returns device information (firmware version, chip info, etc.).
func (m *Marauder) Info() (string, error) {
	return m.Exec("info", 5*time.Second)
}

func (m *Marauder) Reboot() (string, error) {
	return m.Exec("reboot", 5*time.Second)
}

// Update triggers an OTA firmware update check.
func (m *Marauder) Update() (string, error) {
	return m.Exec("update -s", 30*time.Second)
}
