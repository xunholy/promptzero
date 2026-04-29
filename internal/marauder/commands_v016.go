package marauder

import (
	"fmt"
	"time"

	"github.com/xunholy/promptzero/internal/clisafe"
)

// commands_v016.go contains Marauder CLI wrappers added for the v0.16 feature
// set (audit gap list §2). The existing commands.go is intentionally untouched.

// --- MAC Manipulation ---

// CloneStaMAC clones the MAC address of the station at the given index.
// Wire: clonestamac -s <index>
func (m *Marauder) CloneStaMAC(index int) (string, error) {
	return m.Exec(fmt.Sprintf("clonestamac -s %d", index), 5*time.Second)
}

// --- System ---

// InfoAP returns firmware/device info for the AP at the given index.
// Wire: info -a <index>
func (m *Marauder) InfoAP(apIndex int) (string, error) {
	return m.Exec(fmt.Sprintf("info -a %d", apIndex), 5*time.Second)
}

// --- Passive Sniffers ---

// MacTrack passively tracks MAC addresses seen in the air for the given duration.
// Suggested timeout: 30 s.
// Wire: mactrack
func (m *Marauder) MacTrack(timeout time.Duration) (string, error) {
	return m.Exec("mactrack", timeout)
}

// Sigmon monitors WiFi signal levels for the given duration.
// Suggested timeout: 30 s.
// Wire: sigmon
func (m *Marauder) Sigmon(timeout time.Duration) (string, error) {
	return m.Exec("sigmon", timeout)
}

// SniffPineScan sniffs for WiFi Pineapple scan frames for the given duration.
// Suggested timeout: 30 s.
// Wire: sniffpinescan
func (m *Marauder) SniffPineScan(timeout time.Duration) (string, error) {
	return m.Exec("sniffpinescan", timeout)
}

// SniffMultiSSID sniffs for multi-SSID beacon frames for the given duration.
// Suggested timeout: 30 s.
// Wire: sniffmultissid
func (m *Marauder) SniffMultiSSID(timeout time.Duration) (string, error) {
	return m.Exec("sniffmultissid", timeout)
}

// --- Wardrive ---

// WardriveStart begins GPS-tagged AP logging to a Wigle CSV file.
// The session runs until the timeout elapses or WardriveStop is called.
// Wire: wardrive
func (m *Marauder) WardriveStart(timeout time.Duration) (string, error) {
	return m.Exec("wardrive", timeout)
}

// WardriveStop sends stopscan to end an active wardrive session.
// Wire: stopscan
func (m *Marauder) WardriveStop() (string, error) {
	return m.Exec("stopscan", 5*time.Second)
}

// WardrivePOI marks a named point of interest during an active wardrive session.
// The label is sanitised and double-quoted so embedded spaces are preserved.
// Wire: wardrivepoi "<label>"
func (m *Marauder) WardrivePOI(label string) (string, error) {
	return m.Exec(fmt.Sprintf(`wardrivepoi "%s"`, clisafe.SanitizeArg(label)), 5*time.Second)
}

// --- GPS Tracker ---

// GpsTrackerStart starts the GPS tracker, logging fixes for the given duration.
// Suggested timeout: 30 s.
// Wire: gpstracker
func (m *Marauder) GpsTrackerStart(timeout time.Duration) (string, error) {
	return m.Exec("gpstracker", timeout)
}

// GpsTrackerStop sends stopscan to end an active GPS tracker session.
// Wire: stopscan
func (m *Marauder) GpsTrackerStop() (string, error) {
	return m.Exec("stopscan", 5*time.Second)
}

// GpsPoi manages GPS points of interest. action must be one of:
//   - "start" → gpspoi -s        (begin a POI segment)
//   - "mark"  → gpspoi -m <label> (mark current position; label required)
//   - "end"   → gpspoi -e        (end the POI segment)
//
// For action "mark", label is sanitised and double-quoted to preserve spaces.
// Wire: gpspoi -<s|m <label>|e>
func (m *Marauder) GpsPoi(action, label string) (string, error) {
	switch action {
	case "start":
		return m.Exec("gpspoi -s", 5*time.Second)
	case "mark":
		return m.Exec(fmt.Sprintf(`gpspoi -m "%s"`, clisafe.SanitizeArg(label)), 5*time.Second)
	case "end":
		return m.Exec("gpspoi -e", 5*time.Second)
	default:
		return "", fmt.Errorf("invalid gpspoi action %q (want \"start\", \"mark\", or \"end\")", action)
	}
}

// --- List Manipulation ---

// AddAP adds an access point entry to the AP list.
// bssid is the hardware MAC (e.g. "aa:bb:cc:dd:ee:ff"), channel is the WiFi
// channel number as a string (e.g. "6"), and essid is the network name.
// All string arguments are sanitised; essid is double-quoted to preserve spaces.
// Wire: add -a -b <bssid> -c <channel> -s "<essid>"
func (m *Marauder) AddAP(bssid, channel, essid string) (string, error) {
	return m.Exec(fmt.Sprintf(`add -a -b %s -c %s -s "%s"`,
		clisafe.SanitizeArg(bssid),
		clisafe.SanitizeArg(channel),
		clisafe.SanitizeArg(essid),
	), 5*time.Second)
}

// AddStation adds a station entry to the station list.
// bssid is the station MAC address; apIndex is the index of the associated AP
// in the current AP list.
// Wire: add -c -m <bssid> -a <apIndex>
func (m *Marauder) AddStation(bssid string, apIndex int) (string, error) {
	return m.Exec(fmt.Sprintf("add -c -m %s -a %d", clisafe.SanitizeArg(bssid), apIndex), 5*time.Second)
}

// --- BLE Spoof ---

// BTSpoofAirtag spoofs AirTag BLE advertisements using the device at the
// given index in the current scan list.
// Wire: spoofat -t <index>
func (m *Marauder) BTSpoofAirtag(index int) (string, error) {
	return m.Exec(fmt.Sprintf("spoofat -t %d", index), 5*time.Second)
}

// --- WiFi Attacks ---

// Karma responds to probe requests from the station at the given probe-list
// index, acting as an open AP for any SSID the station is probing for.
// Runs for the given timeout duration.
// Wire: karma -p <probeIndex>
func (m *Marauder) Karma(probeIndex int) (string, error) {
	return m.Exec(fmt.Sprintf("karma -p %d", probeIndex), 60*time.Second)
}

// AttackQuiet sends quiet (low-noise) disassociation frames to selected targets
// for the given duration.
// Wire: attack -t quiet
func (m *Marauder) AttackQuiet(timeout time.Duration) (string, error) {
	return m.Exec("attack -t quiet", timeout)
}

// AttackBadmsg sends malformed management frames to selected targets for the
// given duration. When targeted is true, the -c flag limits the attack to the
// currently-selected station list (same semantics as DeauthToStationList).
// Wire: attack -t badmsg [-c]
func (m *Marauder) AttackBadmsg(targeted bool, timeout time.Duration) (string, error) {
	cmd := "attack -t badmsg"
	if targeted {
		cmd += " -c"
	}
	return m.Exec(cmd, timeout)
}

// AttackSleep sends power-save spoofed frames to selected targets for the
// given duration, causing victims to buffer and drop their traffic.
// When targeted is true, the -c flag limits the attack to the currently-selected
// station list (same semantics as DeauthToStationList).
// Wire: attack -t sleep [-c]
func (m *Marauder) AttackSleep(targeted bool, timeout time.Duration) (string, error) {
	cmd := "attack -t sleep"
	if targeted {
		cmd += " -c"
	}
	return m.Exec(cmd, timeout)
}

// --- Evil Portal (additional subverbs) ---
// EvilPortalSetHTML and EvilPortalSetHTMLStr already exist in commands.go.

// EvilPortalSetAP configures the evil portal to use the AP at the given index
// as the rogue access point.
// Wire: evilportal -c setap -i <index>
func (m *Marauder) EvilPortalSetAP(index int) (string, error) {
	return m.Exec(fmt.Sprintf("evilportal -c setap -i %d", index), 5*time.Second)
}

// EvilPortalReset resets the evil portal configuration to firmware defaults.
// Wire: evilportal -c reset
func (m *Marauder) EvilPortalReset() (string, error) {
	return m.Exec("evilportal -c reset", 5*time.Second)
}

// EvilPortalAck acknowledges a pending captive-portal credential capture,
// allowing the portal to accept the next connection.
// Wire: evilportal -c ack
func (m *Marauder) EvilPortalAck() (string, error) {
	return m.Exec("evilportal -c ack", 5*time.Second)
}
