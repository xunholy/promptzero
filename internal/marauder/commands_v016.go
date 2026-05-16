package marauder

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/clisafe"
)

// commands_v016.go contains Marauder CLI wrappers added for the v0.16 feature
// set (audit gap list §2). The existing commands.go is intentionally untouched.

// validateBSSID accepts a 6-octet MAC in any case using common separators
// (colon, hyphen, period). The Marauder firmware parses these formats but
// silently no-ops on malformed input — reject up front so the LLM doesn't
// spend a turn waiting for nothing.
func validateBSSID(bssid string) error {
	if strings.TrimSpace(bssid) == "" {
		return fmt.Errorf("invalid BSSID: empty")
	}
	mac, err := net.ParseMAC(bssid)
	if err != nil {
		return fmt.Errorf("invalid BSSID %q (want MAC, e.g. AA:BB:CC:DD:EE:FF): %w", bssid, err)
	}
	if len(mac) != 6 {
		return fmt.Errorf("invalid BSSID %q (want 6 octets; got %d)", bssid, len(mac))
	}
	return nil
}

// validateWiFiChannel24 accepts 2.4 GHz channels 1-14. The ESP32 Marauder
// is a 2.4-GHz-only platform; passing 36/40/etc silently no-ops because
// the radio cannot tune there.
func validateWiFiChannel24(channelStr string) error {
	ch, err := strconv.Atoi(strings.TrimSpace(channelStr))
	if err != nil {
		return fmt.Errorf("invalid WiFi channel %q (want a number 1-14): %w", channelStr, err)
	}
	return validateWiFiChannel24Int(ch)
}

// validateWiFiChannel24Int is the int variant for callers (SetChannel)
// that already have a parsed value.
func validateWiFiChannel24Int(ch int) error {
	if ch < 1 || ch > 14 {
		return fmt.Errorf("invalid WiFi channel %d (must be 1-14; the ESP32 Marauder is 2.4-GHz only)", ch)
	}
	return nil
}

// validateListIndex rejects negative list indices. The Marauder CLI
// silently no-ops `-a -1` / `-c -2` etc., so the LLM sees a clean
// empty response with no signal that the request did nothing.
func validateListIndex(name string, idx int) error {
	if idx < 0 {
		return fmt.Errorf("invalid %s %d (must be >= 0)", name, idx)
	}
	return nil
}

// --- MAC Manipulation ---

// CloneStaMAC clones the MAC address of the station at the given index.
// Wire: clonestamac -s <index>
func (m *Marauder) CloneStaMAC(index int) (string, error) {
	if err := validateListIndex("station index", index); err != nil {
		return "", err
	}
	return m.Exec(fmt.Sprintf("clonestamac -s %d", index), 5*time.Second)
}

// --- System ---

// InfoAP returns firmware/device info for the AP at the given index.
// Wire: info -a <index>
func (m *Marauder) InfoAP(apIndex int) (string, error) {
	if err := validateListIndex("AP index", apIndex); err != nil {
		return "", err
	}
	return m.Exec(fmt.Sprintf("info -a %d", apIndex), 5*time.Second)
}

// --- Passive Sniffers ---

// MacTrack passively tracks MAC addresses seen in the air for the given duration.
// Suggested timeout: 30 s.
// Wire: mactrack
func (m *Marauder) MacTrack(timeout time.Duration) (string, error) {
	return m.MacTrackCtx(context.Background(), timeout)
}

// MacTrackCtx is the context-aware variant of MacTrack.
func (m *Marauder) MacTrackCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "mactrack", timeout)
}

// Sigmon monitors WiFi signal levels for the given duration.
// Suggested timeout: 30 s.
// Wire: sigmon
func (m *Marauder) Sigmon(timeout time.Duration) (string, error) {
	return m.SigmonCtx(context.Background(), timeout)
}

// SigmonCtx is the context-aware variant of Sigmon.
func (m *Marauder) SigmonCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "sigmon", timeout)
}

// SniffPineScan sniffs for WiFi Pineapple scan frames for the given duration.
// Suggested timeout: 30 s.
// Wire: sniffpinescan
func (m *Marauder) SniffPineScan(timeout time.Duration) (string, error) {
	return m.SniffPineScanCtx(context.Background(), timeout)
}

// SniffPineScanCtx is the context-aware variant of SniffPineScan.
func (m *Marauder) SniffPineScanCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "sniffpinescan", timeout)
}

// SniffMultiSSID sniffs for multi-SSID beacon frames for the given duration.
// Suggested timeout: 30 s.
// Wire: sniffmultissid
func (m *Marauder) SniffMultiSSID(timeout time.Duration) (string, error) {
	return m.SniffMultiSSIDCtx(context.Background(), timeout)
}

// SniffMultiSSIDCtx is the context-aware variant of SniffMultiSSID.
func (m *Marauder) SniffMultiSSIDCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "sniffmultissid", timeout)
}

// --- Wardrive ---

// WardriveStart begins GPS-tagged AP logging to a Wigle CSV file.
// The session runs until the timeout elapses or WardriveStop is called.
// Wire: wardrive
func (m *Marauder) WardriveStart(timeout time.Duration) (string, error) {
	return m.WardriveStartCtx(context.Background(), timeout)
}

// WardriveStartCtx is the context-aware variant of WardriveStart.
// Particularly impactful given wardrive's 600 s default duration —
// operators no longer wait out the full 10 minutes to cancel a turn.
func (m *Marauder) WardriveStartCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "wardrive", timeout)
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
	return m.GpsTrackerStartCtx(context.Background(), timeout)
}

// GpsTrackerStartCtx is the context-aware variant of GpsTrackerStart.
func (m *Marauder) GpsTrackerStartCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "gpstracker", timeout)
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
//
// Validates bssid as a MAC and channel as a 2.4-GHz channel number before
// transport. Pre-fix, the Marauder silently no-op'd malformed entries —
// the LLM had no way to tell whether the AP made it into the list.
// Wire: add -a -b <bssid> -c <channel> -s "<essid>"
func (m *Marauder) AddAP(bssid, channel, essid string) (string, error) {
	if err := validateBSSID(bssid); err != nil {
		return "", err
	}
	if err := validateWiFiChannel24(channel); err != nil {
		return "", err
	}
	if strings.TrimSpace(essid) == "" {
		return "", fmt.Errorf("invalid ESSID: empty")
	}
	return m.Exec(fmt.Sprintf(`add -a -b %s -c %s -s "%s"`,
		clisafe.SanitizeArg(bssid),
		clisafe.SanitizeArg(channel),
		clisafe.SanitizeArg(essid),
	), 5*time.Second)
}

// AddStation adds a station entry to the station list.
// bssid is the station MAC address; apIndex is the index of the associated AP
// in the current AP list.
//
// Validates bssid as a MAC and apIndex as a non-negative list index.
// Wire: add -c -m <bssid> -a <apIndex>
func (m *Marauder) AddStation(bssid string, apIndex int) (string, error) {
	if err := validateBSSID(bssid); err != nil {
		return "", err
	}
	if apIndex < 0 {
		return "", fmt.Errorf("invalid AP index %d (must be >= 0)", apIndex)
	}
	return m.Exec(fmt.Sprintf("add -c -m %s -a %d", clisafe.SanitizeArg(bssid), apIndex), 5*time.Second)
}

// --- BLE Spoof ---

// BTSpoofAirtag spoofs AirTag BLE advertisements using the device at the
// given index in the current scan list.
// Wire: spoofat -t <index>
func (m *Marauder) BTSpoofAirtag(index int) (string, error) {
	if err := validateListIndex("scan-list index", index); err != nil {
		return "", err
	}
	return m.Exec(fmt.Sprintf("spoofat -t %d", index), 5*time.Second)
}

// --- WiFi Attacks ---

// Karma responds to probe requests from the station at the given probe-list
// index, acting as an open AP for any SSID the station is probing for.
// Runs for the given timeout duration.
// Wire: karma -p <probeIndex>
func (m *Marauder) Karma(probeIndex int) (string, error) {
	if err := validateListIndex("probe-list index", probeIndex); err != nil {
		return "", err
	}
	return m.Exec(fmt.Sprintf("karma -p %d", probeIndex), 60*time.Second)
}

// AttackQuiet sends quiet (low-noise) disassociation frames to selected targets
// for the given duration.
// Wire: attack -t quiet
func (m *Marauder) AttackQuiet(timeout time.Duration) (string, error) {
	return m.AttackQuietCtx(context.Background(), timeout)
}

// AttackQuietCtx is the context-aware variant of AttackQuiet.
func (m *Marauder) AttackQuietCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "attack -t quiet", timeout)
}

// AttackBadmsg sends malformed management frames to selected targets for the
// given duration. When targeted is true, the -c flag limits the attack to the
// currently-selected station list (same semantics as DeauthToStationList).
// Wire: attack -t badmsg [-c]
func (m *Marauder) AttackBadmsg(targeted bool, timeout time.Duration) (string, error) {
	return m.AttackBadmsgCtx(context.Background(), targeted, timeout)
}

// AttackBadmsgCtx is the context-aware variant of AttackBadmsg.
func (m *Marauder) AttackBadmsgCtx(ctx context.Context, targeted bool, timeout time.Duration) (string, error) {
	cmd := "attack -t badmsg"
	if targeted {
		cmd += " -c"
	}
	return m.ExecCtx(ctx, cmd, timeout)
}

// AttackSleep sends power-save spoofed frames to selected targets for the
// given duration, causing victims to buffer and drop their traffic.
// When targeted is true, the -c flag limits the attack to the currently-selected
// station list (same semantics as DeauthToStationList).
// Wire: attack -t sleep [-c]
func (m *Marauder) AttackSleep(targeted bool, timeout time.Duration) (string, error) {
	return m.AttackSleepCtx(context.Background(), targeted, timeout)
}

// AttackSleepCtx is the context-aware variant of AttackSleep.
func (m *Marauder) AttackSleepCtx(ctx context.Context, targeted bool, timeout time.Duration) (string, error) {
	cmd := "attack -t sleep"
	if targeted {
		cmd += " -c"
	}
	return m.ExecCtx(ctx, cmd, timeout)
}

// --- Evil Portal (additional subverbs) ---
// EvilPortalSetHTML and EvilPortalSetHTMLStr already exist in commands.go.

// EvilPortalSetAP configures the evil portal to use the AP at the given index
// as the rogue access point.
// Wire: evilportal -c setap -i <index>
func (m *Marauder) EvilPortalSetAP(index int) (string, error) {
	if err := validateListIndex("AP index", index); err != nil {
		return "", err
	}
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
