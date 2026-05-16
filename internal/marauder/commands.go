package marauder

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/clisafe"
)

// --- WiFi Scanning ---
//
// Each timed method here has a Background-context wrapper for
// back-compat (`ScanAP`, `ScanAll`, …) and a context-aware variant
// (`ScanAPCtx`, `ScanAllCtx`, …) that threads ctx through to the
// Marauder read loop. Tool handlers and any other caller with a
// turn-level ctx should prefer the *Ctx form so a Ctrl+C aborts
// the in-flight call within ~100 ms instead of blocking until
// timeout. The Background wrappers exist so the migration can be
// done incrementally per call site.

func (m *Marauder) ScanAP(timeout time.Duration) (string, error) {
	return m.ScanAPCtx(context.Background(), timeout)
}

// ScanAPCtx is the context-aware variant of ScanAP.
func (m *Marauder) ScanAPCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "scanap", timeout)
}

// ScanAll scans for both APs and stations simultaneously.
// (scansta is not available in Marauder v1.11.1; use scanall instead.)
func (m *Marauder) ScanAll(timeout time.Duration) (string, error) {
	return m.ScanAllCtx(context.Background(), timeout)
}

// ScanAllCtx is the context-aware variant of ScanAll.
func (m *Marauder) ScanAllCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "scanall", timeout)
}

// ScanStation was the short-hand for scanning stations only on pre-v1.11
// firmware. The underlying `scansta` command was removed in v1.11.1 with no
// replacement on the current upstream — ScanAll is the sanctioned path.
// Exposing this as a hard error means SDK / MCP surfaces that advertise
// "scansta" get a clear failure mode instead of a silent timeout on a no-op.
func (m *Marauder) ScanStation(_ time.Duration) (string, error) {
	return "", fmt.Errorf("scansta is unavailable in Marauder v1.11.1+; use ScanAll instead")
}

func (m *Marauder) StopScan() (string, error) {
	return m.Exec("stopscan", 5*time.Second)
}

// --- Selection ---

// selectIndicesRe accepts a Marauder `select` index argument: either the
// literal token "all", or a comma/space/tab-separated list of decimal
// indices. The character class is explicit (not `\s`) because `\s` also
// matches \r, \n, and \f — exactly the bytes an attacker would use to
// inject a follow-on command over the serial link.
var selectIndicesRe = regexp.MustCompile(`^(?:all|[0-9][0-9, \t]*)$`)

// validateSelectIndices returns nil when s is a safe Marauder select index
// list. See selectIndicesRe for the accepted grammar.
func validateSelectIndices(s string) error {
	if !selectIndicesRe.MatchString(s) {
		return fmt.Errorf("invalid indices %q (want \"all\" or a comma/space-separated list of digits)", s)
	}
	return nil
}

// SelectAP selects APs by index list or "all".
func (m *Marauder) SelectAP(indices string) (string, error) {
	if err := validateSelectIndices(indices); err != nil {
		return "", err
	}
	return m.Exec("select -a "+indices, 5*time.Second)
}

// SelectStation selects stations by index list or "all".
func (m *Marauder) SelectStation(indices string) (string, error) {
	if err := validateSelectIndices(indices); err != nil {
		return "", err
	}
	return m.Exec("select -c "+indices, 5*time.Second)
}

// SelectSSID selects SSIDs by index list or "all".
func (m *Marauder) SelectSSID(indices string) (string, error) {
	if err := validateSelectIndices(indices); err != nil {
		return "", err
	}
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
	return m.DeauthAttackCtx(context.Background(), timeout)
}

// DeauthAttackCtx is the context-aware variant of DeauthAttack.
func (m *Marauder) DeauthAttackCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "attack -t deauth", timeout)
}

// DeauthToStationList sends deauth frames to the currently-selected
// *station list* (rather than the broad "all captured APs" mode used by
// DeauthAttack). Upstream parses `-c` as a mode flag that selects the
// WIFI_ATTACK_DEAUTH_TARGETED path; it does NOT take a channel argument.
// Callers need to have populated the station list via ScanAll / SelectStation
// first, otherwise the attack finds no targets and returns immediately.
func (m *Marauder) DeauthToStationList(timeout time.Duration) (string, error) {
	return m.DeauthToStationListCtx(context.Background(), timeout)
}

// DeauthToStationListCtx is the context-aware variant of DeauthToStationList.
func (m *Marauder) DeauthToStationListCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "attack -t deauth -c", timeout)
}

// BeaconSpamList spams beacon frames from the current SSID list.
func (m *Marauder) BeaconSpamList(timeout time.Duration) (string, error) {
	return m.BeaconSpamListCtx(context.Background(), timeout)
}

// BeaconSpamListCtx is the context-aware variant of BeaconSpamList.
func (m *Marauder) BeaconSpamListCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "attack -t beacon -l", timeout)
}

// BeaconSpamRandom spams beacon frames with random SSIDs.
func (m *Marauder) BeaconSpamRandom(timeout time.Duration) (string, error) {
	return m.BeaconSpamRandomCtx(context.Background(), timeout)
}

// BeaconSpamRandomCtx is the context-aware variant of BeaconSpamRandom.
func (m *Marauder) BeaconSpamRandomCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "attack -t beacon -r", timeout)
}

// BeaconSpamClone clones nearby AP SSIDs and spams them as beacons.
func (m *Marauder) BeaconSpamClone(timeout time.Duration) (string, error) {
	return m.BeaconSpamCloneCtx(context.Background(), timeout)
}

// BeaconSpamCloneCtx is the context-aware variant of BeaconSpamClone.
func (m *Marauder) BeaconSpamCloneCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "attack -t beacon -a", timeout)
}

// BeaconSpamRickroll spams Rick Astley-themed SSIDs as beacons.
func (m *Marauder) BeaconSpamRickroll(timeout time.Duration) (string, error) {
	return m.BeaconSpamRickrollCtx(context.Background(), timeout)
}

// BeaconSpamRickrollCtx is the context-aware variant of BeaconSpamRickroll.
func (m *Marauder) BeaconSpamRickrollCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "attack -t rickroll", timeout)
}

// BeaconSpamFunny spams a set of funny SSIDs as beacons.
func (m *Marauder) BeaconSpamFunny(timeout time.Duration) (string, error) {
	return m.BeaconSpamFunnyCtx(context.Background(), timeout)
}

// BeaconSpamFunnyCtx is the context-aware variant of BeaconSpamFunny.
func (m *Marauder) BeaconSpamFunnyCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "attack -t funny", timeout)
}

// ProbeFlood floods the air with probe request frames.
func (m *Marauder) ProbeFlood(timeout time.Duration) (string, error) {
	return m.ProbeFloodCtx(context.Background(), timeout)
}

// ProbeFloodCtx is the context-aware variant of ProbeFlood.
func (m *Marauder) ProbeFloodCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "attack -t probe", timeout)
}

// CSAAttack sends Channel Switch Announcement frames to selected APs.
func (m *Marauder) CSAAttack(timeout time.Duration) (string, error) {
	return m.CSAAttackCtx(context.Background(), timeout)
}

// CSAAttackCtx is the context-aware variant of CSAAttack.
func (m *Marauder) CSAAttackCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "attack -t csa", timeout)
}

// SAEFlood floods selected APs with SAE (WPA3) authentication frames.
func (m *Marauder) SAEFlood(timeout time.Duration) (string, error) {
	return m.SAEFloodCtx(context.Background(), timeout)
}

// SAEFloodCtx is the context-aware variant of SAEFlood.
func (m *Marauder) SAEFloodCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "attack -t sae", timeout)
}

// --- Sniffing ---

// SniffPMKID captures PMKID handshakes. channel selects a specific WiFi
// channel (0 = all channels / default). deauth=true triggers active deauth
// frames against scanned APs to coerce PMKID exchange. listOnly=true passes
// `-l` to limit capture to the currently-loaded AP list.
//
// The previous signature accepted a free-form flags string that was passed
// through unsanitised — a caller-supplied `\n` would inject arbitrary
// follow-on commands over the serial link. Typed params remove that vector.
func (m *Marauder) SniffPMKID(channel int, deauth, listOnly bool, timeout time.Duration) (string, error) {
	return m.SniffPMKIDCtx(context.Background(), channel, deauth, listOnly, timeout)
}

// SniffPMKIDCtx is the context-aware variant of SniffPMKID.
func (m *Marauder) SniffPMKIDCtx(ctx context.Context, channel int, deauth, listOnly bool, timeout time.Duration) (string, error) {
	cmd := "sniffpmkid"
	if channel > 0 {
		cmd += fmt.Sprintf(" -c %d", channel)
	}
	if deauth {
		cmd += " -d"
	}
	if listOnly {
		cmd += " -l"
	}
	return m.ExecCtx(ctx, cmd, timeout)
}

func (m *Marauder) SniffBeacon(timeout time.Duration) (string, error) {
	return m.SniffBeaconCtx(context.Background(), timeout)
}

// SniffBeaconCtx is the context-aware variant of SniffBeacon.
func (m *Marauder) SniffBeaconCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "sniffbeacon", timeout)
}

func (m *Marauder) SniffDeauth(timeout time.Duration) (string, error) {
	return m.SniffDeauthCtx(context.Background(), timeout)
}

// SniffDeauthCtx is the context-aware variant of SniffDeauth.
func (m *Marauder) SniffDeauthCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "sniffdeauth", timeout)
}

func (m *Marauder) SniffProbe(timeout time.Duration) (string, error) {
	return m.SniffProbeCtx(context.Background(), timeout)
}

// SniffProbeCtx is the context-aware variant of SniffProbe.
func (m *Marauder) SniffProbeCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "sniffprobe", timeout)
}

// SniffPwnagotchi sniffs for Pwnagotchi devices.
func (m *Marauder) SniffPwnagotchi(timeout time.Duration) (string, error) {
	return m.SniffPwnagotchiCtx(context.Background(), timeout)
}

// SniffPwnagotchiCtx is the context-aware variant of SniffPwnagotchi.
func (m *Marauder) SniffPwnagotchiCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "sniffpwn", timeout)
}

func (m *Marauder) SniffRaw(timeout time.Duration) (string, error) {
	return m.SniffRawCtx(context.Background(), timeout)
}

// SniffRawCtx is the context-aware variant of SniffRaw.
func (m *Marauder) SniffRawCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "sniffraw", timeout)
}

// --- BLE Spam ---

// bleSpamModes is the allowlist of valid `blespam -t` mode tokens accepted
// by the Marauder firmware. Any value outside this set is rejected at the
// Go layer rather than being silently forwarded as-is.
var bleSpamModes = map[string]struct{}{
	"apple":   {},
	"google":  {},
	"samsung": {},
	"windows": {},
	"flipper": {},
	"all":     {},
}

// BLESpam sends BLE advertisement spam of the given type.
// Valid modes: apple, google, samsung, windows, flipper, all.
func (m *Marauder) BLESpam(mode string, timeout time.Duration) (string, error) {
	return m.BLESpamCtx(context.Background(), mode, timeout)
}

// BLESpamCtx is the context-aware variant of BLESpam.
func (m *Marauder) BLESpamCtx(ctx context.Context, mode string, timeout time.Duration) (string, error) {
	if _, ok := bleSpamModes[mode]; !ok {
		return "", fmt.Errorf("invalid blespam mode %q (valid: apple, google, samsung, windows, flipper, all)", mode)
	}
	return m.ExecCtx(ctx, "blespam -t "+clisafe.SanitizeArg(mode), timeout)
}

// --- Bluetooth Scanning ---

// sniffBTTargets is the allowlist of valid `sniffbt -t` tokens. Anything
// outside this set is rejected to prevent command injection via a free-form
// string that would otherwise be concatenated into the CLI line.
var sniffBTTargets = map[string]struct{}{
	"airtag":  {},
	"flipper": {},
	"flock":   {},
	"meta":    {},
}

// SniffBT sniffs Bluetooth advertisements for specific device types.
// Valid targetType values: airtag, flipper, flock, meta.
func (m *Marauder) SniffBT(targetType string, timeout time.Duration) (string, error) {
	return m.SniffBTCtx(context.Background(), targetType, timeout)
}

// SniffBTCtx is the context-aware variant of SniffBT.
func (m *Marauder) SniffBTCtx(ctx context.Context, targetType string, timeout time.Duration) (string, error) {
	if _, ok := sniffBTTargets[targetType]; !ok {
		return "", fmt.Errorf("invalid sniffbt target %q (valid: airtag, flipper, flock, meta)", targetType)
	}
	return m.ExecCtx(ctx, "sniffbt -t "+clisafe.SanitizeArg(targetType), timeout)
}

// SniffSkimmer sniffs for Bluetooth credit card skimmers.
func (m *Marauder) SniffSkimmer(timeout time.Duration) (string, error) {
	return m.SniffSkimmerCtx(context.Background(), timeout)
}

// SniffSkimmerCtx is the context-aware variant of SniffSkimmer.
func (m *Marauder) SniffSkimmerCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "sniffskim", timeout)
}

// --- Evil Portal ---

// EvilPortalStart starts the evil portal captive portal.
// Pass an optional HTML filename, or empty string to use the default page.
// The filename is sanitised and quoted so spaces are preserved (Marauder's
// arg parser otherwise truncates at the first whitespace character).
func (m *Marauder) EvilPortalStart(filename string) (string, error) {
	cmd := "evilportal -c start"
	if filename != "" {
		cmd += fmt.Sprintf(` -w "%s"`, clisafe.SanitizeArg(filename))
	}
	return m.Exec(cmd, 10*time.Second)
}

// EvilPortalSetHTML sets the evil portal HTML page to the given filename on
// the SD card. Filename is sanitised and quoted (see EvilPortalStart).
func (m *Marauder) EvilPortalSetHTML(filename string) (string, error) {
	return m.Exec(fmt.Sprintf(`evilportal -c sethtml "%s"`, clisafe.SanitizeArg(filename)), 5*time.Second)
}

// EvilPortalSetHTMLStr tells Marauder to read the HTML page from serial input.
func (m *Marauder) EvilPortalSetHTMLStr() (string, error) {
	return m.Exec("evilportal -c sethtmlstr", 5*time.Second)
}

// --- Channel ---

// SetChannel sets the WiFi channel (1–14).
func (m *Marauder) SetChannel(channel int) (string, error) {
	if err := validateWiFiChannel24Int(channel); err != nil {
		return "", err
	}
	return m.Exec(fmt.Sprintf("channel -s %d", channel), 5*time.Second)
}

// GetChannel returns the current WiFi channel.
func (m *Marauder) GetChannel() (string, error) {
	return m.Exec("channel", 5*time.Second)
}

// --- SSID Management ---

// AddSSID adds a named SSID to the SSID list. Double-quotes, CR, LF and NUL
// in `name` are stripped so the argument cannot break out of the quoted form
// the Marauder CLI expects.
func (m *Marauder) AddSSID(name string) (string, error) {
	return m.Exec(fmt.Sprintf(`ssid -a -n "%s"`, clisafe.SanitizeArg(name)), 5*time.Second)
}

// GenerateSSIDs generates count random SSIDs and adds them to the list.
func (m *Marauder) GenerateSSIDs(count int) (string, error) {
	if count <= 0 {
		return "", fmt.Errorf("invalid SSID count %d (must be >= 1)", count)
	}
	return m.Exec(fmt.Sprintf("ssid -a -g %d", count), 5*time.Second)
}

// RemoveSSID removes the SSID at the given index from the list.
func (m *Marauder) RemoveSSID(index int) (string, error) {
	if err := validateListIndex("SSID index", index); err != nil {
		return "", err
	}
	return m.Exec(fmt.Sprintf("ssid -r %d", index), 5*time.Second)
}

// --- Network Recon (requires WiFi join) ---

// Join connects to the AP at the given index using the provided password.
// The password is quoted and sanitised so embedded spaces / special chars
// survive the Marauder CLI parser; CR/LF/NUL/quote are stripped.
func (m *Marauder) Join(apIndex int, password string) (string, error) {
	if err := validateListIndex("AP index", apIndex); err != nil {
		return "", err
	}
	return m.Exec(fmt.Sprintf(`join -a %d -p "%s"`, apIndex, clisafe.SanitizeArg(password)), 15*time.Second)
}

// PingScan performs an ICMP ping sweep of the joined network. The Marauder
// firmware silently no-ops this command unless the board has already
// associated with an AP via Join — there is no error on the wire. Callers
// should invoke Join successfully beforehand.
func (m *Marauder) PingScan(timeout time.Duration) (string, error) {
	return m.PingScanCtx(context.Background(), timeout)
}

// PingScanCtx is the context-aware variant of PingScan.
func (m *Marauder) PingScanCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "pingscan", timeout)
}

// ARPScan performs an ARP scan of the joined network. Silently no-ops on
// the dual-band board variant (HAS_DUAL_BAND=1 in firmware) and whenever
// the board isn't associated. Call Join first and, on dual-band hardware,
// use the upstream pingscan as an alternative.
func (m *Marauder) ARPScan(timeout time.Duration) (string, error) {
	return m.ARPScanCtx(context.Background(), timeout)
}

// ARPScanCtx is the context-aware variant of ARPScan.
func (m *Marauder) ARPScanCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "arpscan", timeout)
}

// PortScan performs a full-port scan against the host at the given IP
// index. Requires a successful Join and a prior pingscan/arpscan to
// populate the IP list. See PortScanService for the named-service variant.
func (m *Marauder) PortScan(ipIndex int, timeout time.Duration) (string, error) {
	return m.PortScanCtx(context.Background(), ipIndex, timeout)
}

// PortScanCtx is the context-aware variant of PortScan.
func (m *Marauder) PortScanCtx(ctx context.Context, ipIndex int, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, fmt.Sprintf("portscan -a -t %d", ipIndex), timeout)
}

// portScanServices is the allowlist of well-known service tokens Marauder
// accepts on `portscan -s <service>`. Firmware upstream maps these to fixed
// port numbers (e.g. ssh → 22, http → 80). We validate at the Go layer so
// callers don't get a silent no-op on a typo.
var portScanServices = map[string]struct{}{
	"ssh":   {},
	"http":  {},
	"https": {},
	"ftp":   {},
	"smb":   {},
	"rdp":   {},
	"dns":   {},
	"smtp":  {},
	"pop3":  {},
	"imap":  {},
	"mysql": {},
	"psql":  {},
	"mssql": {},
	"redis": {},
	"vnc":   {},
}

// PortScanService runs the named-service variant of portscan (`portscan -s
// <service> -t <ipIndex>`). Requires the same Join precondition as PortScan.
func (m *Marauder) PortScanService(ipIndex int, service string, timeout time.Duration) (string, error) {
	return m.PortScanServiceCtx(context.Background(), ipIndex, service, timeout)
}

// PortScanServiceCtx is the context-aware variant of PortScanService.
func (m *Marauder) PortScanServiceCtx(ctx context.Context, ipIndex int, service string, timeout time.Duration) (string, error) {
	if _, ok := portScanServices[service]; !ok {
		return "", fmt.Errorf("invalid portscan service %q (valid: ssh, http, https, ftp, smb, rdp, dns, smtp, pop3, imap, mysql, psql, mssql, redis, vnc)", service)
	}
	return m.ExecCtx(ctx, fmt.Sprintf("portscan -s %s -t %d", clisafe.SanitizeArg(service), ipIndex), timeout)
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
	if err := validateListIndex("AP index", index); err != nil {
		return "", err
	}
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

// settingNames is the allowlist of setting names `settings -s` accepts on
// current ESP32-Marauder firmware. Validating at the Go layer turns typos
// and free-form input from an LLM into a clear error instead of a silent
// firmware no-op (the parser ignores unknown names without feedback) — and
// closes a CLI-injection path where an attacker-controlled `name` would
// otherwise have been concatenated verbatim.
var settingNames = map[string]struct{}{
	"ForcePMKID":   {},
	"ForceProbe":   {},
	"SavePCAP":     {},
	"SaveLog":      {},
	"SavePMKID":    {},
	"EnableLED":    {},
	"RandomBLEMac": {},
	"EnableWeb":    {},
	"SDCard":       {},
	"WebAuth":      {},
}

// SetSetting updates a single device setting by name and value. Both args
// are sanitised (CR/LF/NUL/quote stripped) so a value with embedded control
// characters can't inject additional CLI commands.
//
// The firmware's settings parser only accepts exactly "enable" or "disable"
// for value — any other token is silently ignored and no error is returned
// over the CLI. We validate at the Go layer so callers get a clear error
// instead of a silent no-op.
func (m *Marauder) SetSetting(name, value string) (string, error) {
	if _, ok := settingNames[name]; !ok {
		return "", fmt.Errorf("invalid setting name %q (valid: ForcePMKID, ForceProbe, SavePCAP, SaveLog, SavePMKID, EnableLED, RandomBLEMac, EnableWeb, SDCard, WebAuth)", name)
	}
	if value != "enable" && value != "disable" {
		return "", fmt.Errorf("invalid setting value %q (must be \"enable\" or \"disable\")", value)
	}
	return m.Exec(fmt.Sprintf("settings -s %s %s", clisafe.SanitizeArg(name), clisafe.SanitizeArg(value)), 5*time.Second)
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

// --- GPS (requires GPS module on the devboard) ---

// GPSData prints the last parsed GPS fix (lat/lon/alt/date/accuracy/text).
// Silently returns empty if no GPS module is attached.
func (m *Marauder) GPSData() (string, error) {
	return m.Exec("gpsdata", 5*time.Second)
}

// gpsValidFields is the allowlist of `gps -g <field>` tokens accepted by
// firmware: applications/main/gps_cli.c (or equivalent). Guarded at the Go
// layer to surface typos as errors instead of silent no-ops.
var gpsValidFields = map[string]struct{}{
	"fix": {}, "sat": {}, "lon": {}, "lat": {}, "alt": {},
	"date": {}, "accuracy": {}, "text": {}, "nmea": {},
}

// GPSField returns a single GPS datum selected by `field`. Accepts:
// fix, sat, lon, lat, alt, date, accuracy, text, nmea. The optional
// navSystem token selects the satellite system: "native", "all", "gps",
// "glonass", "galileo", "navic", "qzss", "beidou" (empty = firmware default).
func (m *Marauder) GPSField(field, navSystem string) (string, error) {
	if _, ok := gpsValidFields[field]; !ok {
		return "", fmt.Errorf("invalid gps field %q (valid: fix, sat, lon, lat, alt, date, accuracy, text, nmea)", field)
	}
	cmd := "gps -g " + clisafe.SanitizeArg(field)
	if navSystem != "" {
		cmd += " -n " + clisafe.SanitizeArg(navSystem)
	}
	return m.Exec(cmd, 5*time.Second)
}

// NMEA streams raw NMEA sentences from the attached GPS module. Empty on
// boards without GPS hardware.
func (m *Marauder) NMEA(timeout time.Duration) (string, error) {
	return m.NMEACtx(context.Background(), timeout)
}

// NMEACtx is the context-aware variant of NMEA.
func (m *Marauder) NMEACtx(ctx context.Context, timeout time.Duration) (string, error) {
	return m.ExecCtx(ctx, "nmea", timeout)
}

// --- Device-local utilities ---

// PacketCount returns a live packet-counter snapshot (cumulative packets
// received since boot, grouped by frame type).
func (m *Marauder) PacketCount() (string, error) {
	return m.Exec("packetcount", 5*time.Second)
}

// StorageLS lists the contents of the given directory on the Marauder SD
// card. The path is sanitised + double-quoted so spaces are preserved
// (the firmware's args parser otherwise truncates at the first space).
func (m *Marauder) StorageLS(path string) (string, error) {
	if path == "" {
		path = "/"
	}
	return m.Exec(fmt.Sprintf(`ls "%s"`, clisafe.SanitizeArg(path)), 5*time.Second)
}

// --- LED control ---

// LEDSetHex sets the devboard LED to a literal 24-bit RGB hex colour
// (e.g. "ff0000" for red). The hex value is sanitised; the firmware
// rejects non-hex strings silently, so we validate at the Go layer.
func (m *Marauder) LEDSetHex(rgbHex string) (string, error) {
	cleaned := strings.TrimPrefix(strings.TrimPrefix(rgbHex, "#"), "0x")
	if len(cleaned) != 6 {
		return "", fmt.Errorf("invalid LED colour %q (want 6-hex RGB e.g. \"ff0000\")", rgbHex)
	}
	for _, c := range cleaned {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return "", fmt.Errorf("invalid LED colour %q (non-hex character)", rgbHex)
		}
	}
	return m.Exec("led -s "+clisafe.SanitizeArg(cleaned), 5*time.Second)
}

// LEDRainbow starts the cycling rainbow pattern. Use any other LED command
// to stop it.
func (m *Marauder) LEDRainbow() (string, error) {
	return m.Exec("led -p rainbow", 5*time.Second)
}
