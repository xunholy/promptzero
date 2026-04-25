package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/bruce"
	"github.com/xunholy/promptzero/internal/risk"
)

// bruce.go registers the bruce_* tools for the Bruce ESP32 pentesting firmware
// backend (https://github.com/pr3y/Bruce). Bruce is a sibling to the Marauder
// backend (internal/marauder) — same serial-over-USB pattern, wider capability
// set: 5 GHz Wi-Fi (ESP32-C5), Zigbee/IEEE 802.15.4, LoRa, NFC via PN532,
// BadUSB, IR, and more.

// GroupBruce is the router bucket for all Bruce-backend tools.
const GroupBruce Group = "bruce"

// RequireBruce returns a friendly error when the optional Bruce devboard is
// not connected.  Bruce handlers call this before invoking any d.Bruce method,
// mirroring RequireMarauder (internal/tools/spec.go).
func (d *Deps) RequireBruce() error {
	if d == nil || d.Bruce == nil {
		return fmt.Errorf("Bruce devboard not connected — configure bruce.port in config or use --bruce flag")
	}
	return nil
}

//nolint:gochecknoinits
func init() {
	// --- Capabilities (read-only) -------------------------------------------

	Register(Spec{
		Name: "bruce_capabilities",
		Description: "Return the capability bitmap of the connected Bruce devboard: " +
			"HasFiveGHz, HasZigbee, HasLoRa, HasNFC, HasIR, BoardType, FirmwareVersion. " +
			"Read from the boot banner captured during Connect; no hardware probe is issued.",
		Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
		Required:  nil,
		Risk:      risk.Low,
		Group:     GroupBruce,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireBruce(); err != nil {
				return "", err
			}
			caps := d.Bruce.Capabilities()
			b, err := json.Marshal(caps)
			if err != nil {
				return "", fmt.Errorf("bruce_capabilities: marshal: %w", err)
			}
			return string(b), nil
		},
	})

	// --- Wi-Fi scanning -----------------------------------------------------

	Register(Spec{
		Name: "bruce_wifi_scan",
		Description: "Scan for 2.4 GHz Wi-Fi access points using the Bruce devboard. " +
			"Returns a JSON array of APs with SSID, BSSID, RSSI, channel, and band.",
		Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
		Required:  nil,
		Risk:      risk.Medium,
		Group:     GroupBruce,
		AgentOnly: false,
		Handler: func(ctx context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireBruce(); err != nil {
				return "", err
			}
			aps, err := d.Bruce.ScanWiFi(ctx)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(aps)
			return string(b), nil
		},
	})

	Register(Spec{
		Name: "bruce_wifi_5g_scan",
		Description: "Scan for 5 GHz Wi-Fi access points using the Bruce devboard (requires ESP32-C5 hardware). " +
			"Returns ErrCapabilityNotAvailable when the board does not support 5 GHz. " +
			"Check bruce_capabilities first.",
		Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
		Required:  nil,
		Risk:      risk.Medium,
		Group:     GroupBruce,
		AgentOnly: false,
		Handler: func(ctx context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireBruce(); err != nil {
				return "", err
			}
			aps, err := d.Bruce.Scan5GHz(ctx)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(aps)
			return string(b), nil
		},
	})

	// --- Wi-Fi attacks -------------------------------------------------------

	Register(Spec{
		Name: "bruce_wifi_deauth",
		Description: "Send 802.11 deauthentication frames against a target BSSID on the specified channel. " +
			"Disconnects clients from their access point. AUTHORIZED LAB/PENTEST USE ONLY.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"bssid":{"type":"string","description":"Target AP BSSID (colon-separated hex, e.g. aa:bb:cc:dd:ee:ff)"},` +
			`"channel":{"type":"integer","description":"Wi-Fi channel the target is on (1–14 for 2.4 GHz, 36–165 for 5 GHz)"}}}`),
		Required:  []string{"bssid", "channel"},
		Risk:      risk.Critical,
		Group:     GroupBruce,
		AgentOnly: false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireBruce(); err != nil {
				return "", err
			}
			bssid := str(p, "bssid")
			channel := intOr(p, "channel", 0)
			if bssid == "" {
				return "", fmt.Errorf("bruce_wifi_deauth: bssid is required")
			}
			if channel == 0 {
				return "", fmt.Errorf("bruce_wifi_deauth: channel is required")
			}
			if err := d.Bruce.Deauth(ctx, bssid, channel); err != nil {
				return "", err
			}
			return fmt.Sprintf(`{"status":"deauth sent","bssid":%q,"channel":%d}`, bssid, channel), nil
		},
	})

	Register(Spec{
		Name: "bruce_evil_twin",
		Description: "Start a rogue access point (evil twin) that clones the given SSID/BSSID. " +
			"Lures clients to connect to the attacker-controlled AP. AUTHORIZED LAB/PENTEST USE ONLY.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"ssid":{"type":"string","description":"SSID to clone"},` +
			`"bssid":{"type":"string","description":"BSSID of the original AP to clone"}}}`),
		Required:  []string{"ssid", "bssid"},
		Risk:      risk.Critical,
		Group:     GroupBruce,
		AgentOnly: false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireBruce(); err != nil {
				return "", err
			}
			ssid := str(p, "ssid")
			bssid := str(p, "bssid")
			if ssid == "" {
				return "", fmt.Errorf("bruce_evil_twin: ssid is required")
			}
			if bssid == "" {
				return "", fmt.Errorf("bruce_evil_twin: bssid is required")
			}
			if err := d.Bruce.EvilTwin(ctx, ssid, bssid); err != nil {
				return "", err
			}
			return fmt.Sprintf(`{"status":"evil twin started","ssid":%q,"bssid":%q}`, ssid, bssid), nil
		},
	})

	// --- Zigbee / IEEE 802.15.4 ---------------------------------------------

	Register(Spec{
		Name: "bruce_zigbee_scan",
		Description: "Passively scan the 802.15.4 spectrum for Zigbee beacons and associated devices " +
			"(PAN ID, short address, channel). Requires a board with Zigbee/IEEE 802.15.4 support " +
			"(HasZigbee in bruce_capabilities). Passive — no frames transmitted.",
		Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
		Required:  nil,
		Risk:      risk.Medium,
		Group:     GroupBruce,
		AgentOnly: false,
		Handler: func(ctx context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireBruce(); err != nil {
				return "", err
			}
			peers, err := d.Bruce.ZigbeeScan(ctx)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(peers)
			return string(b), nil
		},
	})

	// --- LoRa ---------------------------------------------------------------

	Register(Spec{
		Name: "bruce_lora_scan",
		Description: "Passively listen for LoRa packets on the given frequency (MHz). " +
			"Requires a board with LoRa hardware (HasLoRa in bruce_capabilities). Passive — no transmission.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"frequency_mhz":{"type":"number","description":"LoRa carrier frequency in MHz (e.g. 433.92, 868.1, 915.0)"}}}`),
		Required:  []string{"frequency_mhz"},
		Risk:      risk.Medium,
		Group:     GroupBruce,
		AgentOnly: false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireBruce(); err != nil {
				return "", err
			}
			freq := floatOr(p, "frequency_mhz", 0)
			if freq == 0 {
				return "", fmt.Errorf("bruce_lora_scan: frequency_mhz is required")
			}
			if err := d.Bruce.LoRaScan(ctx, freq); err != nil {
				return "", err
			}
			return fmt.Sprintf(`{"status":"lora scan complete","frequency_mhz":%.3f}`, freq), nil
		},
	})

	// --- IR -----------------------------------------------------------------

	Register(Spec{
		Name: "bruce_ir_send",
		Description: "Transmit an IR signal using the Bruce devboard's IR blaster. " +
			"Requires HasIR (check bruce_capabilities). " +
			"Use bruce_ir_receive first to capture the protocol and code from a real remote.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"protocol":{"type":"string","description":"IR protocol name (e.g. NEC, RC5, Samsung, SONY)"},` +
			`"code":{"type":"string","description":"IR code as a hex string (e.g. 0xDEADBEEF)"}}}`),
		Required:  []string{"protocol", "code"},
		Risk:      risk.High,
		Group:     GroupBruce,
		AgentOnly: false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireBruce(); err != nil {
				return "", err
			}
			protocol := str(p, "protocol")
			code := str(p, "code")
			if protocol == "" {
				return "", fmt.Errorf("bruce_ir_send: protocol is required")
			}
			if code == "" {
				return "", fmt.Errorf("bruce_ir_send: code is required")
			}
			if err := d.Bruce.IRSend(ctx, protocol, code); err != nil {
				return "", err
			}
			return fmt.Sprintf(`{"status":"ir sent","protocol":%q,"code":%q}`, protocol, code), nil
		},
	})

	Register(Spec{
		Name: "bruce_ir_receive",
		Description: "Open the Bruce IR receiver and wait for a signal. " +
			"Returns the captured IR protocol and code that can be replayed with bruce_ir_send. " +
			"Requires HasIR (check bruce_capabilities).",
		Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
		Required:  nil,
		Risk:      risk.Medium,
		Group:     GroupBruce,
		AgentOnly: false,
		Handler: func(ctx context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireBruce(); err != nil {
				return "", err
			}
			cap, err := d.Bruce.IRReceive(ctx)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(cap)
			return string(b), nil
		},
	})

	// --- BadUSB -------------------------------------------------------------

	Register(Spec{
		Name: "bruce_badusb_run",
		Description: "Execute a Ducky Script payload stored on the Bruce devboard's SD card. " +
			"The board enumerates as a USB HID keyboard and types the script. " +
			"Provide the filename as it appears on the SD card. AUTHORIZED LAB/PENTEST USE ONLY.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"filename":{"type":"string","description":"Ducky Script filename on the Bruce SD card (e.g. payload.txt)"}}}`),
		Required:  []string{"filename"},
		Risk:      risk.Critical,
		Group:     GroupBruce,
		AgentOnly: false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireBruce(); err != nil {
				return "", err
			}
			filename := str(p, "filename")
			if filename == "" {
				return "", fmt.Errorf("bruce_badusb_run: filename is required")
			}
			if err := d.Bruce.BadUSBRun(ctx, filename); err != nil {
				return "", err
			}
			return fmt.Sprintf(`{"status":"badusb executed","filename":%q}`, filename), nil
		},
	})

	// --- NFC ----------------------------------------------------------------

	Register(Spec{
		Name: "bruce_nfc_read",
		Description: "Read an NFC card or tag using the PN532 module attached to the Bruce devboard. " +
			"Returns UID, ATQA, SAK, and raw response lines. " +
			"Requires HasNFC (check bruce_capabilities).",
		Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
		Required:  nil,
		Risk:      risk.Medium,
		Group:     GroupBruce,
		AgentOnly: false,
		Handler: func(ctx context.Context, d *Deps, _ map[string]any) (string, error) {
			if err := d.RequireBruce(); err != nil {
				return "", err
			}
			card, err := d.Bruce.NFCRead(ctx)
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(card)
			return string(b), nil
		},
	})

	// --- Raw CLI passthrough ------------------------------------------------

	Register(Spec{
		Name: "bruce_raw_cli",
		Description: "Send a raw command string to the Bruce firmware and return the response verbatim. " +
			"Full access to the Bruce serial menu — use this for commands not yet exposed as typed tools. " +
			"AUTHORIZED LAB/PENTEST USE ONLY: this bypasses all tool-level validation.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"command":{"type":"string","description":"Raw Bruce CLI command to send (e.g. \"wifi scan\", \"rf lora scan 433.92\")"}}}`),
		Required:  []string{"command"},
		Risk:      risk.Critical,
		Group:     GroupBruce,
		AgentOnly: false,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			if err := d.RequireBruce(); err != nil {
				return "", err
			}
			cmd := str(p, "command")
			if cmd == "" {
				return "", fmt.Errorf("bruce_raw_cli: command is required")
			}
			return d.Bruce.RawCommand(ctx, cmd)
		},
	})
}

// bruceCaps returns the Bruce field from Deps so tool code reads cleanly
// without direct Bruce import in spec.go. Not currently used by spec.go —
// handlers access d.Bruce directly.
var _ = func(d *Deps) *bruce.Client { return d.Bruce }
