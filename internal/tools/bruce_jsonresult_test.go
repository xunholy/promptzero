package tools_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/xunholy/promptzero/internal/bruce"
	"github.com/xunholy/promptzero/internal/tools"
)

// bruceEvilTwinSpec / bruceDeauthSpec / bruceIRSendSpec / bruceBadUSBRunSpec
// are captured at init() — the package-level resetForTest helper in
// spec_test.go can clear the registry between tests, so we snapshot the
// Specs before that happens, matching the wifi_marauder_test.go pattern.
var (
	bruceEvilTwinSpec, bruceEvilTwinFound   = tools.Get("bruce_evil_twin")
	bruceDeauthSpec, bruceDeauthFound       = tools.Get("bruce_wifi_deauth")
	bruceIRSendSpec, bruceIRSendFound       = tools.Get("bruce_ir_send")
	bruceBadUSBRunSpec, bruceBadUSBRunFound = tools.Get("bruce_badusb_run")
	bruceLoRaScanSpec, bruceLoRaScanFound   = tools.Get("bruce_lora_scan")
)

// newOKBruceClient returns a Bruce *Client wired to an empty-but-non-erroring
// mock port — every RawCommand returns "" successfully. Capability flags are
// flipped on so capability-gated handlers (bruce_ir_send, bruce_lora_scan)
// reach the result-build path rather than short-circuiting with
// ErrCapabilityNotAvailable.
func newOKBruceClient(t *testing.T) *bruce.Client {
	t.Helper()
	port := bruce.NewMockPort()
	c := bruce.NewWithPort(port)
	c.SetCapabilities(bruce.Capabilities{
		HasIR:     true,
		HasLoRa:   true,
		HasZigbee: true,
		HasNFC:    true,
	})
	return c
}

// TestBruce_EvilTwin_HostileSSIDProducesValidJSON pins the v0.152
// contract: tool-result strings built from operator/firmware-
// supplied bytes must be valid JSON. Pre-fix the handlers used
// fmt.Sprintf("...%q...", ssid, ...) — strconv.Quote semantics with
// \a / \v / \xNN escapes outside JSON's {\b \f \n \r \t} whitelist.
// A spoofed SSID carrying a BEL byte (firmware scan results CAN
// contain arbitrary bytes — IEEE 802.11 SSID fields are 32 raw
// octets) produced an audit row that downstream parsers rejected.
func TestBruce_EvilTwin_HostileSSIDProducesValidJSON(t *testing.T) {
	if !bruceEvilTwinFound {
		t.Skip("bruce_evil_twin not found in registry (registry was cleared before capture)")
	}
	d := &tools.Deps{Bruce: newOKBruceClient(t)}
	// SSID with embedded BEL (\x07) — the byte that broke the audit
	// log's pre-v0.150 placeholder and would break the bruce_evil_twin
	// result too without v0.152.
	out, err := bruceEvilTwinSpec.Handler(context.Background(), d, map[string]any{
		"ssid":  "spoof\x07evil",
		"bssid": "aa:bb:cc:dd:ee:ff",
	})
	if err != nil {
		t.Fatalf("bruce_evil_twin handler error: %v", err)
	}
	var parsed map[string]any
	if jerr := json.Unmarshal([]byte(out), &parsed); jerr != nil {
		t.Fatalf("tool result is not valid JSON: %v\nresult = %q", jerr, out)
	}
	if got, _ := parsed["status"].(string); got != "evil twin started" {
		t.Errorf("status = %q, want \"evil twin started\"", got)
	}
}

// TestBruce_Deauth_HostileBSSIDProducesValidJSON: same shape for the
// bruce_wifi_deauth handler. BSSIDs from firmware scan output can
// also carry stray bytes from malformed frames, so the json.Marshal
// path must handle them.
func TestBruce_Deauth_HostileBSSIDProducesValidJSON(t *testing.T) {
	if !bruceDeauthFound {
		t.Skip("bruce_wifi_deauth not found in registry")
	}
	d := &tools.Deps{Bruce: newOKBruceClient(t)}
	// intOr only matches float64 / string for JSON-numeric inputs
	// (LLM tool calls always come in as float64). Mirror that here
	// so the handler sees a populated channel instead of the zero-
	// value rejection.
	out, err := bruceDeauthSpec.Handler(context.Background(), d, map[string]any{
		"bssid":   "aa\x0Bxx:cc:dd:ee:ff", // \x0B = VT — JSON-invalid via Go's \v
		"channel": float64(6),
	})
	if err != nil {
		t.Fatalf("bruce_wifi_deauth handler error: %v", err)
	}
	var parsed map[string]any
	if jerr := json.Unmarshal([]byte(out), &parsed); jerr != nil {
		t.Fatalf("tool result is not valid JSON: %v\nresult = %q", jerr, out)
	}
}

// TestBruce_IRSend_HostileCodeProducesValidJSON: IR codes are
// operator-supplied strings; the bruce_ir_send handler used to
// inline-format them with %q. Pin the JSON-validity contract here.
func TestBruce_IRSend_HostileCodeProducesValidJSON(t *testing.T) {
	if !bruceIRSendFound {
		t.Skip("bruce_ir_send not found in registry")
	}
	d := &tools.Deps{Bruce: newOKBruceClient(t)}
	out, err := bruceIRSendSpec.Handler(context.Background(), d, map[string]any{
		"protocol": "NEC",
		"code":     "raw\x07with\x00nul",
	})
	if err != nil {
		t.Fatalf("bruce_ir_send handler error: %v", err)
	}
	var parsed map[string]any
	if jerr := json.Unmarshal([]byte(out), &parsed); jerr != nil {
		t.Fatalf("tool result is not valid JSON: %v\nresult = %q", jerr, out)
	}
}

// TestBruce_BadUSBRun_HostileFilenameProducesValidJSON: filenames
// passed to bruce_badusb_run originate in the operator's SD card,
// and a hand-crafted file name on a shared card could carry weird
// bytes. Pin the JSON-validity contract.
func TestBruce_BadUSBRun_HostileFilenameProducesValidJSON(t *testing.T) {
	if !bruceBadUSBRunFound {
		t.Skip("bruce_badusb_run not found in registry")
	}
	d := &tools.Deps{Bruce: newOKBruceClient(t)}
	out, err := bruceBadUSBRunSpec.Handler(context.Background(), d, map[string]any{
		"filename": "evil\x07.txt",
	})
	if err != nil {
		t.Fatalf("bruce_badusb_run handler error: %v", err)
	}
	var parsed map[string]any
	if jerr := json.Unmarshal([]byte(out), &parsed); jerr != nil {
		t.Fatalf("tool result is not valid JSON: %v\nresult = %q", jerr, out)
	}
}

// TestBruce_LoRaScan_StillProducesValidJSON covers the one bruce
// handler v0.152 did NOT migrate (it formats a float with %.3f, no
// user string), pinning that the historical behaviour stays valid
// JSON — a sentinel against a future refactor accidentally
// re-introducing %q on a string parameter here.
func TestBruce_LoRaScan_StillProducesValidJSON(t *testing.T) {
	if !bruceLoRaScanFound {
		t.Skip("bruce_lora_scan not found in registry")
	}
	d := &tools.Deps{Bruce: newOKBruceClient(t)}
	out, err := bruceLoRaScanSpec.Handler(context.Background(), d, map[string]any{
		"frequency_mhz": 433.92,
	})
	if err != nil {
		t.Fatalf("bruce_lora_scan handler error: %v", err)
	}
	var parsed map[string]any
	if jerr := json.Unmarshal([]byte(out), &parsed); jerr != nil {
		t.Fatalf("tool result is not valid JSON: %v\nresult = %q", jerr, out)
	}
}
