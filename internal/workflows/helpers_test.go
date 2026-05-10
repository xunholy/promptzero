package workflows

import (
	"encoding/json"
	"strings"
	"testing"
)

// helpers_test.go covers the pure helper functions in
// nfc_badge.go, wifi_hashcat.go, and workflows.go that previously
// had 0 % coverage. Internal-package tests (package workflows,
// not workflows_test) so we can reach unexported functions
// directly without exporting them just for testability.

// TestSanitizeFilename pins the UID-to-SD-path sanitiser. Real
// firmware UIDs include hex digits and the occasional dash; an
// attacker-supplied UID could theoretically include slashes /
// quotes / null bytes that would otherwise break the path concat
// inside saveDetectedTag. Every non-[0-9A-Za-z_-] byte must be
// replaced with an underscore.
func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"DEADBEEF", "DEADBEEF"},
		{"ab-cd_ef", "ab-cd_ef"},
		{"deadbeef", "deadbeef"},
		{"AABB:CCDD", "AABB_CCDD"},
		{"AA/BB", "AA_BB"},
		{"AA\\BB", "AA_BB"},
		{"AA BB", "AA_BB"},
		{"AA\nBB", "AA_BB"},
		{"AA;rm -rf /", "AA_rm_-rf__"},
		{"", "unknown"},
		{"//", "__"},
		{"日本語", "___"},
	}
	for _, tc := range tests {
		if got := sanitizeFilename(tc.in); got != tc.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestClassifyNFCSAK pins the SAK-byte → NFCFamily mapping.
// Operators read SAK off the Flipper NFC subshell ("SAK : 08")
// and the pipeline branches on family to pick which dump tool
// to run; a regression here silently routes the workflow to the
// wrong protocol.
func TestClassifyNFCSAK(t *testing.T) {
	tests := []struct {
		in   string
		want NFCFamily
	}{
		// Mifare Classic SAKs.
		{"08", NFCFamilyMIFAREClassic},
		{"09", NFCFamilyMIFAREClassic},
		{"18", NFCFamilyMIFAREClassic},
		{"19", NFCFamilyMIFAREClassic},
		// Casing + whitespace.
		{"  08  ", NFCFamilyMIFAREClassic},
		{"08\n", NFCFamilyMIFAREClassic},
		// Ultralight.
		{"00", NFCFamilyUltralight},
		// ISO 14443-4 (DESFire wraps this; Plus is also here).
		{"20", NFCFamilyISO14443_4},
		{"28", NFCFamilyISO14443_4},
		// Unknown / not yet classified.
		{"", NFCFamilyUnknown},
		{"FF", NFCFamilyUnknown},
		{"AA", NFCFamilyUnknown},
	}
	for _, tc := range tests {
		if got := classifyNFCSAK(tc.in); got != tc.want {
			t.Errorf("classifyNFCSAK(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestNFCFamilyName pins the human-facing labels each NFCFamily
// renders as. Used in the workflow's Summary string so a
// regression to "unknown" for a recognised family would
// confuse the operator-facing audit log.
func TestNFCFamilyName(t *testing.T) {
	tests := []struct {
		in   NFCFamily
		want string
	}{
		{NFCFamilyMIFAREClassic, "Mifare Classic"},
		{NFCFamilyUltralight, "Mifare Ultralight"},
		{NFCFamilyNTAG, "NTAG"},
		{NFCFamilyDESFire, "DESFire"},
		{NFCFamilyEMV, "EMV"},
		{NFCFamilyISO14443_4, "ISO14443-4"},
		{NFCFamilyUnknown, "unknown"},
		{NFCFamily(-1), "unknown"}, // out-of-range sentinel
	}
	for _, tc := range tests {
		if got := nfcFamilyName(tc.in); got != tc.want {
			t.Errorf("nfcFamilyName(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestMapNFCFamilyToDeviceType pins the protocol-string +
// NFCFamily → device-type mapping used by the .nfc file builder.
// Both axes need to match — first the Protocol field is checked
// for substring matches, then the Family enum kicks in as
// fallback.
func TestMapNFCFamilyToDeviceType(t *testing.T) {
	tests := []struct {
		name string
		info NFCDetectInfo
		want string
	}{
		// Protocol-string matches (case insensitive).
		{"NTAG213", NFCDetectInfo{Protocol: "NTAG213"}, "NTAG213"},
		{"NTAG215 lowercase", NFCDetectInfo{Protocol: "ntag215"}, "NTAG215"},
		{"NTAG216 mixed case", NFCDetectInfo{Protocol: "NTAG216 (Read)"}, "NTAG216"},
		{"Ultralight", NFCDetectInfo{Protocol: "Mifare Ultralight"}, "Mifare Ultralight"},
		{"Classic", NFCDetectInfo{Protocol: "Mifare Classic 1K"}, "Mifare Classic"},
		{"DESFire", NFCDetectInfo{Protocol: "Mifare DESFire EV1"}, "Mifare DESFire"},
		{"Plus", NFCDetectInfo{Protocol: "Mifare Plus X 4K"}, "Mifare Plus"},
		// Family fallback when Protocol is empty / unrecognised.
		{"family NTAG fallback", NFCDetectInfo{Family: NFCFamilyNTAG}, "NTAG215"},
		{"family Ultralight fallback", NFCDetectInfo{Family: NFCFamilyUltralight}, "Mifare Ultralight"},
		{"family Classic fallback", NFCDetectInfo{Family: NFCFamilyMIFAREClassic}, "Mifare Classic"},
		{"family DESFire fallback", NFCDetectInfo{Family: NFCFamilyDESFire}, "Mifare DESFire"},
		{"unknown everything", NFCDetectInfo{}, "NFC"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapNFCFamilyToDeviceType(tc.info); got != tc.want {
				t.Errorf("mapNFCFamilyToDeviceType(%+v) = %q, want %q", tc.info, got, tc.want)
			}
		})
	}
}

// TestParseMarauderAPList pins the free-form AP-list parser. The
// parser expects firmware rows where the index is followed by one
// of `]`, `)`, `.`, or `:` — see marauderAPIndexPattern. Older
// Marauder builds emit `[0] ssid=...` while newer use `0: ...`;
// the parser walks tokens after the index rather than using a
// monster regex so firmware variations don't misclassify.
func TestParseMarauderAPList(t *testing.T) {
	in := strings.Join([]string{
		"# index ssid bssid enc rssi ch",
		"0: SSID=HomeWifi BSSID=AA:BB:CC:DD:EE:FF CH=6 ENC=WPA2 RSSI=-55",
		"[1] SSID=NeighbourAP 11:22:33:44:55:66 WPA ch=1 rssi=-77",
		"2. OPEN 99:88:77:66:55:44 ch=11 rssi=-88 SSID=OfficeOpen",
		"",                              // empty line — skipped
		"badrow without bssid or index", // skipped: no index match
		"3] SSID=ExplicitName 22:33:44:55:66:77 WPA3 ch=11 rssi=-60",
	}, "\n")

	got := parseMarauderAPList(in)
	if len(got) != 4 {
		t.Fatalf("parseMarauderAPList returned %d rows, want 4: %#v", len(got), got)
	}

	// Row 0.
	if got[0].Index != 0 || got[0].BSSID != "AA:BB:CC:DD:EE:FF" || got[0].Channel != 6 ||
		got[0].RSSI != -55 || got[0].Encryption != "WPA2" || got[0].SSID != "HomeWifi" {
		t.Errorf("row 0 = %+v", got[0])
	}
	// Row 1.
	if got[1].Index != 1 || got[1].BSSID != "11:22:33:44:55:66" || got[1].Encryption != "WPA" {
		t.Errorf("row 1 = %+v", got[1])
	}
	// Row 2 (OPEN, no PMKID candidate).
	if got[2].Encryption != "OPEN" || got[2].SSID != "OfficeOpen" {
		t.Errorf("row 2 = %+v, want OPEN encryption + OfficeOpen SSID", got[2])
	}
	// Row 3 (explicit ssid= form, different layout, WPA3).
	if got[3].Index != 3 || got[3].SSID != "ExplicitName" || got[3].Encryption != "WPA3" {
		t.Errorf("row 3 = %+v", got[3])
	}
}

// TestPickStrongestWPA pins the pmkid-candidate selection: only
// WPA / WPA2 APs are eligible (no PMKID on OPEN/WEP; WPA3 / SAE
// is a different flow), and ties resolve to the strongest RSSI
// (closest to 0).
func TestPickStrongestWPA(t *testing.T) {
	aps := []marauderAP{
		{Index: 0, BSSID: "A1", Encryption: "OPEN", RSSI: -10}, // skipped
		{Index: 1, BSSID: "A2", Encryption: "WEP", RSSI: -20},  // skipped
		{Index: 2, BSSID: "A3", Encryption: "WPA3", RSSI: -30}, // skipped
		{Index: 3, BSSID: "A4", Encryption: "WPA", RSSI: -60},  // candidate, weaker
		{Index: 4, BSSID: "A5", Encryption: "WPA2", RSSI: -55}, // candidate, strongest
		{Index: 5, BSSID: "A6", Encryption: "WPA2", RSSI: -80}, // candidate, weakest
	}
	best := pickStrongestWPA(aps)
	if best == nil {
		t.Fatal("pickStrongestWPA returned nil with valid candidates")
	}
	if best.Index != 4 || best.BSSID != "A5" {
		t.Errorf("pickStrongestWPA = %+v, want Index=4 BSSID=A5", best)
	}

	// No candidates → nil.
	none := []marauderAP{
		{Index: 0, Encryption: "OPEN"},
		{Index: 1, Encryption: "WPA3"},
	}
	if got := pickStrongestWPA(none); got != nil {
		t.Errorf("pickStrongestWPA(no candidates) = %+v, want nil", got)
	}

	// Empty input → nil.
	if got := pickStrongestWPA(nil); got != nil {
		t.Errorf("pickStrongestWPA(nil) = %+v, want nil", got)
	}
}

// TestExtractSSIDTokens pins the fallback SSID extractor used
// when the AP row has no explicit `ssid=` label. The first
// non-metadata token after the BSSID is the SSID.
func TestExtractSSIDTokens(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		bssid string
		want  string
	}{
		{
			"bssid then ssid then metadata",
			"AA:BB:CC:DD:EE:FF HomeWifi ch=6 WPA2 rssi=-55",
			"AA:BB:CC:DD:EE:FF",
			"HomeWifi",
		},
		{
			"only bssid + ssid",
			"AA:BB:CC:DD:EE:FF Office",
			"AA:BB:CC:DD:EE:FF",
			"Office",
		},
		{
			"no tokens after bssid",
			"AA:BB:CC:DD:EE:FF",
			"AA:BB:CC:DD:EE:FF",
			"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractSSIDTokens(tc.line, tc.bssid); got != tc.want {
				t.Errorf("extractSSIDTokens(%q, %q) = %q, want %q", tc.line, tc.bssid, got, tc.want)
			}
		})
	}
}

// TestCancelledResult pins the partial-JSON envelope every
// long-running workflow returns when ctx fires mid-flight. The
// summary must include the "(cancelled)" suffix; NextSteps must
// contain "cancelled by user"; Phases are preserved verbatim;
// Extra is rolled into the top-level via Result.MarshalJSON.
func TestCancelledResult(t *testing.T) {
	phases := []PhaseResult{
		{Phase: "scan", Tool: "wifi_scan_ap", OK: true, Output: "found 3 APs", ElapsedMs: 1500},
		{Phase: "deauth", Tool: "wifi_deauth", OK: false, Output: "ctx cancelled", ElapsedMs: 200},
	}
	extra := map[string]interface{}{
		"target_bssid": "AA:BB:CC:DD:EE:FF",
		"channel":      6,
	}
	got := cancelledResult("wifi_hashcat", phases, extra)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("cancelledResult output is not valid JSON: %v\n%s", err, got)
	}
	if !strings.HasSuffix(parsed["summary"].(string), "(cancelled)") {
		t.Errorf("summary = %q, want suffix '(cancelled)'", parsed["summary"])
	}
	if !strings.HasPrefix(parsed["summary"].(string), "wifi_hashcat") {
		t.Errorf("summary = %q, want prefix 'wifi_hashcat'", parsed["summary"])
	}
	steps, ok := parsed["next_steps"].([]interface{})
	if !ok || len(steps) != 1 || steps[0].(string) != "cancelled by user" {
		t.Errorf("next_steps = %v, want [\"cancelled by user\"]", parsed["next_steps"])
	}
	// Extra fields rolled into top level via MarshalJSON.
	if parsed["target_bssid"] != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("extra target_bssid not rolled into top level: %v", parsed)
	}
	if got := parsed["channel"]; got != float64(6) {
		t.Errorf("extra channel = %v, want 6", got)
	}
	// Phases preserved.
	phasesParsed, ok := parsed["phases"].([]interface{})
	if !ok || len(phasesParsed) != 2 {
		t.Errorf("phases len = %d, want 2 (%v)", len(phasesParsed), parsed["phases"])
	}
}
