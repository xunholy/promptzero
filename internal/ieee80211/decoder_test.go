package ieee80211

import (
	"strings"
	"testing"
)

// TestDecode_BeaconFrame_BasicSSID pins a minimal beacon frame.
//
//	Frame Control: 0x8000 (Type=Mgmt=0, Subtype=8=Beacon)
//	  → wire bytes 80 00
//	Duration: 0000
//	DA (broadcast): FF FF FF FF FF FF
//	SA: 00 11 22 33 44 55
//	BSSID: 00 11 22 33 44 55
//	Sequence Control: 0x0010 (seq 1) → wire 10 00
//	Body:
//	  Timestamp (8 bytes): all zero
//	  Beacon Interval: 0x0064 → wire 64 00 (100 TU)
//	  Capabilities: 0x0001 (ESS) → wire 01 00
//	  IE: SSID "TestAP" → ID=0, len=6, "TestAP"
//	  IE: DS Parameter Set channel 6 → ID=3, len=1, 06
func TestDecode_BeaconFrame_BasicSSID(t *testing.T) {
	hex := "80 00 " + // FC
		"00 00 " + // Duration
		"FF FF FF FF FF FF " + // DA
		"00 11 22 33 44 55 " + // SA
		"00 11 22 33 44 55 " + // BSSID
		"10 00 " + // SeqControl
		"00 00 00 00 00 00 00 00 " + // Timestamp
		"64 00 " + // Beacon Interval
		"01 00 " + // Capabilities (ESS)
		"00 06 54 65 73 74 41 50 " + // SSID "TestAP"
		"03 01 06" // DS Param channel 6
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FrameControl.SubtypeName != "Beacon" {
		t.Errorf("SubtypeName = %q; want 'Beacon'", got.FrameControl.SubtypeName)
	}
	if got.FrameControl.TypeName != "Management" {
		t.Errorf("TypeName = %q", got.FrameControl.TypeName)
	}
	if got.DA != "FF:FF:FF:FF:FF:FF" {
		t.Errorf("DA = %q; want broadcast", got.DA)
	}
	if got.BSSID != "00:11:22:33:44:55" {
		t.Errorf("BSSID = %q", got.BSSID)
	}
	if got.SequenceNumber != 1 {
		t.Errorf("SequenceNumber = %d; want 1", got.SequenceNumber)
	}
	if got.BeaconInterval == nil || *got.BeaconInterval != 100 {
		t.Errorf("BeaconInterval = %v; want 100", got.BeaconInterval)
	}
	if got.Capabilities == nil || !got.Capabilities.ESS {
		t.Errorf("Capabilities.ESS = false; want true")
	}
	if len(got.InformationElements) != 2 {
		t.Fatalf("IEs count = %d; want 2", len(got.InformationElements))
	}
	// SSID IE
	if got.InformationElements[0].Name != "SSID" {
		t.Errorf("IE[0].Name = %q", got.InformationElements[0].Name)
	}
	if got.InformationElements[0].Decoded["ssid"] != "TestAP" {
		t.Errorf("SSID = %v; want 'TestAP'", got.InformationElements[0].Decoded["ssid"])
	}
	// DS Param IE
	if got.InformationElements[1].Decoded["channel"] != 6 {
		t.Errorf("channel = %v; want 6", got.InformationElements[1].Decoded["channel"])
	}
}

// TestDecode_BeaconWithRSN exercises the RSN IE decoder —
// WPA2/WPA3 carries the cipher suite info here.
func TestDecode_BeaconWithRSN(t *testing.T) {
	hex := "80 00 " +
		"00 00 " +
		"FF FF FF FF FF FF " +
		"00 11 22 33 44 55 " +
		"00 11 22 33 44 55 " +
		"00 00 " +
		"00 00 00 00 00 00 00 00 " +
		"64 00 " +
		"11 04 " + // Capabilities (ESS + Privacy)
		"00 03 41 50 31 " + // SSID "AP1"
		// RSN IE (ID 48 = 0x30, len 20):
		//   version 0001
		//   group cipher 00 0F AC 04 (CCMP)
		//   pairwise count 0001
		//   pairwise 00 0F AC 04 (CCMP)
		//   AKM count 0001
		//   AKM 00 0F AC 02 (PSK)
		//   RSN capabilities 0000
		"30 14 " +
		"01 00 " +
		"00 0F AC 04 " +
		"01 00 " +
		"00 0F AC 04 " +
		"01 00 " +
		"00 0F AC 02 " +
		"00 00"
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Capabilities.Privacy {
		t.Error("Capabilities.Privacy = false; want true (Privacy bit set)")
	}
	// Find the RSN IE
	var rsn *InformationElement
	for i := range got.InformationElements {
		if got.InformationElements[i].ID == 48 {
			rsn = &got.InformationElements[i]
			break
		}
	}
	if rsn == nil {
		t.Fatal("RSN IE not found")
	}
	if rsn.Decoded["version"] != 1 {
		t.Errorf("RSN version = %v; want 1", rsn.Decoded["version"])
	}
	if rsn.Decoded["pairwise_count"] != 1 {
		t.Errorf("pairwise_count = %v; want 1", rsn.Decoded["pairwise_count"])
	}
	if rsn.Decoded["akm_count"] != 1 {
		t.Errorf("akm_count = %v; want 1", rsn.Decoded["akm_count"])
	}
}

// TestDecode_ProbeRequest — subtype 4 has no fixed body, just
// IEs (SSID + Supported Rates).
func TestDecode_ProbeRequest(t *testing.T) {
	hex := "40 00 " + // FC (Type=0, Subtype=4)
		"00 00 " +
		"FF FF FF FF FF FF " +
		"00 11 22 33 44 55 " +
		"FF FF FF FF FF FF " +
		"00 00 " +
		"00 04 57 69 46 69 " + // SSID "WiFi"
		"01 04 82 84 8B 96" // Supported Rates (4 entries, all basic)
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FrameControl.SubtypeName != "Probe Request" {
		t.Errorf("SubtypeName = %q", got.FrameControl.SubtypeName)
	}
	if got.InformationElements[0].Decoded["ssid"] != "WiFi" {
		t.Errorf("SSID = %v", got.InformationElements[0].Decoded["ssid"])
	}
	rates, ok := got.InformationElements[1].Decoded["rates"].([]string)
	if !ok || len(rates) != 4 {
		t.Errorf("rates = %v; want 4 entries", got.InformationElements[1].Decoded)
	}
}

// TestDecode_DeauthFrame surfaces the reason code with its
// documented name.
func TestDecode_DeauthFrame(t *testing.T) {
	hex := "C0 00 " + // FC (Type=0, Subtype=12=Deauth)
		"00 00 " +
		"AA BB CC DD EE FF " +
		"00 11 22 33 44 55 " +
		"00 11 22 33 44 55 " +
		"00 00 " +
		"04 00" // Reason code 4 = Disassociated due to inactivity
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FrameControl.SubtypeName != "Deauthentication" {
		t.Errorf("SubtypeName = %q", got.FrameControl.SubtypeName)
	}
	if got.ReasonCode == nil || *got.ReasonCode != 4 {
		t.Errorf("ReasonCode = %v; want 4", got.ReasonCode)
	}
	if !strings.Contains(got.ReasonCodeName, "inactivity") {
		t.Errorf("ReasonCodeName = %q; want 'inactivity' wording", got.ReasonCodeName)
	}
}

// TestDecode_AuthenticationFrame exercises the auth subtype
// decode (auth algorithm + sequence + status code).
func TestDecode_AuthenticationFrame(t *testing.T) {
	hex := "B0 00 " + // FC (Type=0, Subtype=11=Auth)
		"00 00 " +
		"00 11 22 33 44 55 " +
		"AA BB CC DD EE FF " +
		"00 11 22 33 44 55 " +
		"00 00 " +
		"00 00 " + // Auth algorithm: Open System
		"01 00 " + // Auth sequence: 1
		"00 00" // Status code: 0 = success
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.AuthAlgorithm == nil || *got.AuthAlgorithm != 0 {
		t.Errorf("AuthAlgorithm = %v; want 0 (Open System)", got.AuthAlgorithm)
	}
	if got.AuthSequence == nil || *got.AuthSequence != 1 {
		t.Errorf("AuthSequence = %v; want 1", got.AuthSequence)
	}
	if got.StatusCode == nil || *got.StatusCode != 0 {
		t.Errorf("StatusCode = %v; want 0", got.StatusCode)
	}
}

// TestDecode_FrameControlFlags pins all the flag bits via a
// fabricated frame with every flag set.
func TestDecode_FrameControlFlags(t *testing.T) {
	// FC = 0xFFFF (every flag + max type/subtype). Wire LE = FF FF.
	hex := "FF FF " +
		"00 00 " +
		strings.Repeat("00 ", 6) + // DA
		strings.Repeat("00 ", 6) + // SA
		strings.Repeat("00 ", 6) + // BSSID
		"00 00" // SeqControl
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	fc := got.FrameControl
	if !fc.ToDS || !fc.FromDS || !fc.MoreFragments || !fc.Retry ||
		!fc.PowerManagement || !fc.MoreData || !fc.ProtectedFrame || !fc.Order {
		t.Errorf("not all flags set: %+v", fc)
	}
}

// TestDecode_NonManagementFrameOnlyHeader — Data frame (Type=2)
// returns the MAC header without trying to walk the body.
func TestDecode_NonManagementFrameOnlyHeader(t *testing.T) {
	// FC = 0x0008 — Type=2 (Data), Subtype=0 (Data). Wire LE 08 00.
	hex := "08 00 00 00 " +
		strings.Repeat("00 ", 6) + // DA
		strings.Repeat("00 ", 6) + // SA
		strings.Repeat("00 ", 6) + // BSSID
		"00 00"
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FrameControl.TypeName != "Data" {
		t.Errorf("TypeName = %q", got.FrameControl.TypeName)
	}
	if got.Capabilities != nil || got.BeaconInterval != nil {
		t.Errorf("non-mgmt frame should have no body fields")
	}
}

// TestDecode_VendorSpecificMicrosoftWPS exercises the vendor IE
// decoder for the OUI 00-50-F2 type 4 (WPS).
func TestDecode_VendorSpecificMicrosoftWPS(t *testing.T) {
	// Beacon header (24 bytes) + body (TS+BI+Caps + Vendor IE)
	hex := "80 00 " +
		"00 00 " +
		strings.Repeat("00 ", 6) +
		strings.Repeat("00 ", 6) +
		strings.Repeat("00 ", 6) +
		"00 00 " +
		strings.Repeat("00 ", 8) +
		"64 00 " +
		"00 00 " +
		// Vendor IE (ID 221 = 0xDD, len 5): OUI 00-50-F2, type 4, 1 data byte
		"DD 05 00 50 F2 04 AA"
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.InformationElements) != 1 {
		t.Fatalf("IEs count = %d; want 1", len(got.InformationElements))
	}
	v := got.InformationElements[0].Decoded
	if v["microsoft_subtype"] != "WPS" {
		t.Errorf("microsoft_subtype = %v; want 'WPS'", v["microsoft_subtype"])
	}
	if v["vendor"] != "Microsoft (WPA / WPS)" {
		t.Errorf("vendor = %v", v["vendor"])
	}
}

// TestDecode_TruncatedFrame — frame shorter than 24-byte MAC
// header is rejected.
func TestDecode_TruncatedFrame(t *testing.T) {
	_, err := Decode("80 00 00 00")
	if err == nil {
		t.Fatal("want error for truncated frame")
	}
}

// TestDecode_BadInput — empty / invalid hex.
func TestDecode_BadInput(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecode_ToleratesSeparators — ':' / '-' / '_' / whitespace.
func TestDecode_ToleratesSeparators(t *testing.T) {
	beaconBase := "80 00 00 00 " +
		strings.Repeat("FF ", 6) +
		strings.Repeat("00 ", 6) +
		strings.Repeat("00 ", 6) +
		"00 00 " +
		strings.Repeat("00 ", 8) +
		"64 00 01 00 " +
		"00 03 41 50 31"
	for _, sep := range []string{":", "-", "_", " "} {
		in := strings.ReplaceAll(beaconBase, " ", sep)
		got, err := Decode(in)
		if err != nil {
			t.Errorf("sep=%q: %v", sep, err)
			continue
		}
		if got.InformationElements[0].Decoded["ssid"] != "AP1" {
			t.Errorf("sep=%q: SSID = %v", sep, got.InformationElements[0].Decoded["ssid"])
		}
	}
}

// TestSubtypeNames spot-checks the mgmt-subtype table.
func TestSubtypeNames(t *testing.T) {
	cases := map[int]string{
		0:  "Association Request",
		4:  "Probe Request",
		5:  "Probe Response",
		8:  "Beacon",
		10: "Disassociation",
		11: "Authentication",
		12: "Deauthentication",
	}
	for st, want := range cases {
		if got := subtypeName(0, st); got != want {
			t.Errorf("subtypeName(mgmt, %d) = %q; want %q", st, got, want)
		}
	}
}

// TestReasonCodes spot-checks the reason code table.
func TestReasonCodes(t *testing.T) {
	cases := map[int]string{
		1:  "Unspecified reason",
		4:  "Disassociated due to inactivity",
		15: "4-Way Handshake timeout",
	}
	for rc, want := range cases {
		if got := reasonCodeName(rc); got != want {
			t.Errorf("reasonCodeName(%d) = %q; want %q", rc, got, want)
		}
	}
}

// makeDataFrame builds a minimal 802.11 data frame header with the given DS bits
// and four distinct addresses (Addr4 appended only for the WDS case), so the
// address-resolution table can be checked end-to-end.
func makeDataFrame(toDS, fromDS, wds bool) []byte {
	var flags byte
	if toDS {
		flags |= 0x01
	}
	if fromDS {
		flags |= 0x02
	}
	b := []byte{0x08, flags, 0x00, 0x00} // FC (type=2 data, subtype=0) + Duration
	a1 := []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	a2 := []byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22}
	a3 := []byte{0x33, 0x33, 0x33, 0x33, 0x33, 0x33}
	b = append(b, a1...)
	b = append(b, a2...)
	b = append(b, a3...)
	b = append(b, 0x00, 0x10) // Sequence Control
	if wds {
		b = append(b, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44) // Address 4
	}
	return b
}

func TestResolveAddresses_DSBits(t *testing.T) {
	const (
		a1 = "11:11:11:11:11:11"
		a2 = "22:22:22:22:22:22"
		a3 = "33:33:33:33:33:33"
		a4 = "44:44:44:44:44:44"
	)
	cases := []struct {
		name              string
		toDS, fromDS, wds bool
		da, sa, bssid     string
	}{
		{"ibss/mgmt 00", false, false, false, a1, a2, a3},
		{"from-DS 01", false, true, false, a1, a3, a2},
		{"to-DS 10", true, false, false, a3, a2, a1},
		{"wds 11", true, true, true, a3, a4, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := DecodeBytes(makeDataFrame(c.toDS, c.fromDS, c.wds))
			if err != nil {
				t.Fatalf("DecodeBytes: %v", err)
			}
			if f.DA != c.da || f.SA != c.sa || f.BSSID != c.bssid {
				t.Errorf("DA/SA/BSSID = %q/%q/%q, want %q/%q/%q", f.DA, f.SA, f.BSSID, c.da, c.sa, c.bssid)
			}
			// RA / TA are always Address 1 / Address 2.
			if f.RA != a1 || f.TA != a2 {
				t.Errorf("RA/TA = %q/%q, want %q/%q", f.RA, f.TA, a1, a2)
			}
		})
	}
}
