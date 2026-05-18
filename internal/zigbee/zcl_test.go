package zigbee

import (
	"strings"
	"testing"
)

// TestDecodeZCL_ProfileWideReadAttributes pins a typical
// profile-wide Read Attributes command.
//
//	FC: Profile-wide (00) + Client→Server (dir=0) = 0x00
//	TSN: 0x42
//	Command: 0x00 (Read Attributes)
//	Payload: 04 00 05 00 (attribute IDs 0x0004 + 0x0005 LE)
func TestDecodeZCL_ProfileWideReadAttributes(t *testing.T) {
	got, err := DecodeZCL("00 42 00 04 00 05 00")
	if err != nil {
		t.Fatalf("DecodeZCL: %v", err)
	}
	if got.FrameControl.FrameTypeName != "Profile-wide" {
		t.Errorf("FrameTypeName = %q; want 'Profile-wide'", got.FrameControl.FrameTypeName)
	}
	if got.FrameControl.DirectionName != "Client → Server" {
		t.Errorf("DirectionName = %q", got.FrameControl.DirectionName)
	}
	if got.TransactionSequenceNumber != 0x42 {
		t.Errorf("TransactionSequenceNumber = 0x%X; want 0x42",
			got.TransactionSequenceNumber)
	}
	if got.CommandID != 0x00 {
		t.Errorf("CommandID = 0x%X; want 0x00", got.CommandID)
	}
	if got.CommandName != "Read Attributes" {
		t.Errorf("CommandName = %q; want 'Read Attributes'", got.CommandName)
	}
	if got.PayloadHex != "04000500" {
		t.Errorf("PayloadHex = %q", got.PayloadHex)
	}
}

// TestDecodeZCL_ReportAttributes pins the Report Attributes
// command (the unsolicited push from server to client when a
// reported attribute changes).
func TestDecodeZCL_ReportAttributes(t *testing.T) {
	// FC: Profile-wide + Server→Client (dir=1, bit 3 = 0x08) = 0x08
	// TSN 0x10, command 0x0A (Report Attributes), payload
	got, err := DecodeZCL("08 10 0A 00 00 20 32")
	if err != nil {
		t.Fatalf("DecodeZCL: %v", err)
	}
	if got.FrameControl.DirectionName != "Server → Client" {
		t.Errorf("DirectionName = %q", got.FrameControl.DirectionName)
	}
	if got.CommandID != 0x0A {
		t.Errorf("CommandID = 0x%X; want 0x0A", got.CommandID)
	}
	if got.CommandName != "Report Attributes" {
		t.Errorf("CommandName = %q", got.CommandName)
	}
}

// TestDecodeZCL_DefaultResponse — the catch-all status reply
// (command 0x0B).
func TestDecodeZCL_DefaultResponse(t *testing.T) {
	// FC: Profile-wide + Server→Client + DisableDefaultResponse
	// (bit 4 = 0x10) = 0x18
	// TSN 0x55, command 0x0B (Default Response), payload =
	// command_being_responded_to (1) + status (1)
	got, err := DecodeZCL("18 55 0B 00 00")
	if err != nil {
		t.Fatalf("DecodeZCL: %v", err)
	}
	if !got.FrameControl.DisableDefaultResponse {
		t.Error("DisableDefaultResponse should be true")
	}
	if got.CommandName != "Default Response" {
		t.Errorf("CommandName = %q", got.CommandName)
	}
}

// TestDecodeZCL_ManufacturerSpecific exercises the
// manufacturer-code path. FC bit 2 = 0x04 set; 2-byte
// manufacturer code follows the FC byte.
func TestDecodeZCL_ManufacturerSpecific(t *testing.T) {
	// FC: Cluster-specific (01) + Manufacturer (0x04) = 0x05
	// Manuf code: 0x117C (Philips Hue) → wire LE 7C 11
	// TSN 0x01, command 0x00, payload
	got, err := DecodeZCL("05 7C 11 01 00 AA BB")
	if err != nil {
		t.Fatalf("DecodeZCL: %v", err)
	}
	if !got.FrameControl.ManufacturerSpecific {
		t.Error("ManufacturerSpecific should be true")
	}
	if got.ManufacturerCode != "117C" {
		t.Errorf("ManufacturerCode = %q; want '117C'", got.ManufacturerCode)
	}
	if got.TransactionSequenceNumber != 0x01 {
		t.Errorf("TSN = 0x%X; want 0x01", got.TransactionSequenceNumber)
	}
}

// TestDecodeZCL_ClusterSpecific — Cluster-specific commands
// (FC bit 0 set) don't get a CommandName because the meaning
// depends on the cluster ID, which lives in the APS layer.
func TestDecodeZCL_ClusterSpecific(t *testing.T) {
	// FC: Cluster-specific (01) + Client→Server = 0x01
	// TSN 0x03, command 0x02 (e.g. Toggle on On/Off cluster)
	got, err := DecodeZCL("01 03 02")
	if err != nil {
		t.Fatalf("DecodeZCL: %v", err)
	}
	if got.FrameControl.FrameTypeName != "Cluster-specific" {
		t.Errorf("FrameTypeName = %q", got.FrameControl.FrameTypeName)
	}
	if got.CommandID != 0x02 {
		t.Errorf("CommandID = 0x%X; want 0x02", got.CommandID)
	}
	if got.CommandName != "" {
		t.Errorf("CommandName = %q; want empty (cluster-specific has no profile-wide name)",
			got.CommandName)
	}
}

// TestDecodeZCL_ConfigureReporting pins command 0x06.
func TestDecodeZCL_ConfigureReporting(t *testing.T) {
	got, err := DecodeZCL("00 11 06 00 00 00 20 0E 00 1C 00 01 00")
	if err != nil {
		t.Fatalf("DecodeZCL: %v", err)
	}
	if got.CommandName != "Configure Reporting" {
		t.Errorf("CommandName = %q", got.CommandName)
	}
}

// TestDecodeZCL_DiscoverAttributes pins command 0x0C.
func TestDecodeZCL_DiscoverAttributes(t *testing.T) {
	got, err := DecodeZCL("00 01 0C 00 00 0A")
	if err != nil {
		t.Fatalf("DecodeZCL: %v", err)
	}
	if got.CommandName != "Discover Attributes" {
		t.Errorf("CommandName = %q", got.CommandName)
	}
}

// TestDecodeZCL_TruncatedFrame — frame shorter than 3-byte
// minimum (FC + TSN + CommandID).
func TestDecodeZCL_TruncatedFrame(t *testing.T) {
	_, err := DecodeZCL("00 42")
	if err == nil {
		t.Fatal("want error for truncated ZCL frame")
	}
}

// TestDecodeZCL_TruncatedManufacturerCode — Manufacturer
// Specific flag set but only partial manuf code present.
func TestDecodeZCL_TruncatedManufacturerCode(t *testing.T) {
	_, err := DecodeZCL("05 7C")
	if err == nil {
		t.Fatal("want error for truncated manuf code")
	}
}

// TestDecodeZCL_BadInput — empty / invalid hex.
func TestDecodeZCL_BadInput(t *testing.T) {
	if _, err := DecodeZCL(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := DecodeZCL("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecodeZCL_ToleratesSeparators — ':' / '-' / '_' /
// whitespace.
func TestDecodeZCL_ToleratesSeparators(t *testing.T) {
	base := "00 42 00 04 00 05 00"
	for _, sep := range []string{":", "-", "_", " "} {
		in := strings.ReplaceAll(base, " ", sep)
		got, err := DecodeZCL(in)
		if err != nil {
			t.Errorf("sep=%q: %v", sep, err)
			continue
		}
		if got.CommandName != "Read Attributes" {
			t.Errorf("sep=%q: CommandName = %q", sep, got.CommandName)
		}
	}
}

// TestZCLFrameTypeNames pins the frame-type name table.
func TestZCLFrameTypeNames(t *testing.T) {
	cases := map[ZCLFrameType]string{
		ZCLFrameTypeProfileWide:     "Profile-wide",
		ZCLFrameTypeClusterSpecific: "Cluster-specific",
	}
	for ft, want := range cases {
		if got := ft.String(); got != want {
			t.Errorf("ZCLFrameType(%d).String() = %q; want %q", ft, got, want)
		}
	}
}

// TestProfileWideCommands spot-checks the documented profile-
// wide command catalog.
func TestProfileWideCommands(t *testing.T) {
	cases := map[byte]string{
		0x00: "Read Attributes",
		0x01: "Read Attributes Response",
		0x0A: "Report Attributes",
		0x0B: "Default Response",
		0x0C: "Discover Attributes",
	}
	for id, want := range cases {
		if got := profileWideCommands[id]; got != want {
			t.Errorf("profileWideCommands[0x%02X] = %q; want %q", id, got, want)
		}
	}
}
