package zigbee

import (
	"strings"
	"testing"
)

// TestDecodeAPS_DataUnicastHappyPath pins a typical Home
// Automation data frame.
//
//	FC = 0x40 (Frame Type=Data=00, Delivery=Unicast=00,
//	            AckRequest=1 (bit 6), no Security, no Ext)
//	Dest EP = 0x01
//	Cluster ID = 0x0006 (On/Off cluster) → wire LE 06 00
//	Profile ID = 0x0104 (HA) → wire LE 04 01
//	Source EP = 0x01
//	APS Counter = 0xAB
//	Payload: 01 00 02 (ZCL header + read attribute)
func TestDecodeAPS_DataUnicastHappyPath(t *testing.T) {
	got, err := DecodeAPS("40 01 06 00 04 01 01 AB 01 00 02")
	if err != nil {
		t.Fatalf("DecodeAPS: %v", err)
	}
	if got.FrameControl.FrameTypeName != "Data" {
		t.Errorf("FrameTypeName = %q; want 'Data'", got.FrameControl.FrameTypeName)
	}
	if got.FrameControl.DeliveryModeName != "Unicast" {
		t.Errorf("DeliveryModeName = %q", got.FrameControl.DeliveryModeName)
	}
	if !got.FrameControl.AckRequest {
		t.Error("AckRequest should be true")
	}
	if got.DestinationEndpoint == nil || *got.DestinationEndpoint != 1 {
		t.Errorf("DestinationEndpoint = %v; want 1", got.DestinationEndpoint)
	}
	if got.ClusterID != "0006" {
		t.Errorf("ClusterID = %q; want '0006' (On/Off)", got.ClusterID)
	}
	if got.ProfileID != "0104" {
		t.Errorf("ProfileID = %q; want '0104'", got.ProfileID)
	}
	if got.ProfileName != "Home Automation (HA)" {
		t.Errorf("ProfileName = %q; want HA", got.ProfileName)
	}
	if got.SourceEndpoint == nil || *got.SourceEndpoint != 1 {
		t.Errorf("SourceEndpoint = %v", got.SourceEndpoint)
	}
	if got.APSCounter != 0xAB {
		t.Errorf("APSCounter = 0x%X; want 0xAB", got.APSCounter)
	}
	if got.PayloadHex != "010002" {
		t.Errorf("PayloadHex = %q; want '010002'", got.PayloadHex)
	}
}

// TestDecodeAPS_GroupDelivery pins the group-delivery path —
// the destination endpoint is replaced by a 2-byte group address.
//
//	FC: Data + Group delivery (0x0C) + AckRequest (0x40) = 0x4C
//	GroupAddr = 0x1234 LE → 34 12
//	ClusterID = 0x0006 → 06 00
//	ProfileID = 0x0104 → 04 01
//	SrcEP = 0x05
//	APSCounter = 0x01
func TestDecodeAPS_GroupDelivery(t *testing.T) {
	got, err := DecodeAPS("4C 34 12 06 00 04 01 05 01")
	if err != nil {
		t.Fatalf("DecodeAPS: %v", err)
	}
	if got.FrameControl.DeliveryModeName != "Group" {
		t.Errorf("DeliveryModeName = %q; want 'Group'", got.FrameControl.DeliveryModeName)
	}
	if got.GroupAddress != "1234" {
		t.Errorf("GroupAddress = %q; want '1234'", got.GroupAddress)
	}
	if got.DestinationEndpoint != nil {
		t.Errorf("DestinationEndpoint should be nil for Group delivery; got %v",
			got.DestinationEndpoint)
	}
}

// TestDecodeAPS_CommandFrame — APS Command frames skip the
// addressing fields.
//
//	FC: Command = 01 + Unicast (00) = byte 0x01
//	APSCounter = 0xFF
//	Payload: 03 (Transport Key command)
func TestDecodeAPS_CommandFrame(t *testing.T) {
	got, err := DecodeAPS("01 FF 03")
	if err != nil {
		t.Fatalf("DecodeAPS: %v", err)
	}
	if got.FrameControl.FrameTypeName != "APS Command" {
		t.Errorf("FrameTypeName = %q", got.FrameControl.FrameTypeName)
	}
	if got.DestinationEndpoint != nil || got.ClusterID != "" || got.ProfileID != "" {
		t.Errorf("APS Command should have no addressing; got DE=%v CID=%q PID=%q",
			got.DestinationEndpoint, got.ClusterID, got.ProfileID)
	}
	if got.APSCounter != 0xFF {
		t.Errorf("APSCounter = 0x%X; want 0xFF", got.APSCounter)
	}
	if got.PayloadHex != "03" {
		t.Errorf("PayloadHex = %q", got.PayloadHex)
	}
}

// TestDecodeAPS_AcknowledgeFrame pins APS ACK decode (carries
// addressing same as the Data frame it ACKs).
//
//	FC: Acknowledge = 02 (bits 1..0)
//	    Delivery = Unicast (00, bits 3..2)
//	    AckFormat = 0 (data ACK)
//	    Combined: 0x02
//	Dest EP, Cluster, Profile, Source EP, APS Counter
func TestDecodeAPS_AcknowledgeFrame(t *testing.T) {
	got, err := DecodeAPS("02 01 06 00 04 01 01 AB")
	if err != nil {
		t.Fatalf("DecodeAPS: %v", err)
	}
	if got.FrameControl.FrameTypeName != "Acknowledge" {
		t.Errorf("FrameTypeName = %q", got.FrameControl.FrameTypeName)
	}
	if got.FrameControl.AckFormat {
		t.Error("AckFormat should be false (data ACK)")
	}
	if got.DestinationEndpoint == nil || *got.DestinationEndpoint != 1 {
		t.Errorf("DestinationEndpoint = %v", got.DestinationEndpoint)
	}
}

// TestDecodeAPS_SecurityFlag — the security flag pulls in the
// aux security header (sized via the security control byte).
func TestDecodeAPS_SecurityFlag(t *testing.T) {
	// FC: Data + Unicast + Security (bit 5 = 0x20) = 0x20.
	// Standard Data headers: DE=01 CID=0006 PID=0104 SE=01 Counter=AB.
	// Aux security header: SecCtrl=0x08 (KeyID=1=network, no extended nonce)
	// → header length = 1 + 4 + 1 = 6 bytes.
	// Payload: AA BB
	hex := "20 01 06 00 04 01 01 AB " +
		"08 01 02 03 04 00 " + // SecCtrl + Frame Counter + Key Seq
		"AA BB"
	got, err := DecodeAPS(hex)
	if err != nil {
		t.Fatalf("DecodeAPS: %v", err)
	}
	if !got.FrameControl.Security {
		t.Error("Security flag should be true")
	}
	if got.AuxSecurityHeaderHex == "" {
		t.Error("AuxSecurityHeaderHex should be populated")
	}
	if got.PayloadHex != "AABB" {
		t.Errorf("PayloadHex = %q; want 'AABB'", got.PayloadHex)
	}
}

// TestDecodeAPS_ExtendedHeader — when the extended header flag
// is set, the next 3 bytes are surfaced as hex (fragmentation
// control + block number + ack bitfield).
func TestDecodeAPS_ExtendedHeader(t *testing.T) {
	// FC: Data + Unicast + Extended Header (bit 7 = 0x80) = 0x80
	// Standard Data headers + counter, then 3-byte ext header, then payload.
	hex := "80 01 06 00 04 01 01 AB " +
		"00 01 FF " + // Ext: type=0 frag, block=1, ack=0xFF
		"AA BB"
	got, err := DecodeAPS(hex)
	if err != nil {
		t.Fatalf("DecodeAPS: %v", err)
	}
	if !got.FrameControl.ExtendedHeader {
		t.Error("ExtendedHeader flag should be true")
	}
	if got.ExtendedHeaderHex != "0001FF" {
		t.Errorf("ExtendedHeaderHex = %q; want '0001FF'", got.ExtendedHeaderHex)
	}
	if got.PayloadHex != "AABB" {
		t.Errorf("PayloadHex = %q", got.PayloadHex)
	}
}

// TestDecodeAPS_ZDPProfile — Zigbee Device Profile (0x0000).
func TestDecodeAPS_ZDPProfile(t *testing.T) {
	got, err := DecodeAPS("00 00 00 00 00 00 00 01")
	if err != nil {
		t.Fatalf("DecodeAPS: %v", err)
	}
	if got.ProfileID != "0000" {
		t.Errorf("ProfileID = %q", got.ProfileID)
	}
	if got.ProfileName != "Zigbee Device Profile (ZDP)" {
		t.Errorf("ProfileName = %q", got.ProfileName)
	}
}

// TestDecodeAPS_UnknownProfile — unfamiliar profile IDs still
// decode (ProfileName empty).
func TestDecodeAPS_UnknownProfile(t *testing.T) {
	got, err := DecodeAPS("00 01 06 00 EF BE 01 AB")
	if err != nil {
		t.Fatalf("DecodeAPS: %v", err)
	}
	if got.ProfileID != "BEEF" {
		t.Errorf("ProfileID = %q; want 'BEEF'", got.ProfileID)
	}
	if got.ProfileName != "" {
		t.Errorf("ProfileName = %q; want empty for unknown", got.ProfileName)
	}
}

// TestDecodeAPS_TruncatedDestEndpoint — Data frame missing the
// destination endpoint byte.
func TestDecodeAPS_TruncatedDestEndpoint(t *testing.T) {
	_, err := DecodeAPS("00")
	if err == nil {
		t.Fatal("want error for missing dest endpoint")
	}
}

// TestDecodeAPS_TruncatedClusterID — Data frame missing cluster
// ID bytes.
func TestDecodeAPS_TruncatedClusterID(t *testing.T) {
	_, err := DecodeAPS("00 01 06")
	if err == nil {
		t.Fatal("want error for missing cluster ID")
	}
}

// TestDecodeAPS_TruncatedAPSCounter — frame ends before the APS
// counter.
func TestDecodeAPS_TruncatedAPSCounter(t *testing.T) {
	// Command frame (no addressing), but no counter byte present.
	_, err := DecodeAPS("01")
	if err == nil {
		t.Fatal("want error for missing APS counter")
	}
}

// TestDecodeAPS_EmptyAndInvalidHex — input validation.
func TestDecodeAPS_BadInput(t *testing.T) {
	if _, err := DecodeAPS(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := DecodeAPS("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecodeAPS_ToleratesSeparators — ':' / '-' / '_' /
// whitespace.
func TestDecodeAPS_ToleratesSeparators(t *testing.T) {
	base := "40 01 06 00 04 01 01 AB 01 00 02"
	for _, sep := range []string{":", "-", "_", " "} {
		in := strings.ReplaceAll(base, " ", sep)
		got, err := DecodeAPS(in)
		if err != nil {
			t.Errorf("sep=%q: %v", sep, err)
			continue
		}
		if got.ProfileName != "Home Automation (HA)" {
			t.Errorf("sep=%q: ProfileName = %q", sep, got.ProfileName)
		}
	}
}

// TestAPSFrameTypeNames pins the frame-type name table.
func TestAPSFrameTypeNames(t *testing.T) {
	cases := map[APSFrameType]string{
		APSFrameTypeData:        "Data",
		APSFrameTypeCommand:     "APS Command",
		APSFrameTypeAcknowledge: "Acknowledge",
		APSFrameTypeInterPAN:    "Inter-PAN APS",
	}
	for ft, want := range cases {
		if got := ft.String(); got != want {
			t.Errorf("APSFrameType(%d).String() = %q; want %q", ft, got, want)
		}
	}
}

// TestDeliveryModeNames pins the delivery-mode name table.
func TestDeliveryModeNames(t *testing.T) {
	cases := map[DeliveryMode]string{
		DeliveryModeUnicast:   "Unicast",
		DeliveryModeBroadcast: "Broadcast",
		DeliveryModeGroup:     "Group",
	}
	for dm, want := range cases {
		if got := dm.String(); got != want {
			t.Errorf("DeliveryMode(%d).String() = %q; want %q", dm, got, want)
		}
	}
}

// TestZigbeeProfilesSpotCheck cross-checks a handful of
// well-known profile IDs against the table.
func TestZigbeeProfilesSpotCheck(t *testing.T) {
	cases := map[uint16]string{
		0x0000: "Zigbee Device Profile (ZDP)",
		0x0104: "Home Automation (HA)",
		0x010A: "Smart Energy (SE)",
		0x0260: "Light Link (ZLL)",
	}
	for id, want := range cases {
		if got := zigbeeProfiles[id]; got != want {
			t.Errorf("zigbeeProfiles[0x%04X] = %q; want %q", id, got, want)
		}
	}
}
