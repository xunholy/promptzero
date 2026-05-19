package stp

import (
	"strings"
	"testing"
)

func TestDecode_STPConfigurationBPDU(t *testing.T) {
	// 4-byte common header: Protocol=0000, Version=00, Type=00.
	// 31-byte body: Flags 00 + Root ID (priority 32768, MAC
	// 00:11:22:33:44:55) + Cost 0 + Bridge ID (same as root)
	// + Port ID priority 8 port 1 + timers (Msg Age 0,
	// Max Age 20s, Hello 2s, Fwd Delay 15s).
	in := "0000 00 00" + // header
		"00" + // flags
		"8000 001122334455" + // Root ID priority 0x8000 (32768) + MAC
		"00000000" + // Root path cost
		"8000 001122334455" + // Bridge ID (same as root)
		"8001" + // Port ID priority 8, port 1
		"0000 1400 0200 0F00" // Msg Age 0 / Max Age 20s / Hello 2s / Fwd Delay 15s
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.VersionName != "STP (IEEE 802.1D)" {
		t.Errorf("version: %q", r.VersionName)
	}
	if r.BPDUTypeName != "Configuration BPDU" {
		t.Errorf("type: %q", r.BPDUTypeName)
	}
	if r.Configuration == nil {
		t.Fatal("Configuration nil")
	}
	c := r.Configuration
	if c.RootBridgeID.Priority != 0x8000 {
		t.Errorf("root priority: 0x%X", c.RootBridgeID.Priority)
	}
	if c.RootBridgeID.MAC != "00:11:22:33:44:55" {
		t.Errorf("root MAC: %q", c.RootBridgeID.MAC)
	}
	if c.RootPathCost != 0 {
		t.Errorf("root cost: %d", c.RootPathCost)
	}
	if c.PortPriority != 8 || c.PortNumber != 1 {
		t.Errorf("port: prio=%d num=%d", c.PortPriority, c.PortNumber)
	}
	if c.MessageAgeMs != 0 {
		t.Errorf("msg age: %d", c.MessageAgeMs)
	}
	if c.MaxAgeMs != 20000 {
		t.Errorf("max age: %d", c.MaxAgeMs)
	}
	if c.HelloTimeMs != 2000 {
		t.Errorf("hello: %d", c.HelloTimeMs)
	}
	if c.ForwardDelayMs != 15000 {
		t.Errorf("fwd delay: %d", c.ForwardDelayMs)
	}
}

func TestDecode_RSTPBPDU_WithFlags(t *testing.T) {
	// Version=02 (RSTP), Type=02. Flags 0x7C =
	// 0111_1100 = Port Role=11 Designated, Learning, Forwarding,
	// Agreement.
	in := "0000 02 02" +
		"7C" + // Flags
		"8000 001122334455" +
		"00000000" +
		"8000 001122334455" +
		"8001" +
		"0000 1400 0200 0F00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.VersionName != "RSTP (IEEE 802.1D-2004)" {
		t.Errorf("version: %q", r.VersionName)
	}
	c := r.Configuration
	if c.PortRoleName != "Designated" {
		t.Errorf("port role: %q", c.PortRoleName)
	}
	wantFlags := []string{"Learning", "Forwarding", "Agreement"}
	for _, w := range wantFlags {
		found := false
		for _, f := range c.FlagsDecoded {
			if strings.Contains(f, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("flags missing %q in %v", w, c.FlagsDecoded)
		}
	}
}

func TestDecode_TCN(t *testing.T) {
	// Protocol=0000, Version=00, Type=80. Empty body.
	in := "0000 00 80"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.BPDUTypeName != "Topology Change Notification (TCN)" {
		t.Errorf("type: %q", r.BPDUTypeName)
	}
	if r.TCN == nil {
		t.Fatal("TCN nil")
	}
}

func TestDecode_TopologyChangeBit(t *testing.T) {
	// Flags 0x01 (TC bit set).
	in := "0000 00 00" +
		"01" +
		"8000 001122334455" +
		"00000000" +
		"8000 001122334455" +
		"8001" +
		"0000 1400 0200 0F00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, f := range r.Configuration.FlagsDecoded {
		if strings.Contains(f, "Topology Change") {
			found = true
		}
	}
	if !found {
		t.Errorf("TC flag should be decoded: %v",
			r.Configuration.FlagsDecoded)
	}
}

func TestDecode_BridgeIDSystemIDExtension(t *testing.T) {
	// Priority+SysExt = 0x800A → priority 0x8000 + ext 0x00A
	// (typical PVST+ for VLAN 10).
	in := "0000 00 00" +
		"00" +
		"800A 001122334455" + // Root ID with ext VLAN 10
		"00000000" +
		"800A 001122334455" +
		"8001" +
		"0000 1400 0200 0F00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	c := r.Configuration
	if c.RootBridgeID.Priority != 0x8000 {
		t.Errorf("priority: 0x%X", c.RootBridgeID.Priority)
	}
	if c.RootBridgeID.SystemIDExtension != 0x00A {
		t.Errorf("system ID ext: 0x%X", c.RootBridgeID.SystemIDExtension)
	}
}

func TestDecode_MSTPVersion3(t *testing.T) {
	// Version=03 (MSTP), Type=02. After the 31-byte config
	// body, append a trailing MSTI blob.
	in := "0000 03 02" +
		"00" +
		"8000 001122334455" +
		"00000000" +
		"8000 001122334455" +
		"8001" +
		"0000 1400 0200 0F00" +
		"00 0040 " + strings.Repeat("AB", 64) // V1 Len 0 + V3 Len 64 + MSTI body
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.VersionName != "MSTP (IEEE 802.1Q-2014 §13)" {
		t.Errorf("version: %q", r.VersionName)
	}
	if r.MSTITrailerHex == "" {
		t.Errorf("expected MSTI trailer hex")
	}
}

func TestDecode_PortRoles(t *testing.T) {
	cases := map[int]string{
		0: "Unknown / Master",
		1: "Alternate or Backup",
		2: "Root",
		3: "Designated",
	}
	for k, v := range cases {
		if got := portRoleName(k); got != v {
			t.Errorf("portRoleName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":             "",
		"odd hex":           "000000000",
		"short header":      "0000",
		"bad protocol ID":   "00010000",
		"unknown BPDU type": "00000099",
		"truncated config":  "00000000" + "0080",
		"bad hex":           "ZZ000000",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
