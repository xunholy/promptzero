package lacp

import (
	"strings"
	"testing"
)

func TestDecode_FullLACPDU(t *testing.T) {
	// Subtype=1 LACP, Version=1.
	// Actor (T=1 L=20):  SysPri=100, SysID=00:11:22:33:44:55,
	//   Key=1, PortPri=128, PortID=1, State=0x3D (Activity +
	//   Aggregation + Sync + Collecting + Distributing).
	// Partner (T=2 L=20): SysPri=100, SysID=AA:BB:CC:DD:EE:FF,
	//   Key=1, PortPri=128, PortID=1, State=0x3D.
	// Collector (T=3 L=16): MaxDelay=0x8000.
	// Terminator (T=0 L=0).
	in := "01 01" +
		"01 14 0064 001122334455 0001 0080 0001 3D 000000" +
		"02 14 0064 AABBCCDDEEFF 0001 0080 0001 3D 000000" +
		"03 10 8000 000000000000000000000000" +
		"00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Subtype != 1 || r.SubtypeName != "LACP" {
		t.Errorf("subtype: %d %q", r.Subtype, r.SubtypeName)
	}
	if r.Version != 1 {
		t.Errorf("version: %d", r.Version)
	}
	if len(r.TLVs) != 4 {
		t.Fatalf("TLVs: %d", len(r.TLVs))
	}

	// Actor.
	a := r.TLVs[0].Actor
	if a == nil {
		t.Fatal("Actor nil")
	}
	if a.SystemPriority != 100 {
		t.Errorf("actor SystemPriority: %d", a.SystemPriority)
	}
	if a.SystemID != "00:11:22:33:44:55" {
		t.Errorf("actor SystemID: %q", a.SystemID)
	}
	if a.Key != 1 || a.PortPriority != 128 || a.PortID != 1 {
		t.Errorf("actor key/port: %+v", a)
	}
	if a.State != 0x3D {
		t.Errorf("actor state: 0x%02X", a.State)
	}
	if !a.StateFlags.LACPActivity || a.StateFlags.LACPTimeout {
		t.Errorf("actor activity/timeout: %+v", a.StateFlags)
	}
	if !a.StateFlags.Aggregation || !a.StateFlags.Synchronization ||
		!a.StateFlags.Collecting || !a.StateFlags.Distributing {
		t.Errorf("actor aggregation flags: %+v", a.StateFlags)
	}
	if a.StateFlags.Defaulted || a.StateFlags.Expired {
		t.Errorf("actor stale flags set: %+v", a.StateFlags)
	}

	// Partner.
	p := r.TLVs[1].Partner
	if p == nil {
		t.Fatal("Partner nil")
	}
	if p.SystemID != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("partner SystemID: %q", p.SystemID)
	}

	// Collector.
	c := r.TLVs[2].Collector
	if c == nil {
		t.Fatal("Collector nil")
	}
	if c.MaxDelay != 0x8000 {
		t.Errorf("collector MaxDelay: %d", c.MaxDelay)
	}
	if c.MaxDelayMicros != 0x8000*10 {
		t.Errorf("collector micros: %d", c.MaxDelayMicros)
	}

	// Terminator.
	if r.TLVs[3].Type != 0 || r.TLVs[3].TypeName != "Terminator" {
		t.Errorf("terminator: %+v", r.TLVs[3])
	}
}

func TestDecode_AllStateBitsSet(t *testing.T) {
	// State = 0xFF — every bit set.
	in := "01 01" +
		"01 14 0064 001122334455 0001 0080 0001 FF 000000" +
		"00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := r.TLVs[0].Actor
	if !a.StateFlags.LACPActivity || !a.StateFlags.LACPTimeout ||
		!a.StateFlags.Aggregation || !a.StateFlags.Synchronization ||
		!a.StateFlags.Collecting || !a.StateFlags.Distributing ||
		!a.StateFlags.Defaulted || !a.StateFlags.Expired {
		t.Errorf("expected all state flags set: %+v", a.StateFlags)
	}
}

func TestDecode_PassiveLongTimeout(t *testing.T) {
	// State = 0x00 — Passive, Long timeout, Individual.
	in := "01 01" +
		"01 14 0064 001122334455 0001 0080 0001 00 000000" +
		"00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := r.TLVs[0].Actor
	if a.StateFlags.LACPActivity {
		t.Errorf("Activity should be Passive: %+v", a.StateFlags)
	}
	if a.StateFlags.LACPTimeout {
		t.Errorf("Timeout should be Long: %+v", a.StateFlags)
	}
	if a.StateFlags.Aggregation {
		t.Errorf("Aggregation should be Individual: %+v", a.StateFlags)
	}
}

func TestDecode_MarkerSubtype_Note(t *testing.T) {
	// Subtype=2 (Marker Protocol).
	in := "02 01"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.SubtypeName != "Marker" {
		t.Errorf("subtype name: %q", r.SubtypeName)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "Marker") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Marker note in: %v", r.Notes)
	}
}

func TestDecode_UnsupportedSubtype(t *testing.T) {
	// Subtype=0x0A (not LACP or Marker).
	in := "0A 01"
	_, err := Decode(in)
	if err == nil {
		t.Fatal("expected error for unsupported subtype")
	}
}

func TestDecode_SubtypeNameTable(t *testing.T) {
	cases := map[int]string{
		1: "LACP",
		2: "Marker",
	}
	for k, v := range cases {
		if got := subtypeName(k); got != v {
			t.Errorf("subtypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_TLVTypeTable(t *testing.T) {
	cases := map[int]string{
		0: "Terminator",
		1: "Actor Information",
		2: "Partner Information",
		3: "Collector Information",
	}
	for k, v := range cases {
		if got := typeName(k); got != v {
			t.Errorf("typeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_StateFlagsBitMapping(t *testing.T) {
	cases := map[byte]string{
		0x01: "LACPActivity",
		0x02: "LACPTimeout",
		0x04: "Aggregation",
		0x08: "Synchronization",
		0x10: "Collecting",
		0x20: "Distributing",
		0x40: "Defaulted",
		0x80: "Expired",
	}
	for raw, name := range cases {
		f := decodeStateFlags(raw)
		switch name {
		case "LACPActivity":
			if !f.LACPActivity {
				t.Errorf("0x%02X expected %s", raw, name)
			}
		case "LACPTimeout":
			if !f.LACPTimeout {
				t.Errorf("0x%02X expected %s", raw, name)
			}
		case "Aggregation":
			if !f.Aggregation {
				t.Errorf("0x%02X expected %s", raw, name)
			}
		case "Synchronization":
			if !f.Synchronization {
				t.Errorf("0x%02X expected %s", raw, name)
			}
		case "Collecting":
			if !f.Collecting {
				t.Errorf("0x%02X expected %s", raw, name)
			}
		case "Distributing":
			if !f.Distributing {
				t.Errorf("0x%02X expected %s", raw, name)
			}
		case "Defaulted":
			if !f.Defaulted {
				t.Errorf("0x%02X expected %s", raw, name)
			}
		case "Expired":
			if !f.Expired {
				t.Errorf("0x%02X expected %s", raw, name)
			}
		}
	}
}

func TestDecode_TruncatedTLV(t *testing.T) {
	// Actor TLV claims length 20 but body is short.
	in := "01 01 01 14 0064 0011"
	_, err := Decode(in)
	if err == nil {
		t.Fatal("expected error for truncated Actor body")
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":     "",
		"odd hex":   "0101 0",
		"too short": "01",
		"bad hex":   "ZZ 01",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
