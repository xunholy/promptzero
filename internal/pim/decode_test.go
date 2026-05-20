package pim

import (
	"strings"
	"testing"
)

func TestDecode_HelloWithHoldtimeDRPriorityGenID(t *testing.T) {
	// Hello (V=2 T=0): Holdtime=105 (0x0069), DR Priority=1,
	// Generation ID=0xDEADBEEF.
	in := "20 00 ABCD" +
		"0001 0002 0069" +
		"0013 0004 00000001" +
		"0014 0004 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Hello" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.Hello == nil {
		t.Fatal("Hello body nil")
	}
	if len(r.Hello.Options) != 3 {
		t.Fatalf("expected 3 options, got %d", len(r.Hello.Options))
	}
	o := r.Hello.Options
	if o[0].TypeName != "Holdtime" || o[0].HoldtimeSeconds == nil ||
		*o[0].HoldtimeSeconds != 105 {
		t.Errorf("holdtime: %+v", o[0])
	}
	if o[1].TypeName != "DR Priority" || o[1].DRPriority == nil ||
		*o[1].DRPriority != 1 {
		t.Errorf("DR priority: %+v", o[1])
	}
	if o[2].TypeName != "Generation ID" || o[2].GenerationID == nil ||
		*o[2].GenerationID != 0xDEADBEEF {
		t.Errorf("generation ID: %+v", o[2])
	}
}

func TestDecode_HelloLANPruneDelay(t *testing.T) {
	// LAN Prune Delay: propagation_delay=50 ms (T=0),
	// override_interval=150 ms.
	in := "20 00 ABCD 0002 0004 0032 0096"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Hello == nil || len(r.Hello.Options) != 1 {
		t.Fatalf("Hello options: %+v", r.Hello)
	}
	o := r.Hello.Options[0]
	if o.TypeName != "LAN Prune Delay" {
		t.Errorf("type name: %q", o.TypeName)
	}
	if o.LANPropagationDelayMs == nil || *o.LANPropagationDelayMs != 50 {
		t.Errorf("propagation delay: %+v", o.LANPropagationDelayMs)
	}
	if o.LANOverrideIntervalMs == nil || *o.LANOverrideIntervalMs != 150 {
		t.Errorf("override interval: %+v", o.LANOverrideIntervalMs)
	}
	if o.LANTBit == nil || *o.LANTBit {
		t.Errorf("T bit: %+v", o.LANTBit)
	}
}

func TestDecode_HelloHoldtimeNeverTimeout(t *testing.T) {
	in := "20 00 ABCD 0001 0002 FFFF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(r.Hello.Options[0].HoldtimeNote, "never timeout") {
		t.Errorf("expected never-timeout note: %q",
			r.Hello.Options[0].HoldtimeNote)
	}
}

func TestDecode_Register(t *testing.T) {
	// Flags=0xC0000000 (B=1 N=1) + 4-byte IPv4 header start.
	in := "21 00 ABCD C0000000 45000028"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Register == nil {
		t.Fatal("Register body nil")
	}
	if !r.Register.FlagBorder || !r.Register.FlagNull {
		t.Errorf("flags: %+v", r.Register)
	}
	if r.Register.EncapVersion != 4 {
		t.Errorf("encap version: %d", r.Register.EncapVersion)
	}
}

func TestDecode_RegisterStop(t *testing.T) {
	// Group 239.1.2.3 mask 32 + Source 192.168.1.1.
	in := "22 00 ABCD 01 00 00 20 EF010203 01 00 C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RegisterStop == nil {
		t.Fatal("RegisterStop body nil")
	}
	if r.RegisterStop.Group.Address != "239.1.2.3" {
		t.Errorf("group: %q", r.RegisterStop.Group.Address)
	}
	if r.RegisterStop.Source.Address != "192.168.1.1" {
		t.Errorf("source: %q", r.RegisterStop.Source.Address)
	}
}

func TestDecode_JoinPrune(t *testing.T) {
	// Upstream 192.168.1.1; 1 group (239.1.2.3) with 1 joined
	// source (10.0.0.1, S-bit set) + 0 pruned; hold time 180.
	in := "23 00 ABCD" +
		"01 00 C0A80101" + // upstream
		"00 01 00B4" + // reserved + numGroups=1 + holdtime=180
		"01 00 00 20 EF010203" + // group 239.1.2.3
		"0001 0000" + // numJoined=1, numPruned=0
		"01 00 04 20 0A000001" // joined source 10.0.0.1 S=1
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.JoinPrune == nil {
		t.Fatal("JoinPrune body nil")
	}
	if r.JoinPrune.UpstreamNeighbor.Address != "192.168.1.1" {
		t.Errorf("upstream: %q", r.JoinPrune.UpstreamNeighbor.Address)
	}
	if r.JoinPrune.NumGroups != 1 || r.JoinPrune.HoldTimeSeconds != 180 {
		t.Errorf("counts: %+v", r.JoinPrune)
	}
	if len(r.JoinPrune.Groups) != 1 {
		t.Fatalf("groups: %d", len(r.JoinPrune.Groups))
	}
	g := r.JoinPrune.Groups[0]
	if g.Group.Address != "239.1.2.3" {
		t.Errorf("group addr: %q", g.Group.Address)
	}
	if g.NumJoined != 1 || g.NumPruned != 0 {
		t.Errorf("join/prune counts: %d/%d", g.NumJoined, g.NumPruned)
	}
	if len(g.JoinedSources) != 1 || g.JoinedSources[0].Address != "10.0.0.1" {
		t.Errorf("joined sources: %+v", g.JoinedSources)
	}
	if !g.JoinedSources[0].SBit {
		t.Errorf("S bit not set: %+v", g.JoinedSources[0])
	}
}

func TestDecode_Assert(t *testing.T) {
	// Group 239.1.2.3 + Source 192.168.1.1 + RPT=0 +
	// metric_pref=110 (OSPF) + metric=10.
	in := "25 00 ABCD" +
		"01 00 00 20 EF010203" +
		"01 00 C0A80101" +
		"0000006E 0000000A"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Assert == nil {
		t.Fatal("Assert body nil")
	}
	if r.Assert.Group.Address != "239.1.2.3" {
		t.Errorf("group: %q", r.Assert.Group.Address)
	}
	if r.Assert.Source.Address != "192.168.1.1" {
		t.Errorf("source: %q", r.Assert.Source.Address)
	}
	if r.Assert.RPTBit {
		t.Errorf("RPT should be clear")
	}
	if r.Assert.MetricPreference != 110 || r.Assert.Metric != 10 {
		t.Errorf("metric: pref=%d met=%d",
			r.Assert.MetricPreference, r.Assert.Metric)
	}
}

func TestDecode_Bootstrap(t *testing.T) {
	// FragmentTag=0x1234, HashMaskLen=30, BSRPriority=64,
	// BSR=10.0.0.1.
	in := "24 00 ABCD 1234 1E 40 01 00 0A000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Bootstrap == nil {
		t.Fatal("Bootstrap body nil")
	}
	if r.Bootstrap.FragmentTag != 0x1234 {
		t.Errorf("fragment tag: %d", r.Bootstrap.FragmentTag)
	}
	if r.Bootstrap.HashMaskLen != 30 {
		t.Errorf("hash mask len: %d", r.Bootstrap.HashMaskLen)
	}
	if r.Bootstrap.BSRPriority != 64 {
		t.Errorf("BSR priority: %d", r.Bootstrap.BSRPriority)
	}
	if r.Bootstrap.BSRAddress.Address != "10.0.0.1" {
		t.Errorf("BSR address: %q", r.Bootstrap.BSRAddress.Address)
	}
}

func TestDecode_TypeNameTable(t *testing.T) {
	cases := map[int]string{
		0:  "Hello",
		1:  "Register",
		2:  "Register-Stop",
		3:  "Join/Prune",
		4:  "Bootstrap",
		5:  "Assert",
		6:  "Graft",
		7:  "Graft-Ack",
		8:  "Candidate-RP-Advertisement",
		9:  "State Refresh",
		10: "DF Election",
	}
	for k, v := range cases {
		if got := typeName(k); got != v {
			t.Errorf("typeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_HelloOptionNameTable(t *testing.T) {
	cases := map[int]string{
		1:  "Holdtime",
		2:  "LAN Prune Delay",
		19: "DR Priority",
		20: "Generation ID",
		24: "Address List",
	}
	for k, v := range cases {
		if got := helloOptionName(k); got != v {
			t.Errorf("helloOptionName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_VersionNot2Note(t *testing.T) {
	// V=1 (legacy PIMv1).
	in := "10 00 ABCD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 1 {
		t.Errorf("version: %d", r.Version)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "PIMv2") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PIMv2 note in: %v", r.Notes)
	}
}

func TestDecode_UncataloguedType(t *testing.T) {
	// Type=15 (unknown).
	in := "2F 00 ABCD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(r.TypeName, "uncatalogued") {
		t.Errorf("expected uncatalogued type name, got %q", r.TypeName)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "20 00 AB",
		"short":   "20 00",
		"bad hex": "ZZ 00 ABCD",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
