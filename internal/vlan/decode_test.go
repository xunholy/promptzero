package vlan

import (
	"strings"
	"testing"
)

func TestDecode_SingleQTag_IPv4(t *testing.T) {
	// 802.1Q C-tag (TPID 0x8100), PCP=0, DEI=0, VID=100, EtherType IPv4.
	in := "8100 0064 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TagCount != 1 {
		t.Fatalf("expected 1 tag, got %d", r.TagCount)
	}
	tag := r.Tags[0]
	if tag.TPIDName != "IEEE 802.1Q C-tag (Customer VLAN)" {
		t.Errorf("TPID name: %q", tag.TPIDName)
	}
	if tag.VID != 100 {
		t.Errorf("VID: %d", tag.VID)
	}
	if tag.PCP != 0 || tag.DEI {
		t.Errorf("PCP/DEI: %d / %v", tag.PCP, tag.DEI)
	}
	if r.InnerEtherName != "IPv4" {
		t.Errorf("inner ether: %q", r.InnerEtherName)
	}
	if r.IsQinQ {
		t.Errorf("should not be QinQ")
	}
}

func TestDecode_VoicePriority(t *testing.T) {
	// PCP=5 Voice, VID=200.
	// TCI = PCP<<13 | VID = 0xA000 | 0x00C8 = 0xA0C8.
	in := "8100 A0C8 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Tags[0].PCP != 5 {
		t.Errorf("PCP: %d", r.Tags[0].PCP)
	}
	if !strings.Contains(r.Tags[0].PCPName, "Voice") {
		t.Errorf("PCP name: %q", r.Tags[0].PCPName)
	}
	if r.Tags[0].VID != 200 {
		t.Errorf("VID: %d", r.Tags[0].VID)
	}
}

func TestDecode_QinQ_802_1ad(t *testing.T) {
	// Outer S-tag (0x88A8) VID=300, inner C-tag (0x8100) VID=10.
	in := "88A8 012C 8100 000A 0806"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TagCount != 2 {
		t.Fatalf("expected 2 tags, got %d", r.TagCount)
	}
	if !r.IsQinQ {
		t.Errorf("expected QinQ")
	}
	if r.Tags[0].TPID != 0x88A8 || r.Tags[0].VID != 300 {
		t.Errorf("outer tag: %+v", r.Tags[0])
	}
	if r.Tags[1].TPID != 0x8100 || r.Tags[1].VID != 10 {
		t.Errorf("inner tag: %+v", r.Tags[1])
	}
	if r.InnerEtherName != "ARP" {
		t.Errorf("inner ether: %q", r.InnerEtherName)
	}
	if len(r.Notes) == 0 {
		t.Errorf("expected QinQ note")
	}
}

func TestDecode_TripleTagUnusual(t *testing.T) {
	// Three stacked 0x8100 tags — unusual but valid; surfaces a note.
	in := "8100 0001 8100 0002 8100 0003 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TagCount != 3 {
		t.Fatalf("expected 3 tags, got %d", r.TagCount)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "3 stacked") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected triple-tag note in: %v", r.Notes)
	}
}

func TestDecode_PriorityTaggedFrame(t *testing.T) {
	// VID=0 (priority-tagged), PCP=7 Network Control.
	in := "8100 E000 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	tag := r.Tags[0]
	if tag.VID != 0 {
		t.Errorf("VID: %d", tag.VID)
	}
	if !strings.Contains(tag.VIDNote, "priority-tagged") {
		t.Errorf("VID note: %q", tag.VIDNote)
	}
	if tag.PCP != 7 || !strings.Contains(tag.PCPName, "Network Control") {
		t.Errorf("PCP: %d %q", tag.PCP, tag.PCPName)
	}
}

func TestDecode_ReservedVID4095(t *testing.T) {
	in := "8100 0FFF 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(r.Tags[0].VIDNote, "reserved") {
		t.Errorf("VID note: %q", r.Tags[0].VIDNote)
	}
}

func TestDecode_DEIBitSet(t *testing.T) {
	// DEI=1, VID=100. TCI = 0x1000 | 0x0064 = 0x1064.
	in := "8100 1064 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Tags[0].DEI {
		t.Errorf("DEI should be true")
	}
	if r.Tags[0].VID != 100 {
		t.Errorf("VID: %d", r.Tags[0].VID)
	}
}

func TestDecode_LLDPInner(t *testing.T) {
	in := "8100 000A 88CC"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.InnerEtherName != "LLDP" {
		t.Errorf("inner ether: %q", r.InnerEtherName)
	}
}

func TestDecode_LegacyQinQTPID(t *testing.T) {
	// 0x9100 legacy QinQ TPID.
	in := "9100 012C 8100 000A 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.IsQinQ {
		t.Errorf("expected QinQ for legacy 0x9100 + 0x8100 stack")
	}
	if !strings.Contains(r.Tags[0].TPIDName, "Legacy") {
		t.Errorf("TPID name: %q", r.Tags[0].TPIDName)
	}
}

func TestPCPNameTable(t *testing.T) {
	cases := map[int]string{
		0: "Background (Best Effort default)",
		3: "Critical Applications",
		4: "Video (<100ms latency)",
		5: "Voice (<10ms latency)",
		7: "Network Control (Highest)",
	}
	for k, v := range cases {
		if got := pcpName(k); got != v {
			t.Errorf("pcpName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"odd hex":       "81000064080",
		"too short":     "8100",
		"no tag":        "0800AABBCCDD",
		"tag truncated": "8100 00",
		"missing ether": "8100 0064",
		"bad hex":       "ZZ00 0064 0800",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
