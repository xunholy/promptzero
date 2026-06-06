// SPDX-License-Identifier: AGPL-3.0-or-later

package vtp

import (
	"strings"
	"testing"
)

// Field values are scapy's (scapy.contrib.vtp) decode of the same PDUs.

func TestDecodeSummary(t *testing.T) {
	// ver=1 code=1 followers=0 domain "LAB" rev=42 updater 10.0.0.1
	// timestamp "930730150000" md5=0x11*16
	r, err := Decode("010100034c414200000000000000000000000000000000000000000000000000000000000000002a0a00000139333037333031353030303011111111111111111111111111111111")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 1 || r.Code != 1 || r.CodeName != "Summary Advertisement" {
		t.Errorf("ver/code = %d/%d (%q)", r.Version, r.Code, r.CodeName)
	}
	if r.DomainName != "LAB" {
		t.Errorf("DomainName = %q; want LAB", r.DomainName)
	}
	if r.ConfigRevision == nil || *r.ConfigRevision != 42 {
		t.Errorf("ConfigRevision = %v; want 42", r.ConfigRevision)
	}
	if r.UpdaterIdentity != "10.0.0.1" {
		t.Errorf("UpdaterIdentity = %q; want 10.0.0.1", r.UpdaterIdentity)
	}
	if r.UpdateTimestamp != "930730150000" {
		t.Errorf("UpdateTimestamp = %q", r.UpdateTimestamp)
	}
	if r.MD5Hex != "11111111111111111111111111111111" {
		t.Errorf("MD5Hex = %q", r.MD5Hex)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "attack-critical") {
		t.Error("expected the config-revision attack note")
	}
}

func TestDecodeSubset(t *testing.T) {
	// ver=1 code=2 seq=1 domain "LAB" rev=42, one VLAN: id 1 "VLAN0001" mtu 1500
	r, err := Decode("010201034c414200000000000000000000000000000000000000000000000000000000000000002a14000108000105dc00000000564c414e30303031")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Code != 2 || r.CodeName != "Subset Advertisement" {
		t.Errorf("code = %d (%q)", r.Code, r.CodeName)
	}
	if r.SequenceNumber == nil || *r.SequenceNumber != 1 {
		t.Errorf("SequenceNumber = %v; want 1", r.SequenceNumber)
	}
	if r.ConfigRevision == nil || *r.ConfigRevision != 42 {
		t.Errorf("ConfigRevision = %v; want 42", r.ConfigRevision)
	}
	if len(r.VLANs) != 1 {
		t.Fatalf("VLANs = %d; want 1", len(r.VLANs))
	}
	v := r.VLANs[0]
	if v.VLANID != 1 || v.Name != "VLAN0001" || v.MTU != 1500 {
		t.Errorf("vlan = id %d %q mtu %d; want 1 VLAN0001 1500", v.VLANID, v.Name, v.MTU)
	}
	if v.Status != 0 || v.StatusName != "operational" || v.Type != 1 || v.TypeName != "Ethernet" {
		t.Errorf("status/type = %d(%q)/%d(%q)", v.Status, v.StatusName, v.Type, v.TypeName)
	}
}

func TestDecodeAdvRequest(t *testing.T) {
	// ver=1 code=3 domain "LAB"
	r, err := Decode("010300034c414200000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Code != 3 || r.CodeName != "Advertisement Request" || r.DomainName != "LAB" {
		t.Errorf("code/domain = %d(%q)/%q", r.Code, r.CodeName, r.DomainName)
	}
	if r.ConfigRevision != nil {
		t.Error("AdvRequest should not carry a config revision")
	}
}

func TestDecodeWithSNAP(t *testing.T) {
	pdu := "010100034c414200000000000000000000000000000000000000000000000000000000000000002a0a00000139333037333031353030303011111111111111111111111111111111"
	r, err := Decode("aaaa03" + "00000c2003" + pdu)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.DomainName != "LAB" || r.ConfigRevision == nil || *r.ConfigRevision != 42 {
		t.Errorf("SNAP-wrapped decode wrong: %+v", r)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "zz", "0101"} { // empty / non-hex / too short
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("010100034c414200000000000000000000000000000000000000000000000000000000000000002a0a00000139333037333031353030303011111111111111111111111111111111")
	f.Add("010201034c414200000000000000000000000000000000000000000000000000000000000000002a14000108000105dc00000000564c414e30303031")
	f.Add("")
	f.Add("0101")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
