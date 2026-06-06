// SPDX-License-Identifier: AGPL-3.0-or-later

package mld

import "testing"

// Vectors are built from scapy's MLD layers (ICMPv6MLQuery / ICMPv6MLReport /
// ICMPv6MLDone / ICMPv6MLQuery2 / ICMPv6MLReport2 / ICMPv6MLDMultAddrRec) and
// hand-verified against RFC 2710 / RFC 3810.

func TestMLDv1GeneralQuery(t *testing.T) {
	r, err := Decode("820000002710000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Type != 130 || r.TypeName != "Multicast_Listener_Query" {
		t.Errorf("type = %d/%q", r.Type, r.TypeName)
	}
	if r.MLDVersion != 1 {
		t.Errorf("MLDVersion = %d, want 1", r.MLDVersion)
	}
	if r.MaxResponseDelayMs != 10000 {
		t.Errorf("MaxResponseDelayMs = %d, want 10000", r.MaxResponseDelayMs)
	}
	if !r.GeneralQuery {
		t.Error("GeneralQuery should be true for mladdr ::")
	}
	if r.MulticastAddress != "::" {
		t.Errorf("MulticastAddress = %q", r.MulticastAddress)
	}
}

func TestMLDv1Report(t *testing.T) {
	r, err := Decode("8300000000000000ff020000000000000000000000010003")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Multicast_Listener_Report" || r.MLDVersion != 1 {
		t.Errorf("type = %q v%d", r.TypeName, r.MLDVersion)
	}
	if r.MulticastAddress != "ff02::1:3" {
		t.Errorf("MulticastAddress = %q, want ff02::1:3 (LLMNR)", r.MulticastAddress)
	}
}

func TestMLDv1Done(t *testing.T) {
	r, err := Decode("8400000000000000ff0200000000000000000000000000fb")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Multicast_Listener_Done" {
		t.Errorf("TypeName = %q", r.TypeName)
	}
	if r.MulticastAddress != "ff02::fb" {
		t.Errorf("MulticastAddress = %q, want ff02::fb (mDNS)", r.MulticastAddress)
	}
}

func TestMLDv2Query(t *testing.T) {
	r, err := Decode("8200000027100000ff0200000000000000000000000000fb027d000120010db8000000000000000000000001")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MLDVersion != 2 {
		t.Errorf("MLDVersion = %d, want 2", r.MLDVersion)
	}
	if r.MaxResponseDelayMs != 10000 {
		t.Errorf("MaxResponseDelayMs = %d", r.MaxResponseDelayMs)
	}
	if r.MulticastAddress != "ff02::fb" {
		t.Errorf("MulticastAddress = %q", r.MulticastAddress)
	}
	if r.SuppressRouterProcessing {
		t.Error("S flag should be false")
	}
	if r.QRV != 2 {
		t.Errorf("QRV = %d, want 2", r.QRV)
	}
	if r.QQICSeconds != 125 {
		t.Errorf("QQICSeconds = %d, want 125", r.QQICSeconds)
	}
	if len(r.QuerierSources) != 1 || r.QuerierSources[0] != "2001:db8::1" {
		t.Errorf("QuerierSources = %v", r.QuerierSources)
	}
}

func TestMLDv2ReportNoSources(t *testing.T) {
	r, err := Decode("8f0000000000000102000000ff0200000000000000000000000000fb")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Multicast_Listener_Report_v2" || r.MLDVersion != 2 {
		t.Errorf("type = %q v%d", r.TypeName, r.MLDVersion)
	}
	if len(r.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(r.Records))
	}
	rec := r.Records[0]
	if rec.RecordType != 2 || rec.RecordTypeName != "MODE_IS_EXCLUDE" {
		t.Errorf("record type = %d/%q", rec.RecordType, rec.RecordTypeName)
	}
	if rec.MulticastAddress != "ff02::fb" {
		t.Errorf("record group = %q", rec.MulticastAddress)
	}
	if len(rec.Sources) != 0 {
		t.Errorf("expected no sources, got %v", rec.Sources)
	}
}

func TestMLDv2ReportWithSources(t *testing.T) {
	r, err := Decode("8f0000000000000105000002ff38000000000000000000000000123420010db8000000000000000000000001" +
		"20010db8000000000000000000000002")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(r.Records))
	}
	rec := r.Records[0]
	if rec.RecordTypeName != "ALLOW_NEW_SOURCES" {
		t.Errorf("record type = %q", rec.RecordTypeName)
	}
	if rec.MulticastAddress != "ff38::1234" {
		t.Errorf("record group = %q", rec.MulticastAddress)
	}
	want := []string{"2001:db8::1", "2001:db8::2"}
	if len(rec.Sources) != 2 || rec.Sources[0] != want[0] || rec.Sources[1] != want[1] {
		t.Errorf("Sources = %v, want %v", rec.Sources, want)
	}
}

func TestMLDv2MaxRespFloat(t *testing.T) {
	// code 0x8000: mant=0, exp=0 -> (0|0x1000)<<3 = 0x8000 = 32768.
	if got := mldv2MaxResp(0x8000); got != 32768 {
		t.Errorf("mldv2MaxResp(0x8000) = %d, want 32768", got)
	}
	// code < 0x8000 is the value directly.
	if got := mldv2MaxResp(5000); got != 5000 {
		t.Errorf("mldv2MaxResp(5000) = %d, want 5000", got)
	}
}

func TestRejectNonMLD(t *testing.T) {
	// type 128 (Echo Request) is ICMPv6 but not MLD.
	if _, err := Decode("80000000"); err == nil {
		t.Error("expected rejection of non-MLD ICMPv6 type 128")
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "8200", "zz", "82000000271000000000"} {
		// empty, 2 bytes, non-hex, short query (10 bytes < 24)
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
