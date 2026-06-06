// SPDX-License-Identifier: AGPL-3.0-or-later

package igmpv3

import "testing"

// Vectors produced with scapy's IGMPv3 layer (scapy.contrib.igmpv3) and
// verified field-for-field.

func TestDecodeReport(t *testing.T) {
	// IGMPv3()/IGMPv3mr(records=[IGMPv3gr(rtype=4, maddr="239.1.1.1",
	//   srcaddrs=["10.0.0.1","10.0.0.2"])])
	const v = "2200d5f60000000104000002ef0101010a0000010a000002"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Version 3 Membership Report" {
		t.Fatalf("type = %q", r.TypeName)
	}
	if !r.CRCValid {
		t.Error("checksum should verify")
	}
	if r.NumRecords != 1 || len(r.Records) != 1 {
		t.Fatalf("records = %d", r.NumRecords)
	}
	gr := r.Records[0]
	if gr.RecordTypeName != "CHANGE_TO_EXCLUDE_MODE" {
		t.Errorf("rtype = %q", gr.RecordTypeName)
	}
	if gr.MulticastAddress != "239.1.1.1" {
		t.Errorf("maddr = %q", gr.MulticastAddress)
	}
	if len(gr.Sources) != 2 || gr.Sources[0] != "10.0.0.1" || gr.Sources[1] != "10.0.0.2" {
		t.Errorf("sources = %v", gr.Sources)
	}
}

func TestDecodeQuery(t *testing.T) {
	// IGMPv3(type=0x11)/IGMPv3mq(gaddr="239.5.5.5",
	//   srcaddrs=["10.1.1.1","10.1.1.2"], qrv=2, qqic=125, s=1)
	const v = "1114da5cef0505050a7d00020a0101010a010102"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Membership Query" {
		t.Fatalf("type = %q", r.TypeName)
	}
	if !r.CRCValid {
		t.Error("checksum should verify")
	}
	if r.GroupAddress != "239.5.5.5" {
		t.Errorf("group = %q", r.GroupAddress)
	}
	if r.QueryType != "group-and-source-specific" {
		t.Errorf("query type = %q", r.QueryType)
	}
	if r.SuppressRouterSide == nil || !*r.SuppressRouterSide {
		t.Errorf("s = %v", r.SuppressRouterSide)
	}
	if r.QRV == nil || *r.QRV != 2 {
		t.Errorf("qrv = %v", r.QRV)
	}
	if r.QQIC == nil || *r.QQIC != 125 {
		t.Errorf("qqic = %v", r.QQIC)
	}
	if *r.MaxRespCode != 0x14 || *r.MaxRespTimeMS != 2000 {
		t.Errorf("max resp = %d / %dms", *r.MaxRespCode, *r.MaxRespTimeMS)
	}
	if len(r.Sources) != 2 {
		t.Errorf("sources = %v", r.Sources)
	}
}

func TestDecodeGeneralQuery(t *testing.T) {
	// IGMPv3(type=0x11)/IGMPv3mq()
	const v = "1114eeeb0000000000000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.QueryType != "general" {
		t.Errorf("query type = %q, want general", r.QueryType)
	}
	if r.GroupAddress != "0.0.0.0" {
		t.Errorf("group = %q", r.GroupAddress)
	}
}

func TestDecodeFloatEncoding(t *testing.T) {
	// RFC 3376 §4.1.1: code 0x80 -> mant 0, exp 0 -> 0x10 << 3 = 128.
	if got := decodeFloat(0x80); got != 128 {
		t.Errorf("decodeFloat(0x80) = %d, want 128", got)
	}
	// code 0xff -> mant 0xf, exp 7 -> 0x1f << 10 = 31744.
	if got := decodeFloat(0xff); got != 31744 {
		t.Errorf("decodeFloat(0xff) = %d, want 31744", got)
	}
	if got := decodeFloat(0x64); got != 100 {
		t.Errorf("decodeFloat(0x64) = %d, want 100", got)
	}
}

func TestDecodeRejectsNonIGMPv3(t *testing.T) {
	if _, err := Decode("12000000" + "00000000"); err == nil {
		t.Fatal("expected rejection of non-v3 type")
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("2200"); err == nil {
		t.Fatal("expected error on short input")
	}
}
