// SPDX-License-Identifier: AGPL-3.0-or-later

package sv

import "testing"

// Vectors are hand-built per the IEC 61850-9-2 ASN.1 (savPdu tag 0x60,
// seqASDU 0xA2, ASDU 0x30, context-tagged fields) — the same authoritative
// layout Wireshark's sv dissector uses. The BER walk is byte-checkable.
//
// Frame (after the 0x88BA EtherType):
//
//	4000 002e 0000 0000              header: APPID 0x4000, length 46
//	60 24                            savPdu, len 36
//	  80 01 01                       noASDU = 1
//	  a2 1f                          seqASDU, len 31
//	    30 1d                        ASDU, len 29
//	      80 04 4d553031             svID "MU01"
//	      82 02 0001                 smpCnt = 1
//	      83 04 00000001             confRev = 1
//	      85 01 02                   smpSynch = 2 (Global)
//	      87 08 1122334455667788     sample (raw)
const oneASDU = "4000002e000000006024800101a21f301d80044d55303182020001830400000001850102" +
	"87081122334455667788"

func TestSVOneASDU(t *testing.T) {
	r, err := Decode(oneASDU)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.APPID != 0x4000 {
		t.Errorf("APPID = 0x%04X, want 0x4000", r.APPID)
	}
	if r.Length != 46 {
		t.Errorf("Length = %d, want 46", r.Length)
	}
	if r.NoASDU != 1 {
		t.Errorf("NoASDU = %d, want 1", r.NoASDU)
	}
	if len(r.ASDUs) != 1 {
		t.Fatalf("got %d ASDUs, want 1", len(r.ASDUs))
	}
	a := r.ASDUs[0]
	if a.SvID != "MU01" {
		t.Errorf("SvID = %q, want MU01", a.SvID)
	}
	if a.SmpCnt != 1 {
		t.Errorf("SmpCnt = %d, want 1", a.SmpCnt)
	}
	if a.ConfRev != 1 {
		t.Errorf("ConfRev = %d, want 1", a.ConfRev)
	}
	if a.SmpSynch != 2 || a.SmpSynchName != "Global (global / GPS-disciplined clock)" {
		t.Errorf("SmpSynch = %d/%q", a.SmpSynch, a.SmpSynchName)
	}
	if a.SampleHex != "1122334455667788" {
		t.Errorf("SampleHex = %q", a.SampleHex)
	}
}

func TestSVTwoASDUWithOptionals(t *testing.T) {
	// Two ASDUs in seqASDU; the first carries datSet + refrTm + smpRate.
	// ASDU1 body:
	//   80 04 4d553031          svID "MU01"
	//   81 03 445331            datSet "DS1"
	//   82 02 00ff              smpCnt = 255
	//   83 04 00000003          confRev = 3
	//   84 08 0000000000000000  refrTm
	//   85 01 01                smpSynch = 1 (Local)
	//   86 02 1000              smpRate = 4096
	//   87 04 aabbccdd          sample
	// = 6+5+4+6+10+3+4+6 = 44 (0x2c)  -> ASDU1 = 30 2c <44> = 46
	a1 := "30" + "2c" +
		"80044d553031" +
		"8103445331" +
		"820200ff" +
		"830400000003" +
		"84080000000000000000" +
		"850101" +
		"86021000" +
		"8704aabbccdd"
	// ASDU2 minimal:
	//   80 04 4d553032          svID "MU02"
	//   82 02 0100              smpCnt = 256
	//   85 01 00                smpSynch = 0 (None)
	//   87 02 eeff              sample
	// = 6+4+3+4 = 17 (0x11) -> ASDU2 = 30 11 <17> = 19
	a2 := "3011" + "80044d553032" + "82020100" + "850100" + "8702eeff"
	seq := a1 + a2 // 46 + 19 = 65 bytes (0x41)
	savBody := "800101" + "a241" + seq
	// savBody = 3 + 2 + 65 = 70 (0x46)
	pdu := "6046" + savBody
	frame := "40000000" + "00000000" + pdu

	r, err := Decode(frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.ASDUs) != 2 {
		t.Fatalf("got %d ASDUs, want 2", len(r.ASDUs))
	}
	a := r.ASDUs[0]
	if a.SvID != "MU01" || a.DatSet != "DS1" || a.SmpCnt != 255 || a.ConfRev != 3 {
		t.Errorf("ASDU0 = %+v", a)
	}
	if a.SmpSynch != 1 || a.SmpRate != 4096 || a.SampleHex != "AABBCCDD" {
		t.Errorf("ASDU0 optionals = synch %d rate %d sample %q", a.SmpSynch, a.SmpRate, a.SampleHex)
	}
	if a.RefrTimeHex != "0000000000000000" {
		t.Errorf("ASDU0 refrTm = %q", a.RefrTimeHex)
	}
	b := r.ASDUs[1]
	if b.SvID != "MU02" || b.SmpCnt != 256 || b.SmpSynch != 0 || b.SampleHex != "EEFF" {
		t.Errorf("ASDU1 = %+v", b)
	}
	if b.SmpSynchName != "None (not synchronised)" {
		t.Errorf("ASDU1 synch name = %q", b.SmpSynchName)
	}
}

func TestSVRejectsMissingOuterTag(t *testing.T) {
	// Outer tag 0x61 (that's GOOSE) instead of 0x60.
	if _, err := Decode("40000010000000006102800101"); err == nil {
		t.Error("expected rejection of a non-0x60 outer tag")
	}
}

func TestSVErrors(t *testing.T) {
	for _, in := range []string{"", "4000", "zz", "4000000a00000000"} {
		// empty, 2 bytes, non-hex, header-only (no PDU)
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
