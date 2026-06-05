// SPDX-License-Identifier: AGPL-3.0-or-later

package dsmr

import (
	"strings"
	"testing"
)

// v5Lines is the KFM5KAIFA-METER DSMR-5.0 telegram from the dsmr_parser
// reference test fixtures (test/example_telegrams.py). Joined with CRLF
// and terminated by "!6796", its CRC-16/ARC is 0x6796.
var v5Lines = []string{
	"/KFM5KAIFA-METER",
	"",
	"1-3:0.2.8(42)",
	"0-0:1.0.0(161113205757W)",
	"0-0:96.1.1(3960221976967177082151037881335713)",
	"1-0:1.8.1(001581.123*kWh)",
	"1-0:1.8.2(001435.706*kWh)",
	"1-0:2.8.1(000000.000*kWh)",
	"1-0:2.8.2(000000.000*kWh)",
	"0-0:96.14.0(0002)",
	"1-0:1.7.0(02.027*kW)",
	"1-0:2.7.0(00.000*kW)",
	"0-0:96.7.21(00015)",
	"0-0:96.7.9(00007)",
	"1-0:99.97.0(3)(0-0:96.7.19)(000104180320W)(0000237126*s)(000101000001W)(2147583646*s)(000102000003W)(2317482647*s)",
	"1-0:32.32.0(00000)",
	"1-0:52.32.0(00000)",
	"1-0:72.32.0(00000)",
	"1-0:32.36.0(00000)",
	"1-0:52.36.0(00000)",
	"1-0:72.36.0(00000)",
	"0-0:96.13.1()",
	"0-0:96.13.0()",
	"1-0:31.7.0(000*A)",
	"1-0:51.7.0(006*A)",
	"1-0:71.7.0(002*A)",
	"1-0:21.7.0(00.170*kW)",
	"1-0:22.7.0(00.000*kW)",
	"1-0:41.7.0(01.247*kW)",
	"1-0:42.7.0(00.000*kW)",
	"1-0:61.7.0(00.209*kW)",
	"1-0:62.7.0(00.000*kW)",
	"0-1:24.1.0(003)",
	"0-1:96.1.0(4819243993373755377509728609491464)",
	"0-1:24.2.1(161129200000W)(00981.443*m3)",
}

func v5Telegram() string {
	return strings.Join(v5Lines, "\r\n") + "\r\n!6796\r\n"
}

func find(r *Result, obis string) *Object {
	for i := range r.Objects {
		if r.Objects[i].OBIS == obis {
			return &r.Objects[i]
		}
	}
	return nil
}

func TestDecodeV5Telegram(t *testing.T) {
	r, err := Decode(v5Telegram())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Identifier != "KFM5KAIFA-METER" {
		t.Errorf("identifier = %q", r.Identifier)
	}
	if r.CRC != "0x6796" || !r.CRCValid {
		t.Errorf("crc = %s valid=%v, want 0x6796/true", r.CRC, r.CRCValid)
	}
	// Electricity import tariff 1.
	e := find(r, "1-0:1.8.1")
	if e == nil || e.Value != "001581.123" || e.Unit != "kWh" {
		t.Errorf("1-0:1.8.1 = %+v", e)
	}
	if e != nil && !strings.Contains(e.Description, "tariff 1") {
		t.Errorf("1-0:1.8.1 desc = %q", e.Description)
	}
	// Instantaneous power.
	if p := find(r, "1-0:1.7.0"); p == nil || p.Value != "02.027" || p.Unit != "kW" {
		t.Errorf("1-0:1.7.0 = %+v", p)
	}
	// Gas reading (last paren group is the value).
	if g := find(r, "0-1:24.2.1"); g == nil || g.Value != "00981.443" || g.Unit != "m3" {
		t.Errorf("0-1:24.2.1 = %+v", g)
	}
	// Per-phase current.
	if c := find(r, "1-0:51.7.0"); c == nil || c.Value != "006" || c.Unit != "A" {
		t.Errorf("1-0:51.7.0 = %+v", c)
	}
}

func TestCRCNormalisesLFOnly(t *testing.T) {
	// Same telegram pasted with bare LF must still validate (CRLF repaired).
	lf := strings.ReplaceAll(v5Telegram(), "\r\n", "\n")
	r, err := Decode(lf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.CRCValid {
		t.Error("CRC should validate after CRLF normalisation of an LF-only paste")
	}
}

func TestCRCDetectsTamper(t *testing.T) {
	// Change a reading; the CRC must no longer match.
	bad := strings.Replace(v5Telegram(), "001581.123", "009999.999", 1)
	r, err := Decode(bad)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CRCValid {
		t.Error("CRC should be invalid for a tampered telegram")
	}
}

func TestCRC16ARCKnownVector(t *testing.T) {
	covered := strings.Join(v5Lines, "\r\n") + "\r\n!"
	if got := crc16ARC([]byte(covered)); got != 0x6796 {
		t.Errorf("CRC = 0x%04X, want 0x6796", got)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "no telegram", "/ident no bang"} {
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(v5Telegram())
	f.Add("/X\r\n!0000\r\n")
	f.Add("")
	f.Add("/(((")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
