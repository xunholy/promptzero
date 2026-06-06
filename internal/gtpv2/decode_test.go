// SPDX-License-Identifier: AGPL-3.0-or-later

package gtpv2

import (
	"strings"
	"testing"
)

// Field values are scapy's (scapy.contrib.gtp_v2) decode of the same
// message: a Create Session Request (type 32) with TEID 0x11223344,
// seq 0x539, and an IMSI IE for 262011234567890.
const createSession = "5820001411223344000539000100080062021132547698f0"

func TestDecodeCreateSession(t *testing.T) {
	r, err := Decode(createSession)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 || !r.TEIDPresent || !r.Piggybacked {
		t.Errorf("version/flags wrong: %+v", r)
	}
	if r.MessageType != 32 || r.MessageName != "Create Session Request" {
		t.Errorf("type = %d (%q); want 32 Create Session Request", r.MessageType, r.MessageName)
	}
	if r.Length != 20 {
		t.Errorf("Length = %d; want 20", r.Length)
	}
	if r.TEID != "0x11223344" {
		t.Errorf("TEID = %q", r.TEID)
	}
	if r.SequenceNumber != 0x539 {
		t.Errorf("SequenceNumber = %#x; want 0x539", r.SequenceNumber)
	}
	if r.IMSI != "262011234567890" {
		t.Errorf("IMSI = %q; want 262011234567890", r.IMSI)
	}
	if len(r.IEs) != 1 || r.IEs[0].Type != 1 || r.IEs[0].TypeName != "IMSI" || r.IEs[0].Length != 8 {
		t.Errorf("IE = %+v", r.IEs)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "IMSI-harvesting") {
		t.Error("expected the IMSI-harvesting note")
	}
}

func TestTBCD(t *testing.T) {
	// 62021132547698f0 -> 262011234567890 (the F is a filler).
	if got := decodeTBCD([]byte{0x62, 0x02, 0x11, 0x32, 0x54, 0x76, 0x98, 0xf0}); got != "262011234567890" {
		t.Errorf("decodeTBCD = %q; want 262011234567890", got)
	}
}

func TestDecodeNoTEID(t *testing.T) {
	// Echo Request (type 1), no TEID (T=0): byte0=0x40 (version 2, T clear).
	// header 8 bytes: 40 01 0000 seq(3)=000001 spare=00, no IEs.
	r, err := Decode("4001000000000100")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TEIDPresent || r.TEID != "" {
		t.Errorf("TEID should be absent: %+v", r)
	}
	if r.MessageType != 1 || r.MessageName != "Echo Request" {
		t.Errorf("type = %d (%q)", r.MessageType, r.MessageName)
	}
	if r.SequenceNumber != 1 {
		t.Errorf("seq = %d; want 1", r.SequenceNumber)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "zz", "5820", "1801000000000000"} { // empty / non-hex / short / version 0
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestMessageAndIENames(t *testing.T) {
	if messageName(36) != "Delete Session Request" || messageName(170) != "Release Access Bearers Request" {
		t.Error("message name table wrong")
	}
	if ieName(76) != "MSISDN" || ieName(87) != "F-TEID" {
		t.Error("IE name table wrong")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(createSession)
	f.Add("4001000000000100")
	f.Add("")
	f.Add("58")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
