package arpdecode

import (
	"strings"
	"testing"
)

func TestDecode_IPv4Request(t *testing.T) {
	// HW=Ethernet, Proto=IPv4, HLEN=6, PLEN=4, op=Request,
	// sender 00:11:22:33:44:55 / 192.168.1.1, target
	// 00:00:00:00:00:00 / 192.168.1.2.
	in := "0001 0800 06 04 0001 001122334455 C0A80101 000000000000 C0A80102"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.HardwareTypeName != "Ethernet" || r.ProtocolTypeName != "IPv4" {
		t.Errorf("types: %q / %q", r.HardwareTypeName, r.ProtocolTypeName)
	}
	if r.OperationName != "Request" {
		t.Errorf("op: %q", r.OperationName)
	}
	if r.SenderHardware != "00:11:22:33:44:55" {
		t.Errorf("sender MAC: %q", r.SenderHardware)
	}
	if r.SenderProtocol != "192.168.1.1" {
		t.Errorf("sender IP: %q", r.SenderProtocol)
	}
	if r.TargetHardware != "00:00:00:00:00:00" {
		t.Errorf("target MAC: %q", r.TargetHardware)
	}
	if r.TargetProtocol != "192.168.1.2" {
		t.Errorf("target IP: %q", r.TargetProtocol)
	}
	if len(r.Notes) != 0 {
		t.Errorf("expected no notes, got %v", r.Notes)
	}
}

func TestDecode_IPv4Reply(t *testing.T) {
	in := "0001 0800 06 04 0002 AABBCCDDEEFF C0A80102 001122334455 C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OperationName != "Reply" {
		t.Errorf("op: %q", r.OperationName)
	}
	if r.SenderHardware != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("sender MAC: %q", r.SenderHardware)
	}
	if r.SenderProtocol != "192.168.1.2" {
		t.Errorf("sender IP: %q", r.SenderProtocol)
	}
}

func TestDecode_GratuitousARP(t *testing.T) {
	// Reply with sender IP == target IP.
	in := "0001 0800 06 04 0002 001122334455 C0A80101 FFFFFFFFFFFF C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "Gratuitous") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Gratuitous note in: %v", r.Notes)
	}
}

func TestDecode_ARPProbe(t *testing.T) {
	// Request with sender IP 0.0.0.0, target IP non-zero.
	in := "0001 0800 06 04 0001 001122334455 00000000 000000000000 C0A80132"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.SenderProtocol != "0.0.0.0" {
		t.Errorf("sender IP: %q", r.SenderProtocol)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "ARP Probe") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ARP Probe note in: %v", r.Notes)
	}
}

func TestDecode_ARPAnnouncement(t *testing.T) {
	// Request with sender IP == target IP (post-probe announcement).
	in := "0001 0800 06 04 0001 001122334455 C0A80132 000000000000 C0A80132"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "ARP Announcement") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ARP Announcement note in: %v", r.Notes)
	}
}

func TestDecode_RARPRequest(t *testing.T) {
	// Op=3 RARP Request — sender asks "what is my IP for this MAC?"
	in := "0001 0800 06 04 0003 001122334455 00000000 001122334455 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OperationName != "RARP Request" {
		t.Errorf("op: %q", r.OperationName)
	}
}

func TestDecode_IPv6ARP(t *testing.T) {
	// Unusual but valid: HW=Ethernet, Proto=IPv6, HLEN=6, PLEN=16.
	// Sender IP fe80::1, Target IP fe80::2.
	in := "0001 86DD 06 10 0001 001122334455 FE80000000000000000000000000 0001" +
		" AABBCCDDEEFF FE80000000000000000000000000 0002"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProtocolTypeName != "IPv6" {
		t.Errorf("proto: %q", r.ProtocolTypeName)
	}
	if r.SenderProtocol != "fe80::1" {
		t.Errorf("sender IP: %q", r.SenderProtocol)
	}
	if r.TargetProtocol != "fe80::2" {
		t.Errorf("target IP: %q", r.TargetProtocol)
	}
}

func TestOperationNameTable(t *testing.T) {
	cases := map[int]string{
		1: "Request", 2: "Reply",
		3: "RARP Request", 4: "RARP Reply",
		5: "DRARP-Request", 6: "DRARP-Reply", 7: "DRARP-Error",
		8: "InARP-Request", 9: "InARP-Reply",
		10: "ARP-NAK",
	}
	for k, v := range cases {
		if got := operationName(k); got != v {
			t.Errorf("operationName(%d): got %q want %q", k, got, v)
		}
	}
	if !strings.Contains(operationName(99), "uncatalogued") {
		t.Errorf("unknown op fallback")
	}
}

func TestHardwareTypeNameTable(t *testing.T) {
	cases := map[int]string{
		1: "Ethernet", 6: "IEEE 802 Networks", 32: "InfiniBand",
	}
	for k, v := range cases {
		if got := hardwareTypeName(k); got != v {
			t.Errorf("hardwareTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":       "",
		"odd hex":     "00010800060",
		"short":       "00010800",
		"length lies": "0001 0800 06 04 0001 0011",
		"bad hex":     "ZZ010800060400010011223344",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
