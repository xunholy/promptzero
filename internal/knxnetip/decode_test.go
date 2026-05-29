// SPDX-License-Identifier: AGPL-3.0-or-later

package knxnetip

import (
	"strings"
	"testing"
)

// TestDecode_SearchRequest pins the canonical KNXnet/IP discovery
// frame an attacker multicasts to enumerate gateways on a building
// network.
//
//	Header: 06 10 02 01 00 0E  (v1.0, SEARCH_REQUEST, total 14)
//	HPAI:   08 01 C0 A8 00 0A 0E 57  (IPv4 UDP, 192.168.0.10:3671)
func TestDecode_SearchRequest(t *testing.T) {
	got, err := Decode("06 10 02 01 00 0E 08 01 C0 A8 00 0A 0E 57")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Header.ServiceType != stSearchRequest {
		t.Errorf("ServiceType = 0x%04X; want 0x0201", got.Header.ServiceType)
	}
	if got.Header.ServiceTypeName != "SEARCH_REQUEST" {
		t.Errorf("ServiceTypeName = %q", got.Header.ServiceTypeName)
	}
	if got.Header.ServiceFamily != "Core" {
		t.Errorf("ServiceFamily = %q; want Core", got.Header.ServiceFamily)
	}
	if len(got.HPAIs) != 1 {
		t.Fatalf("HPAIs = %d; want 1", len(got.HPAIs))
	}
	h := got.HPAIs[0]
	if h.Address != "192.168.0.10" {
		t.Errorf("HPAI.Address = %q; want 192.168.0.10", h.Address)
	}
	if h.Port != 3671 {
		t.Errorf("HPAI.Port = %d; want 3671", h.Port)
	}
	if h.HostProtocolName != "IPv4 UDP" {
		t.Errorf("HPAI.HostProtocolName = %q", h.HostProtocolName)
	}
}

// TestDecode_TunnellingGroupValueWrite is the high-value case: a
// TUNNELLING_REQUEST carrying a cEMI L_Data.ind that writes to a
// group address — the "switch the lighting group on" command.
//
//	Header:    06 10 04 20 00 15  (TUNNELLING_REQUEST, total 21)
//	ConnHdr:   04 01 00 00        (channel 1, seq 0)
//	cEMI:      29 00 BC E0 11 0A 09 03 01 00 81
//	           L_Data.ind, ctrl BC/E0 (group dest), src 1.1.10,
//	           dst group 1/1/3, NPDU len 1, APCI GroupValueWrite, val 01
func TestDecode_TunnellingGroupValueWrite(t *testing.T) {
	got, err := Decode("0610042000150401000029 00 BC E0 11 0A 09 03 01 00 81")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Header.ServiceTypeName != "TUNNELLING_REQUEST" {
		t.Errorf("ServiceTypeName = %q", got.Header.ServiceTypeName)
	}
	if got.ConnHeader == nil {
		t.Fatal("ConnHeader nil")
	}
	if got.ConnHeader.ChannelID != 1 {
		t.Errorf("ChannelID = %d; want 1", got.ConnHeader.ChannelID)
	}
	if got.CEMI == nil {
		t.Fatal("CEMI nil")
	}
	c := got.CEMI
	if c.MessageCodeName != "L_Data.ind" {
		t.Errorf("MessageCodeName = %q; want L_Data.ind", c.MessageCodeName)
	}
	if c.SourceAddress != "1.1.10" {
		t.Errorf("SourceAddress = %q; want 1.1.10", c.SourceAddress)
	}
	if !c.DestIsGroup {
		t.Error("DestIsGroup = false; want true")
	}
	if c.DestAddress != "1/1/3" {
		t.Errorf("DestAddress = %q; want 1/1/3", c.DestAddress)
	}
	if c.APCIName != "A_GroupValue_Write" {
		t.Errorf("APCIName = %q; want A_GroupValue_Write", c.APCIName)
	}
	if c.PayloadHex != "01" {
		t.Errorf("PayloadHex = %q; want 01", c.PayloadHex)
	}
}

// TestDecode_RoutingIndicationGroupRead exercises the multicast
// routing path with a GroupValueRead (NPDU len 1, zero payload).
//
//	Header: 06 10 05 30 00 11  (ROUTING_INDICATION, total 17)
//	cEMI:   29 00 BC E0 11 05 08 01 01 00 00
func TestDecode_RoutingIndicationGroupRead(t *testing.T) {
	got, err := Decode("06 10 05 30 00 11 29 00 BC E0 11 05 08 01 01 00 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Header.ServiceFamily != "Routing" {
		t.Errorf("ServiceFamily = %q; want Routing", got.Header.ServiceFamily)
	}
	if got.CEMI == nil {
		t.Fatal("CEMI nil")
	}
	if got.CEMI.SourceAddress != "1.1.5" {
		t.Errorf("SourceAddress = %q; want 1.1.5", got.CEMI.SourceAddress)
	}
	if got.CEMI.DestAddress != "1/0/1" {
		t.Errorf("DestAddress = %q; want 1/0/1", got.CEMI.DestAddress)
	}
	if got.CEMI.APCIName != "A_GroupValue_Read" {
		t.Errorf("APCIName = %q; want A_GroupValue_Read", got.CEMI.APCIName)
	}
}

// TestDecode_ConnectRequestTwoHPAIs verifies both the control and
// data HPAI blocks are walked off a CONNECT_REQUEST.
//
//	Header:  06 10 02 05 00 1A  (CONNECT_REQUEST, total 26)
//	control: 08 01 C0 A8 00 0A 0E 57  (192.168.0.10:3671)
//	data:    08 01 C0 A8 00 0A 0E 58  (192.168.0.10:3672)
//	CRI:     04 04 02 00
func TestDecode_ConnectRequestTwoHPAIs(t *testing.T) {
	got, err := Decode("06 10 02 05 00 1A 08 01 C0 A8 00 0A 0E 57 08 01 C0 A8 00 0A 0E 58 04 04 02 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.HPAIs) != 2 {
		t.Fatalf("HPAIs = %d; want 2", len(got.HPAIs))
	}
	if got.HPAIs[0].Role != "control" || got.HPAIs[1].Role != "data" {
		t.Errorf("roles = %q,%q; want control,data", got.HPAIs[0].Role, got.HPAIs[1].Role)
	}
	if got.HPAIs[1].Port != 3672 {
		t.Errorf("data HPAI port = %d; want 3672", got.HPAIs[1].Port)
	}
}

// TestDecode_SecureWrapperNoted confirms a KNXnet/IP Secure frame is
// classified and flagged as not-decoded rather than mis-parsed.
//
//	Header: 06 10 09 50 00 08 + 2 body bytes
func TestDecode_SecureWrapperNoted(t *testing.T) {
	got, err := Decode("06 10 09 50 00 08 AB CD")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Header.ServiceFamily != "KNXnet/IP Secure" {
		t.Errorf("ServiceFamily = %q", got.Header.ServiceFamily)
	}
	found := false
	for _, n := range got.Notes {
		if strings.Contains(n, "not decoded") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a 'not decoded' note, got %v", got.Notes)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":             "",
		"too short":         "0610",
		"odd nibbles":       "06100",
		"bad hex":           "zzzz",
		"total-length lie":  "06 10 02 01 00 FF 08 01 C0 A8 00 0A 0E 57",
		"header-length lie": "FF 10 02 01 00 0E 08 01 C0 A8 00 0A 0E 57",
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// TestDecode_TruncatedCEMINoPanic feeds a tunnelling frame whose
// cEMI runs off the end mid-field; the decoder must surface what it
// can without panicking.
func TestDecode_TruncatedCEMINoPanic(t *testing.T) {
	// Header (TUNNELLING_REQUEST, total 12) + conn header + a single
	// cEMI message-code byte and add-info length, then EOF.
	in := "06 10 04 20 00 0C 04 01 00 00 29 00"
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Decode panicked on truncated cEMI: %v", r)
		}
	}()
	got, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.CEMI == nil {
		t.Fatal("CEMI nil; want a partial decode with message code")
	}
	if got.CEMI.MessageCodeName != "L_Data.ind" {
		t.Errorf("MessageCodeName = %q", got.CEMI.MessageCodeName)
	}
	// No L_Data fields should be populated — the buffer ended early.
	if got.CEMI.SourceAddress != "" {
		t.Errorf("SourceAddress = %q; want empty (truncated)", got.CEMI.SourceAddress)
	}
}

func TestFormatAddrs(t *testing.T) {
	if got := formatIndividualAddr(0x110A); got != "1.1.10" {
		t.Errorf("formatIndividualAddr(0x110A) = %q; want 1.1.10", got)
	}
	if got := formatGroupAddr(0x0903); got != "1/1/3" {
		t.Errorf("formatGroupAddr(0x0903) = %q; want 1/1/3", got)
	}
	// Max group address 31/7/255.
	if got := formatGroupAddr(0xFFFF); got != "31/7/255" {
		t.Errorf("formatGroupAddr(0xFFFF) = %q; want 31/7/255", got)
	}
}
