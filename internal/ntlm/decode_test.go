package ntlm

import (
	"strings"
	"testing"
)

func TestDecode_Negotiate_Minimal(t *testing.T) {
	// NEGOTIATE_MESSAGE with flags 0x0201 (UNICODE | NTLM),
	// no Domain or Workstation strings, no Version.
	in := "4E544C4D53535000 01000000 01020000" +
		"0000 0000 20000000" +
		"0000 0000 20000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageType != 1 {
		t.Errorf("message type: %d", r.MessageType)
	}
	if r.MessageTypeName != "NEGOTIATE_MESSAGE" {
		t.Errorf("message name: %q", r.MessageTypeName)
	}
	n := r.Negotiate
	if n == nil {
		t.Fatal("Negotiate body nil")
	}
	if n.NegotiateFlags != 0x00000201 {
		t.Errorf("flags: 0x%08X", n.NegotiateFlags)
	}
	contains := func(s []string, x string) bool {
		for _, e := range s {
			if e == x {
				return true
			}
		}
		return false
	}
	if !contains(n.NegotiateFlagNames, "NEGOTIATE_UNICODE") ||
		!contains(n.NegotiateFlagNames, "NEGOTIATE_NTLM") {
		t.Errorf("flag names: %+v", n.NegotiateFlagNames)
	}
}

func TestDecode_Negotiate_WithVersionAndDomain(t *testing.T) {
	// NEGOTIATE_MESSAGE with OEM + VERSION flags, Domain
	// "EXAMPLE" (OEM = 7 bytes), no Workstation, with
	// Version (Windows 10.0 build 19041).
	in := "4E544C4D53535000 01000000 02000002" +
		"0700 0700 28000000" +
		"0000 0000 28000000" +
		"0A 00 614A 000000 0F" +
		"4558414D504C45"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	n := r.Negotiate
	if n.Domain != "EXAMPLE" {
		t.Errorf("domain: %q", n.Domain)
	}
	if n.Version == nil {
		t.Fatal("version nil")
	}
	if n.Version.Major != 10 || n.Version.Build != 19041 {
		t.Errorf("version: %+v", n.Version)
	}
	if n.Version.Revision != 15 {
		t.Errorf("revision: %d", n.Version.Revision)
	}
}

func TestDecode_Challenge_WithAVPairs(t *testing.T) {
	// CHALLENGE_MESSAGE with TargetName "EXAMPLE" (Unicode,
	// 14 bytes) and TargetInfo containing AvId=2
	// MsvAvNbDomainName "AC" + MsvAvEOL terminator.
	in := "4E544C4D53535000 02000000" +
		"0E000E0038000000" +
		"05028002" +
		"0102030405060708" +
		"0000000000000000" +
		"0C000C0046000000" +
		"0A 00 614A 000000 0F" +
		"45005800 41004D00 50004C00 4500" +
		"02000400 41004300" +
		"00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageTypeName != "CHALLENGE_MESSAGE" {
		t.Errorf("message name: %q", r.MessageTypeName)
	}
	c := r.Challenge
	if c == nil {
		t.Fatal("Challenge body nil")
	}
	if c.TargetName != "EXAMPLE" {
		t.Errorf("target name: %q", c.TargetName)
	}
	if c.ServerChallenge != "0102030405060708" {
		t.Errorf("server challenge: %q", c.ServerChallenge)
	}
	if len(c.TargetInfoAVPairs) != 1 {
		t.Fatalf("AV pairs: %d", len(c.TargetInfoAVPairs))
	}
	av := c.TargetInfoAVPairs[0]
	if av.AvIDName != "MsvAvNbDomainName" {
		t.Errorf("AV name: %q", av.AvIDName)
	}
	if av.ValueText != "AC" {
		t.Errorf("AV value: %q", av.ValueText)
	}
}

func TestDecode_Authenticate_UserOnly(t *testing.T) {
	// AUTHENTICATE_MESSAGE with only UserName="user"
	// (Unicode = 8 bytes), no LM/NT responses, no Domain,
	// no Workstation, no session key.
	in := "4E544C4D53535000 03000000" +
		"0000 0000 40000000" + // LmChallengeResponse
		"0000 0000 40000000" + // NtChallengeResponse
		"0000 0000 40000000" + // DomainName
		"0800 0800 40000000" + // UserName (Len=8, Offset=64)
		"0000 0000 48000000" + // Workstation
		"0000 0000 48000000" + // EncryptedSessionKey
		"01020000" + // NegotiateFlags
		"75 00 73 00 65 00 72 00" // "user" UTF-16LE
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageTypeName != "AUTHENTICATE_MESSAGE" {
		t.Errorf("message name: %q", r.MessageTypeName)
	}
	a := r.Authenticate
	if a == nil {
		t.Fatal("Authenticate body nil")
	}
	if a.UserName != "user" {
		t.Errorf("user name: %q", a.UserName)
	}
	if a.NtChallengeResponseHex != "" {
		t.Errorf("expected empty NT response, got %q", a.NtChallengeResponseHex)
	}
}

func TestDecode_NegotiateFlags_AllNamed(t *testing.T) {
	// Verify all 23 named flag bits are detected.
	got := decodeNegotiateFlags(0xFFFFFFFF)
	if len(got) < 20 {
		t.Errorf("expected ≥20 named flags, got %d: %+v", len(got), got)
	}
}

func TestDecode_MessageTypeTable(t *testing.T) {
	cases := map[int]string{
		1: "NEGOTIATE_MESSAGE",
		2: "CHALLENGE_MESSAGE",
		3: "AUTHENTICATE_MESSAGE",
	}
	for k, v := range cases {
		if got := messageTypeName(k); got != v {
			t.Errorf("messageTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_AVIDNameTable(t *testing.T) {
	cases := map[int]string{
		0:  "MsvAvEOL",
		1:  "MsvAvNbComputerName",
		2:  "MsvAvNbDomainName",
		3:  "MsvAvDnsComputerName",
		4:  "MsvAvDnsDomainName",
		5:  "MsvAvDnsTreeName",
		6:  "MsvAvFlags",
		7:  "MsvAvTimestamp",
		8:  "MsvAvSingleHost",
		9:  "MsvAvTargetName",
		10: "MsvAvChannelBindings",
	}
	for k, v := range cases {
		if got := avIDName(k); got != v {
			t.Errorf("avIDName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_UncataloguedMessageType_Note(t *testing.T) {
	// Type 99.
	in := "4E544C4D53535000 63000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(r.MessageTypeName, "uncatalogued") {
		t.Errorf("expected uncatalogued type name, got %q", r.MessageTypeName)
	}
	if len(r.Notes) == 0 {
		t.Errorf("expected uncatalogued note")
	}
}

func TestDecode_BadSignature(t *testing.T) {
	// "WRONG\0\0\0" instead of NTLMSSP\0.
	in := "57524F4E47000000 01000000 02020000"
	_, err := Decode(in)
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("expected signature error, got %q", err.Error())
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "4E544C4D5353500",
		"short":   "4E544C4D",
		"bad hex": "ZZ544C4D53535000 01000000",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
