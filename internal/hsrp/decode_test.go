package hsrp

import (
	"strings"
	"testing"
)

func TestDecode_V1_Hello_DefaultCiscoAuth(t *testing.T) {
	// Version=0, Op=0 Hello, State=16 Active, Hellotime=3,
	// Holdtime=10, Priority=100, Group=1, Reserved=0,
	// Auth="cisco\0\0\0", Virtual IP=192.168.1.1.
	in := "00 00 10 03 0A 64 01 00 63697363 6F000000 C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 0 {
		t.Errorf("version: %d", r.Version)
	}
	v := r.V1
	if v == nil {
		t.Fatal("V1 body nil")
	}
	if v.OpCodeName != "Hello" {
		t.Errorf("op code: %q", v.OpCodeName)
	}
	if v.StateName != "Active" {
		t.Errorf("state: %q", v.StateName)
	}
	if v.HelloTimeSeconds != 3 || v.HoldTimeSeconds != 10 {
		t.Errorf("timers: hello=%d hold=%d",
			v.HelloTimeSeconds, v.HoldTimeSeconds)
	}
	if v.Priority != 100 {
		t.Errorf("priority: %d", v.Priority)
	}
	if !strings.Contains(v.PriorityNote, "default Cisco priority") {
		t.Errorf("priority note: %q", v.PriorityNote)
	}
	if v.AuthenticationText != "cisco" {
		t.Errorf("auth text: %q", v.AuthenticationText)
	}
	if v.VirtualIPv4Address != "192.168.1.1" {
		t.Errorf("virtual IP: %q", v.VirtualIPv4Address)
	}
}

func TestDecode_V1_Coup_Standby(t *testing.T) {
	// Op=1 Coup, State=8 Standby, Priority=200.
	in := "00 01 08 03 0A C8 02 00 70617373776F726400 0A000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	v := r.V1
	if v.OpCodeName != "Coup" {
		t.Errorf("op code: %q", v.OpCodeName)
	}
	if v.StateName != "Standby" {
		t.Errorf("state: %q", v.StateName)
	}
	if v.Priority != 200 {
		t.Errorf("priority: %d", v.Priority)
	}
	if v.AuthenticationText != "password" {
		t.Errorf("auth text: %q", v.AuthenticationText)
	}
}

func TestDecode_V1_Priority0_Withdraw(t *testing.T) {
	in := "00 00 00 03 0A 00 01 00 63697363 6F000000 C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.V1.Priority != 0 {
		t.Errorf("priority: %d", r.V1.Priority)
	}
	if !strings.Contains(r.V1.PriorityNote, "withdraw") {
		t.Errorf("priority note: %q", r.V1.PriorityNote)
	}
}

func TestDecode_V1_Priority255_Max(t *testing.T) {
	in := "00 00 10 03 0A FF 01 00 63697363 6F000000 C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(r.V1.PriorityNote, "maximum") {
		t.Errorf("priority note: %q", r.V1.PriorityNote)
	}
}

func TestDecode_V1_Resign(t *testing.T) {
	in := "00 02 02 03 0A 64 01 00 63697363 6F000000 C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.V1.OpCodeName != "Resign" {
		t.Errorf("op code: %q", r.V1.OpCodeName)
	}
	if r.V1.StateName != "Listen" {
		t.Errorf("state: %q", r.V1.StateName)
	}
}

func TestDecode_V2_GroupState_IPv4(t *testing.T) {
	// TLV Type=1 Length=40, body:
	//   Version=2, Op=0 Hello, State=5 Active, IPVer=4,
	//   Group=0x000A (10), MAC=00:11:22:33:44:55,
	//   Priority=200, HelloTimeMs=3000, HoldTimeMs=10000,
	//   Virtual IP=192.168.1.1 (4 + 12 zero pad).
	in := "01 28" +
		"02 00 05 04 000A 001122334455" +
		"000000C8 00000BB8 00002710" +
		"C0A80101 000000000000000000000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 {
		t.Errorf("version: %d", r.Version)
	}
	if len(r.V2TLVs) != 1 {
		t.Fatalf("TLVs: %d", len(r.V2TLVs))
	}
	gs := r.V2TLVs[0].GroupState
	if gs == nil {
		t.Fatal("group state nil")
	}
	if gs.OpCodeName != "Hello" {
		t.Errorf("op code: %q", gs.OpCodeName)
	}
	if gs.StateName != "Active" {
		t.Errorf("state: %q", gs.StateName)
	}
	if gs.Group != 10 {
		t.Errorf("group: %d", gs.Group)
	}
	if gs.IdentifierMAC != "00:11:22:33:44:55" {
		t.Errorf("MAC: %q", gs.IdentifierMAC)
	}
	if gs.Priority != 200 {
		t.Errorf("priority: %d", gs.Priority)
	}
	if gs.HelloTimeMs != 3000 || gs.HoldTimeMs != 10000 {
		t.Errorf("timers: hello=%d hold=%d", gs.HelloTimeMs, gs.HoldTimeMs)
	}
	if gs.VirtualIPAddress != "192.168.1.1" {
		t.Errorf("virtual IP: %q", gs.VirtualIPAddress)
	}
}

func TestDecode_V2_GroupState_IPv6(t *testing.T) {
	// v2 group state with IPv6 virtual IP fe80::1.
	in := "01 28" +
		"02 00 05 06 0001 AABBCCDDEEFF" +
		"00000064 00000BB8 00002710" +
		"FE80000000000000 0000000000000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	gs := r.V2TLVs[0].GroupState
	if gs.IPVersion != 6 {
		t.Errorf("IP version: %d", gs.IPVersion)
	}
	if gs.VirtualIPAddress != "fe80::1" {
		t.Errorf("virtual IPv6: %q", gs.VirtualIPAddress)
	}
}

func TestDecode_V2_TextAuth(t *testing.T) {
	// TLV Type=2, Length=9. AuthType=0, password "secret\0\0".
	in := "02 09 00 73656372657400 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.V2TLVs) != 1 || r.V2TLVs[0].TextAuth == nil {
		t.Fatalf("text auth: %+v", r.V2TLVs)
	}
	if r.V2TLVs[0].TextAuth.Password != "secret" {
		t.Errorf("password: %q", r.V2TLVs[0].TextAuth.Password)
	}
}

func TestDecode_V2_MD5Auth(t *testing.T) {
	// TLV Type=3, Length=28. Algorithm=1 (MD5), Padding=0,
	// Flags=0, IP=10.0.0.1, KeyID=1, 16-byte digest.
	in := "03 1C 01 00 0000 0A000001 00000001 00112233445566778899AABBCCDDEEFF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	md := r.V2TLVs[0].MD5Auth
	if md == nil {
		t.Fatal("MD5 auth nil")
	}
	if md.Algorithm != 1 {
		t.Errorf("algorithm: %d", md.Algorithm)
	}
	if md.IPAddress != "10.0.0.1" {
		t.Errorf("IP: %q", md.IPAddress)
	}
	if md.KeyID != 1 {
		t.Errorf("key ID: %d", md.KeyID)
	}
	if md.DigestHex != "00112233445566778899AABBCCDDEEFF" {
		t.Errorf("digest: %q", md.DigestHex)
	}
}

func TestDecode_V1_OpCodeTable(t *testing.T) {
	cases := map[int]string{
		0: "Hello",
		1: "Coup",
		2: "Resign",
	}
	for k, v := range cases {
		if got := opCodeName(k); got != v {
			t.Errorf("opCodeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_V1_StateTable(t *testing.T) {
	cases := map[int]string{
		0:  "Initial",
		1:  "Learn",
		2:  "Listen",
		4:  "Speak",
		8:  "Standby",
		16: "Active",
	}
	for k, v := range cases {
		if got := stateName(k); got != v {
			t.Errorf("stateName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_V2_StateTable(t *testing.T) {
	cases := map[int]string{
		0: "Initial",
		1: "Learn",
		2: "Listen",
		3: "Speak",
		4: "Standby",
		5: "Active",
	}
	for k, v := range cases {
		if got := v2StateName(k); got != v {
			t.Errorf("v2StateName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_TLVTypeTable(t *testing.T) {
	cases := map[int]string{
		1: "Group State",
		2: "Text Authentication",
		3: "MD5 Authentication",
	}
	for k, v := range cases {
		if got := tlvTypeName(k); got != v {
			t.Errorf("tlvTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_NonZeroVersionNote(t *testing.T) {
	// Version byte 0x05 — not v1's 0x00, not a v2 TLV.
	in := "05 00 10 03 0A 64 01 00 63697363 6F000000 C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "HSRPv1 expects 0x00") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected non-zero-version note in: %v", r.Notes)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":    "",
		"odd hex":  "0001",
		"short v1": "00 00 10 03 0A 64",
		"bad hex":  "ZZ 00 10 03 0A 64 01 00 63697363 6F000000 C0A80101",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
