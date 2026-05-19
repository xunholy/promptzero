package bfd

import (
	"strings"
	"testing"
)

func TestDecode_BasicUpSession(t *testing.T) {
	// Version 1, Diag 0 (No Diag), State 3 (Up), no flags,
	// DetectMult 3, Length 24, MyDisc 1, YourDisc 2, TX=1s,
	// RX=1s, Echo=0.
	in := "20 C0 03 18 00000001 00000002 000F4240 000F4240 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 1 {
		t.Errorf("version: %d", r.Version)
	}
	if r.DiagnosticName != "No Diagnostic" {
		t.Errorf("diag: %q", r.DiagnosticName)
	}
	if r.StateName != "Up" {
		t.Errorf("state: %q", r.StateName)
	}
	if r.DetectMult != 3 {
		t.Errorf("detect mult: %d", r.DetectMult)
	}
	if r.MyDiscriminator != 1 || r.YourDiscriminator != 2 {
		t.Errorf("disc: my=%d your=%d", r.MyDiscriminator, r.YourDiscriminator)
	}
	if r.DesiredMinTXIntervalMs != 1000 {
		t.Errorf("TX ms: %d", r.DesiredMinTXIntervalMs)
	}
	if r.RequiredMinRXIntervalMs != 1000 {
		t.Errorf("RX ms: %d", r.RequiredMinRXIntervalMs)
	}
	if r.RequiredMinEchoRXIntervalMicros != 0 {
		t.Errorf("Echo us: %d (Echo disabled when 0)",
			r.RequiredMinEchoRXIntervalMicros)
	}
	if len(r.Notes) != 0 {
		t.Errorf("expected no notes, got %v", r.Notes)
	}
}

func TestDecode_DownStateWithPathDownDiagnostic(t *testing.T) {
	// Diag 5 (Path Down), State 1 (Down).
	in := "25 40 03 18 00000001 00000000 000F4240 000F4240 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.DiagnosticName != "Path Down" {
		t.Errorf("diag: %q", r.DiagnosticName)
	}
	if r.StateName != "Down" {
		t.Errorf("state: %q", r.StateName)
	}
}

func TestDecode_PollBitSet(t *testing.T) {
	// State 3 (Up) + Poll bit = 0xE0.
	in := "20 E0 03 18 00000001 00000002 000F4240 000F4240 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.FlagPoll {
		t.Errorf("Poll flag should be set")
	}
}

func TestDecode_InitState(t *testing.T) {
	// State 2 (Init).
	in := "20 80 03 18 00000001 00000000 000F4240 000F4240 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.StateName != "Init" {
		t.Errorf("state: %q", r.StateName)
	}
}

func TestDecode_AdminDownWithAdminDiag(t *testing.T) {
	// Diag 7 (Admin Down), State 0 (AdminDown).
	in := "27 00 03 18 00000001 00000000 000F4240 000F4240 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.DiagnosticName != "Administratively Down" {
		t.Errorf("diag: %q", r.DiagnosticName)
	}
	if r.StateName != "AdminDown" {
		t.Errorf("state: %q", r.StateName)
	}
}

func TestDecode_WithSimplePasswordAuth(t *testing.T) {
	// A flag set, Auth Section with Simple Password "password".
	// Auth: type 1, len 11, key 1, data "password" (8 bytes).
	// Total = 24 + 11 = 35 = 0x23.
	in := "20 C4 03 23 00000001 00000002 000F4240 000F4240 00000000" +
		"01 0B 01 70617373776F7264"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.FlagAuth {
		t.Errorf("Auth flag should be set")
	}
	if r.Authentication == nil {
		t.Fatal("Authentication nil")
	}
	a := r.Authentication
	if a.TypeName != "Simple Password" {
		t.Errorf("auth type: %q", a.TypeName)
	}
	if a.Length != 11 {
		t.Errorf("auth length: %d", a.Length)
	}
	if a.KeyID != 1 {
		t.Errorf("key ID: %d", a.KeyID)
	}
	if a.PasswordText != "password" {
		t.Errorf("password: %q", a.PasswordText)
	}
}

func TestDecode_WithKeyedMD5(t *testing.T) {
	// Auth type 2 (Keyed MD5), seq 0x12345678, 16-byte digest.
	// Auth Section: 3 (Type+Len+KeyID) + 1 (Reserved) + 4 (Seq) + 16 (MD5) = 24.
	// Total: 24 + 24 = 48 = 0x30.
	in := "20 C4 03 30 00000001 00000002 000F4240 000F4240 00000000" +
		"02 18 01" + "00" + "12345678" +
		"00112233445566778899AABBCCDDEEFF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := r.Authentication
	if a == nil {
		t.Fatal("Authentication nil")
	}
	if a.TypeName != "Keyed MD5" {
		t.Errorf("auth type: %q", a.TypeName)
	}
	if a.SequenceNumber == nil || *a.SequenceNumber != 0x12345678 {
		t.Errorf("seq: %+v", a.SequenceNumber)
	}
	if a.DigestHex != "00112233445566778899AABBCCDDEEFF" {
		t.Errorf("digest: %q", a.DigestHex)
	}
}

func TestDecode_DiagnosticTable(t *testing.T) {
	cases := map[int]string{
		0: "No Diagnostic",
		1: "Control Detection Time Expired",
		2: "Echo Function Failed",
		3: "Neighbor Signaled Session Down",
		4: "Forwarding Plane Reset",
		5: "Path Down",
		6: "Concatenated Path Down",
		7: "Administratively Down",
		8: "Reverse Concatenated Path Down",
	}
	for k, v := range cases {
		if got := diagnosticName(k); got != v {
			t.Errorf("diagnosticName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_StateTable(t *testing.T) {
	cases := map[int]string{
		0: "AdminDown", 1: "Down", 2: "Init", 3: "Up",
	}
	for k, v := range cases {
		if got := stateName(k); got != v {
			t.Errorf("stateName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_AuthTypeTable(t *testing.T) {
	cases := map[int]string{
		1: "Simple Password",
		2: "Keyed MD5",
		3: "Meticulous Keyed MD5",
		4: "Keyed SHA1",
		5: "Meticulous Keyed SHA1",
	}
	for k, v := range cases {
		if got := authTypeName(k); got != v {
			t.Errorf("authTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_DetectMultZeroNote(t *testing.T) {
	in := "20 C0 00 18 00000001 00000002 000F4240 000F4240 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "Detect Multiplier is 0") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Detect Mult 0 note in: %v", r.Notes)
	}
}

func TestDecode_VersionMismatchNote(t *testing.T) {
	// Version 2 (currently undefined).
	in := "40 C0 03 18 00000001 00000002 000F4240 000F4240 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 {
		t.Errorf("version: %d", r.Version)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "version is 2") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected version note in: %v", r.Notes)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":               "",
		"odd hex":             "20C003",
		"short":               "20C00318",
		"bad hex":             "ZZC003 18 00000001 00000002 000F4240 000F4240 00000000",
		"auth flag truncated": "20 C4 03 18 00000001 00000002 000F4240 000F4240 00000000",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
