package vrrp

import (
	"strings"
	"testing"
)

func TestDecode_VRRPv2_Advertisement(t *testing.T) {
	// V=2, Type=1 (0x21), VRID=10, Priority=100, Count=1,
	// AuthType=0, AdverInt=1, Checksum=ABCD, IPv4 192.168.1.1.
	in := "21 0A 64 01 00 01 ABCD C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 || r.TypeName != "Advertisement" {
		t.Errorf("version/type: %d / %q", r.Version, r.TypeName)
	}
	if r.VRID != 10 {
		t.Errorf("VRID: %d", r.VRID)
	}
	if r.Priority != 100 {
		t.Errorf("priority: %d", r.Priority)
	}
	if r.AuthTypeName != "No Authentication" {
		t.Errorf("auth type: %q", r.AuthTypeName)
	}
	if r.AdverIntSeconds != 1 {
		t.Errorf("adver int: %d", r.AdverIntSeconds)
	}
	if r.AddressFamily != "IPv4" {
		t.Errorf("address family: %q", r.AddressFamily)
	}
	if len(r.VirtualAddresses) != 1 || r.VirtualAddresses[0] != "192.168.1.1" {
		t.Errorf("addresses: %+v", r.VirtualAddresses)
	}
	if !strings.Contains(r.PriorityNote, "100 — default backup priority") {
		t.Errorf("priority note: %q", r.PriorityNote)
	}
}

func TestDecode_VRRPv3_IPv4(t *testing.T) {
	// V=3, Type=1, VRID=5, Priority=200, Count=1,
	// Max Adver Int=100cs (1s), Checksum=ABCD, IPv4 192.168.1.1.
	in := "31 05 C8 01 0064 ABCD C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 3 {
		t.Errorf("version: %d", r.Version)
	}
	if r.MaxAdverIntCs != 100 || r.MaxAdverIntMs != 1000 {
		t.Errorf("max adver int: %d cs / %d ms",
			r.MaxAdverIntCs, r.MaxAdverIntMs)
	}
	if r.AddressFamily != "IPv4" {
		t.Errorf("address family: %q", r.AddressFamily)
	}
}

func TestDecode_VRRPv3_IPv6(t *testing.T) {
	// V=3, VRID=1, Priority=100, Count=1, IPv6 fe80::1.
	in := "31 01 64 01 0064 ABCD FE80000000000000 0000000000000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.AddressFamily != "IPv6" {
		t.Errorf("address family: %q", r.AddressFamily)
	}
	if len(r.VirtualAddresses) != 1 || r.VirtualAddresses[0] != "fe80::1" {
		t.Errorf("addresses: %+v", r.VirtualAddresses)
	}
}

func TestDecode_Priority0_Withdraw(t *testing.T) {
	in := "21 0A 00 01 00 01 ABCD C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Priority != 0 {
		t.Errorf("priority: %d", r.Priority)
	}
	if !strings.Contains(r.PriorityNote, "withdraw") {
		t.Errorf("priority note: %q", r.PriorityNote)
	}
}

func TestDecode_Priority255_IPOwner(t *testing.T) {
	in := "31 0A FF 01 0064 ABCD C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Priority != 255 {
		t.Errorf("priority: %d", r.Priority)
	}
	if !strings.Contains(r.PriorityNote, "IP address owner") {
		t.Errorf("priority note: %q", r.PriorityNote)
	}
}

func TestDecode_VRRPv2_SimpleTextAuth(t *testing.T) {
	// V=2, VRID=1, AuthType=1 (Simple Text), 8-byte password "secret\0\0".
	in := "21 01 64 01 01 01 ABCD C0A80101 7365637265740000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.AuthType != 1 {
		t.Errorf("auth type: %d", r.AuthType)
	}
	if !strings.Contains(r.AuthTypeName, "Simple Text Password") {
		t.Errorf("auth type name: %q", r.AuthTypeName)
	}
	if r.AuthDataText != "secret" {
		t.Errorf("auth text: %q", r.AuthDataText)
	}
	if r.VirtualAddresses[0] != "192.168.1.1" {
		t.Errorf("addresses: %+v", r.VirtualAddresses)
	}
}

func TestDecode_MultipleIPv4Addresses(t *testing.T) {
	// VRRPv3, Count=2, two IPv4 addresses 10.0.0.1 + 10.0.0.2.
	in := "31 0A 64 02 0064 ABCD 0A000001 0A000002"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.VirtualAddresses) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(r.VirtualAddresses))
	}
	if r.VirtualAddresses[0] != "10.0.0.1" || r.VirtualAddresses[1] != "10.0.0.2" {
		t.Errorf("addresses: %+v", r.VirtualAddresses)
	}
}

func TestDecode_TypeNonAdvertisement_Note(t *testing.T) {
	// Type=5 (uncatalogued).
	in := "25 0A 64 01 00 01 ABCD C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "only Type 1") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected non-Advertisement note in: %v", r.Notes)
	}
}

func TestDecode_VersionUnknown_Note(t *testing.T) {
	// Version=1 (predates RFC 3768).
	in := "11 0A 64 01 00 01 ABCD C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "version 1") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unknown-version note in: %v", r.Notes)
	}
}

func TestDecode_AuthTypeTable(t *testing.T) {
	cases := map[int]string{
		0: "No Authentication",
		1: "Simple Text Password (deprecated, RFC 5798 §9.3)",
		2: "IP Authentication Header (deprecated, RFC 2402)",
	}
	for k, v := range cases {
		if got := authTypeName(k); got != v {
			t.Errorf("authTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "210A6401",
		"short":   "210A640100",
		"bad hex": "ZZ0A6401 00 01 ABCD C0A80101",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
