// SPDX-License-Identifier: AGPL-3.0-or-later

package socks

import "testing"

// IPv4 / IPv6 SOCKS5 request+reply and the SOCKS4 request vectors were
// cross-checked against scapy's SOCKS layer. The SOCKS5 domain and SOCKS4
// reply vectors are hand-built to RFC 1928 (scapy's layer is wrong for
// both — see the package doc).

func TestDecodeV5ConnectIPv4(t *testing.T) {
	const v = "050100010102030401bb" // scapy-verified
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 5 {
		t.Fatalf("version = %d", r.Version)
	}
	if r.CommandName != "CONNECT" {
		t.Errorf("command = %q", r.CommandName)
	}
	if r.AddressType != "ipv4" || r.DestAddress != "1.2.3.4" {
		t.Errorf("dest = %q/%q", r.AddressType, r.DestAddress)
	}
	if r.DestPort == nil || *r.DestPort != 443 {
		t.Errorf("port = %v, want 443", r.DestPort)
	}
}

func TestDecodeV5ConnectIPv6(t *testing.T) {
	const v = "0501000420010db80000000000000000000000011f90" // scapy-verified
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.AddressType != "ipv6" || r.DestAddress != "2001:db8::1" {
		t.Errorf("dest = %q/%q", r.AddressType, r.DestAddress)
	}
	if r.DestPort == nil || *r.DestPort != 8080 {
		t.Errorf("port = %v, want 8080", r.DestPort)
	}
}

func TestDecodeV5ReplyOK(t *testing.T) {
	const v = "050000010a0000010438" // scapy-verified
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageKind != "socks5_reply" {
		t.Fatalf("kind = %q", r.MessageKind)
	}
	if r.ReplyCode == nil || *r.ReplyCode != 0 || r.ReplyName != "succeeded" {
		t.Errorf("reply = %v/%q", r.ReplyCode, r.ReplyName)
	}
	if r.DestAddress != "10.0.0.1" || r.DestPort == nil || *r.DestPort != 1080 {
		t.Errorf("bound = %q:%v", r.DestAddress, r.DestPort)
	}
}

func TestDecodeV5ConnectDomain(t *testing.T) {
	// RFC 1928: atyp 3 = 1-octet length (0x0B) + "example.com" + port 80.
	const v = "0501000" + "3" + "0b" + "6578616d706c652e636f6d" + "0050"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.AddressType != "domain" || r.DestAddress != "example.com" {
		t.Errorf("dest = %q/%q, want domain/example.com", r.AddressType, r.DestAddress)
	}
	if r.DestPort == nil || *r.DestPort != 80 {
		t.Errorf("port = %v, want 80", r.DestPort)
	}
}

func TestDecodeV5Greeting(t *testing.T) {
	const v = "05020001" // nmethods=2: no-auth, GSSAPI
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageKind != "socks5_greeting" {
		t.Fatalf("kind = %q", r.MessageKind)
	}
	if len(r.AuthMethods) != 2 || r.AuthMethods[0] != "no authentication" || r.AuthMethods[1] != "GSSAPI" {
		t.Errorf("methods = %v", r.AuthMethods)
	}
}

func TestDecodeV5MethodSelection(t *testing.T) {
	const v = "0500"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageKind != "socks5_method_selection" || r.AuthMethods[0] != "no authentication" {
		t.Errorf("method-select = %q/%v", r.MessageKind, r.AuthMethods)
	}
}

func TestDecodeV4Connect(t *testing.T) {
	const v = "0401001709080706726f6f7400" // scapy-verified
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 4 || r.CommandName != "CONNECT" {
		t.Fatalf("ver/cmd = %d/%q", r.Version, r.CommandName)
	}
	if r.DestAddress != "9.8.7.6" || r.DestPort == nil || *r.DestPort != 23 {
		t.Errorf("dest = %q:%v", r.DestAddress, r.DestPort)
	}
	if r.UserID != "root" {
		t.Errorf("userid = %q", r.UserID)
	}
}

func TestDecodeV4Reply(t *testing.T) {
	// RFC: 8-byte reply VN(0) CD(90) DSTPORT(23) DSTIP(9.8.7.6).
	const v = "005a001709080706"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageKind != "socks4_reply" {
		t.Fatalf("kind = %q", r.MessageKind)
	}
	if r.ReplyCode == nil || *r.ReplyCode != 90 || r.ReplyName != "request granted" {
		t.Errorf("reply = %v/%q", r.ReplyCode, r.ReplyName)
	}
	if r.DestAddress != "9.8.7.6" {
		t.Errorf("dstip = %q", r.DestAddress)
	}
}

func TestDecodeV4a(t *testing.T) {
	// SOCKS4a: dstip 0.0.0.1 signals a domain after the userid.
	// VN4 CD1 PORT(0050=80) IP(00000001) userid("")NUL domain("host.example")NUL
	const v = "0401005000000001" + "00" + "686f73742e6578616d706c6500"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.AddressType != "domain" || r.DestAddress != "host.example" {
		t.Errorf("socks4a dest = %q/%q", r.AddressType, r.DestAddress)
	}
}

func TestDecodeAmbiguousV5(t *testing.T) {
	// Leading byte 1 with rsv=0 + atyp=ipv4 is ambiguous (CONNECT or a reply).
	const v = "050100010102030401bb"
	r, _ := Decode(v)
	if r.MessageKind != "socks5_request_or_reply" {
		t.Errorf("kind = %q, want socks5_request_or_reply", r.MessageKind)
	}
}

func TestDecodeRejectsAndTruncations(t *testing.T) {
	if _, err := Decode("ff00"); err == nil {
		t.Error("expected rejection of unknown version")
	}
	if _, err := Decode("04"); err == nil {
		t.Error("expected error on too-short input")
	}
}
