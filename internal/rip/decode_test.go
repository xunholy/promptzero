package rip

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// ripHeader builds the 4-byte RIP header.
func ripHeader(command, version uint8) []byte {
	return []byte{command, version, 0x00, 0x00}
}

// ripv2Route builds a 20-byte RIPv2 route entry.
func ripv2Route(af, tag uint16, ip, mask, nexthop [4]byte, metric uint32) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, af)
	b = binary.BigEndian.AppendUint16(b, tag)
	b = append(b, ip[:]...)
	b = append(b, mask[:]...)
	b = append(b, nexthop[:]...)
	b = binary.BigEndian.AppendUint32(b, metric)
	return b
}

// ripv1Route builds a 20-byte RIPv1 route entry (mask/nexthop fields zeroed).
func ripv1Route(ip [4]byte, metric uint32) []byte {
	return ripv2Route(afINET, 0, ip, [4]byte{}, [4]byte{}, metric)
}

// ripv2AuthEntry builds a 20-byte RIPv2 authentication entry.
func ripv2AuthEntry(authType uint16, password string) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, afAuth)
	b = binary.BigEndian.AppendUint16(b, authType)
	pw := make([]byte, 16)
	copy(pw, []byte(password))
	b = append(b, pw...)
	return b
}

// TestDecode_RIPv2_Response_TwoRoutes validates a standard RIPv2
// Response with two route entries.
func TestDecode_RIPv2_Response_TwoRoutes(t *testing.T) {
	var pkt []byte
	pkt = append(pkt, ripHeader(cmdResponse, 2)...)
	pkt = append(pkt, ripv2Route(
		afINET, 10,
		[4]byte{10, 0, 0, 0}, [4]byte{255, 0, 0, 0}, [4]byte{10, 0, 0, 1},
		3,
	)...)
	pkt = append(pkt, ripv2Route(
		afINET, 20,
		[4]byte{192, 168, 1, 0}, [4]byte{255, 255, 255, 0}, [4]byte{192, 168, 1, 1},
		2,
	)...)

	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != 2 {
		t.Errorf("version=%d, want 2", r.Version)
	}
	if r.CommandName != "Response" {
		t.Errorf("command_name=%q, want Response", r.CommandName)
	}
	if !r.IsResponse {
		t.Error("expected IsResponse=true")
	}
	if r.IsRequest {
		t.Error("expected IsRequest=false")
	}
	if r.RouteCount != 2 {
		t.Errorf("route_count=%d, want 2", r.RouteCount)
	}
	if len(r.Routes) != 2 {
		t.Fatalf("routes len=%d, want 2", len(r.Routes))
	}
	if r.Routes[0].IPAddress != "10.0.0.0" {
		t.Errorf("routes[0].ip=%q, want 10.0.0.0", r.Routes[0].IPAddress)
	}
	if r.Routes[0].SubnetMask != "255.0.0.0" {
		t.Errorf("routes[0].mask=%q, want 255.0.0.0", r.Routes[0].SubnetMask)
	}
	if r.Routes[0].NextHop != "10.0.0.1" {
		t.Errorf("routes[0].nexthop=%q, want 10.0.0.1", r.Routes[0].NextHop)
	}
	if r.Routes[0].Metric != 3 {
		t.Errorf("routes[0].metric=%d, want 3", r.Routes[0].Metric)
	}
	if r.Routes[0].RouteTag != 10 {
		t.Errorf("routes[0].tag=%d, want 10", r.Routes[0].RouteTag)
	}
	if r.Routes[1].IPAddress != "192.168.1.0" {
		t.Errorf("routes[1].ip=%q, want 192.168.1.0", r.Routes[1].IPAddress)
	}
	if r.HasAuth {
		t.Error("expected HasAuth=false")
	}
	if r.HasInfinityMetric {
		t.Error("expected HasInfinityMetric=false")
	}
}

// TestDecode_RIPv2_SimplePasswordAuth validates cleartext auth
// detection (type 2 — password transmitted in plaintext).
func TestDecode_RIPv2_SimplePasswordAuth(t *testing.T) {
	var pkt []byte
	pkt = append(pkt, ripHeader(cmdResponse, 2)...)
	pkt = append(pkt, ripv2AuthEntry(authTypePassword, "s3cr3tkey")...)
	pkt = append(pkt, ripv2Route(
		afINET, 0,
		[4]byte{172, 16, 0, 0}, [4]byte{255, 255, 0, 0}, [4]byte{172, 16, 0, 1},
		1,
	)...)

	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if !r.HasAuth {
		t.Error("expected HasAuth=true")
	}
	if r.AuthType != authTypePassword {
		t.Errorf("auth_type=%d, want %d", r.AuthType, authTypePassword)
	}
	if r.AuthTypeName != "Simple Password (cleartext)" {
		t.Errorf("auth_type_name=%q, want 'Simple Password (cleartext)'", r.AuthTypeName)
	}
	if !r.IsCleartextAuth {
		t.Error("expected IsCleartextAuth=true for simple password")
	}
	if r.CleartextFlag == "" {
		t.Error("expected non-empty CleartextFlag")
	}
	// Auth entry must not count as a route
	if r.RouteCount != 1 {
		t.Errorf("route_count=%d, want 1 (auth entry excluded)", r.RouteCount)
	}
}

// TestDecode_RIPv1_Request validates a minimal RIPv1 Request.
func TestDecode_RIPv1_Request(t *testing.T) {
	var pkt []byte
	pkt = append(pkt, ripHeader(cmdRequest, 1)...)
	// RIPv1 request for full table: AF=0, metric=16
	pkt = append(pkt, ripv1Route([4]byte{}, metricInfinity)...)

	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != 1 {
		t.Errorf("version=%d, want 1", r.Version)
	}
	if r.CommandName != "Request" {
		t.Errorf("command_name=%q, want Request", r.CommandName)
	}
	if !r.IsRequest {
		t.Error("expected IsRequest=true")
	}
	if r.IsResponse {
		t.Error("expected IsResponse=false")
	}
}

// TestDecode_MetricInfinity validates that metric=16 sets
// HasInfinityMetric and is treated as a black-hole/withdrawal.
func TestDecode_MetricInfinity(t *testing.T) {
	var pkt []byte
	pkt = append(pkt, ripHeader(cmdResponse, 2)...)
	// normal route
	pkt = append(pkt, ripv2Route(
		afINET, 0,
		[4]byte{10, 1, 0, 0}, [4]byte{255, 255, 0, 0}, [4]byte{10, 1, 0, 1},
		4,
	)...)
	// infinity route (withdrawal / black-hole attack)
	pkt = append(pkt, ripv2Route(
		afINET, 0,
		[4]byte{10, 2, 0, 0}, [4]byte{255, 255, 0, 0}, [4]byte{},
		metricInfinity,
	)...)

	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if !r.HasInfinityMetric {
		t.Error("expected HasInfinityMetric=true")
	}
	if r.RouteCount != 2 {
		t.Errorf("route_count=%d, want 2", r.RouteCount)
	}
}

// TestDecode_RejectsEmpty confirms that an empty string is rejected.
func TestDecode_RejectsEmpty(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

// TestDecode_RejectsTruncated confirms that fewer than 4 bytes is rejected.
func TestDecode_RejectsTruncated(t *testing.T) {
	_, err := Decode("020200") // only 3 bytes
	if err == nil {
		t.Fatal("want error for truncated input")
	}
}
