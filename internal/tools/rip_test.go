package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// ripTestHeader builds the 4-byte RIP header.
func ripTestHeader(command, version uint8) []byte {
	return []byte{command, version, 0x00, 0x00}
}

// ripTestRoute builds a 20-byte RIPv2 route entry.
func ripTestRoute(af, tag uint16, ip, mask, nexthop [4]byte, metric uint32) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, af)
	b = binary.BigEndian.AppendUint16(b, tag)
	b = append(b, ip[:]...)
	b = append(b, mask[:]...)
	b = append(b, nexthop[:]...)
	b = binary.BigEndian.AppendUint32(b, metric)
	return b
}

// ripTestAuthEntry builds a 20-byte RIPv2 simple-password auth entry.
func ripTestAuthEntry(authType uint16, password string) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, 0xFFFF) // auth marker
	b = binary.BigEndian.AppendUint16(b, authType)
	pw := make([]byte, 16)
	copy(pw, []byte(password))
	b = append(b, pw...)
	return b
}

// TestRIPDecodeHandler_ResponseWithRoutes pins a canonical RIPv2
// Response with two routes through the Spec handler.
func TestRIPDecodeHandler_ResponseWithRoutes(t *testing.T) {
	var pkt []byte
	pkt = append(pkt, ripTestHeader(2, 2)...) // Response, RIPv2
	pkt = append(pkt, ripTestRoute(
		0x0002, 0,
		[4]byte{10, 0, 0, 0}, [4]byte{255, 0, 0, 0}, [4]byte{10, 0, 0, 1},
		3,
	)...)
	pkt = append(pkt, ripTestRoute(
		0x0002, 5,
		[4]byte{192, 168, 10, 0}, [4]byte{255, 255, 255, 0}, [4]byte{192, 168, 10, 1},
		2,
	)...)

	out, err := ripDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command_name": "Response"`,
		`"version": 2`,
		`"is_response": true`,
		`"route_count": 2`,
		`"ip_address": "10.0.0.0"`,
		`"subnet_mask": "255.0.0.0"`,
		`"next_hop": "10.0.0.1"`,
		`"ip_address": "192.168.10.0"`,
		`"has_infinity_metric": false`,
		`"has_auth": false`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRIPDecodeHandler_CleartextAuth pins the simple-password
// cleartext credential exposure classification.
func TestRIPDecodeHandler_CleartextAuth(t *testing.T) {
	var pkt []byte
	pkt = append(pkt, ripTestHeader(2, 2)...) // Response, RIPv2
	pkt = append(pkt, ripTestAuthEntry(2, "opensesame")...)
	pkt = append(pkt, ripTestRoute(
		0x0002, 0,
		[4]byte{172, 16, 0, 0}, [4]byte{255, 255, 0, 0}, [4]byte{172, 16, 0, 1},
		1,
	)...)

	out, err := ripDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"has_auth": true`,
		`"auth_type": 2`,
		`"is_cleartext_auth": true`,
		`cleartext`,
		`"route_count": 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRIPDecodeHandler_RejectsEmpty confirms that an empty hex
// input returns an error.
func TestRIPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ripDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
