package tools

import (
	"context"
	"strings"
	"testing"
)

// TestHSRPDecodeHandler_V1HelloDefault pins a canonical
// HSRPv1 Hello with default Cisco priority + auth.
func TestHSRPDecodeHandler_V1HelloDefault(t *testing.T) {
	in := "00 00 10 03 0A 64 01 00 63697363 6F000000 C0A80101"
	out, err := hsrpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"op_code_name": "Hello"`,
		`"state_name": "Active"`,
		`"priority": 100`,
		`"authentication_text": "cisco"`,
		`"virtual_ipv4_address": "192.168.1.1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestHSRPDecodeHandler_V2GroupState pins a v2 Group State
// TLV with IPv4 virtual IP.
func TestHSRPDecodeHandler_V2GroupState(t *testing.T) {
	in := "01 28" +
		"02 00 05 04 000A 001122334455" +
		"000000C8 00000BB8 00002710" +
		"C0A80101 000000000000000000000000"
	out, err := hsrpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Group State"`,
		`"state_name": "Active"`,
		`"identifier_mac": "00:11:22:33:44:55"`,
		`"priority": 200`,
		`"hello_time_ms": 3000`,
		`"virtual_ip_address": "192.168.1.1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestHSRPDecodeHandler_V2MD5Auth pins the v2 MD5
// authentication TLV.
func TestHSRPDecodeHandler_V2MD5Auth(t *testing.T) {
	in := "03 1C 01 00 0000 0A000001 00000001 00112233445566778899AABBCCDDEEFF"
	out, err := hsrpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "MD5 Authentication"`,
		`"algorithm": 1`,
		`"ip_address": "10.0.0.1"`,
		`"digest_hex": "00112233445566778899AABBCCDDEEFF"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestHSRPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := hsrpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
