package tools

import (
	"context"
	"strings"
	"testing"
)

// TestDHCPv6DecodeHandler_SOLICIT pins a canonical DHCPv6
// SOLICIT with ClientID + IA_NA + ORO + Elapsed Time.
func TestDHCPv6DecodeHandler_SOLICIT(t *testing.T) {
	in := "01 ABCDEF" +
		"0001 000E 0001 0001 12345678 001122334455" +
		"0003 000C 00000001 00000E10 00001C20" +
		"0006 0004 0017 0018" +
		"0008 0002 0064"
	out, err := dhcpv6DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "SOLICIT"`,
		`"transaction_id": 11259375`, // 0xABCDEF = 11259375
		`"code_name": "OPTION_CLIENTID"`,
		`"type_name": "DUID-LLT (Link-Layer + Time)"`,
		`"code_name": "OPTION_IA_NA"`,
		`"iaid": 1`,
		`"t1_seconds": 3600`,
		`"code_name": "OPTION_ORO"`,
		`"code_name": "OPTION_ELAPSED_TIME"`,
		`"elapsed_time_centiseconds": 100`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestDHCPv6DecodeHandler_ADVERTISE pins an ADVERTISE with
// ServerID DUID-EN + IA_NA carrying IAADDR.
func TestDHCPv6DecodeHandler_ADVERTISE(t *testing.T) {
	in := "02 ABCDEF" +
		"0002 000E 0002 00000009 0123456789ABCDEF" +
		"0003 0028 00000001 00000E10 00001C20" +
		"0005 0018 20010DB8000000000000000000000001 00015180 0002A300"
	out, err := dhcpv6DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "ADVERTISE"`,
		`"type_name": "DUID-EN (Enterprise)"`,
		`"enterprise_number": 9`,
		`"address": "2001:db8::1"`,
		`"preferred_lifetime_seconds": 86400`,
		`"valid_lifetime_seconds": 172800`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestDHCPv6DecodeHandler_RELAY_FORW pins relay-forward
// header + encapsulated message option.
func TestDHCPv6DecodeHandler_RELAY_FORW(t *testing.T) {
	in := "0C 01" +
		"FE800000 00000000 00000000 00000001" +
		"FE800000 00000000 00000000 00000002" +
		"0009 0004 01ABCDEF"
	out, err := dhcpv6DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "RELAY-FORW"`,
		`"hop_count": 1`,
		`"link_address": "fe80::1"`,
		`"peer_address": "fe80::2"`,
		`"relay_message_hex": "01ABCDEF"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestDHCPv6DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := dhcpv6DecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
