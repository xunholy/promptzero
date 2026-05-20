package tools

import (
	"context"
	"strings"
	"testing"
)

// TestSOMEIPDecodeHandler_Request pins a canonical method call.
func TestSOMEIPDecodeHandler_Request(t *testing.T) {
	in := "1234 0001 0000000A 00AB 0001 01 02 00 00 DEAD"
	out, err := someipDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"service_id": 4660`, // 0x1234
		`"method_id": 1`,
		`"is_event": false`,
		`"length": 10`,
		`"client_id": 171`, // 0x00AB
		`"protocol_version": 1`,
		`"interface_version": 2`,
		`"message_type_name": "REQUEST"`,
		`"return_code_name": "E_OK"`,
		`"payload_hex": "DEAD"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSOMEIPDecodeHandler_SDOffer pins a Service Discovery
// OFFER_SERVICE notification with an IPv4 endpoint option.
func TestSOMEIPDecodeHandler_SDOffer(t *testing.T) {
	in := "FFFF 8100 0000003C 0000 0001 01 01 02 00 " +
		"C0 000000 00000010 " +
		"01 00 00 10 1234 0001 02 000003 00000005 " +
		"0000000C " +
		"0009 04 00 C0A80102 00 11 7530"
	out, err := someipDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "NOTIFICATION"`,
		`"reboot_flag": true`,
		`"unicast_flag": true`,
		`"type_name": "OFFER_SERVICE"`,
		`"ttl": 3`,
		`"minor_version": 5`,
		`"ip_address": "192.168.1.2"`,
		`"l4_protocol": "UDP"`,
		`"port": 30000`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSOMEIPDecodeHandler_ErrorTimeout pins ERROR + E_TIMEOUT.
func TestSOMEIPDecodeHandler_ErrorTimeout(t *testing.T) {
	in := "1234 0001 00000008 00AB 0001 01 02 81 06"
	out, err := someipDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "ERROR"`,
		`"return_code_name": "E_TIMEOUT"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestSOMEIPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := someipDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
