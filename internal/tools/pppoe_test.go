package tools

import (
	"context"
	"strings"
	"testing"
)

// TestPPPoEDecodeHandler_PADI pins a Discovery-stage PADI
// through the Spec handler.
func TestPPPoEDecodeHandler_PADI(t *testing.T) {
	in := "11 09 0000 000C 0101 0000 0103 0004 DEADBEEF"
	out, err := pppoeDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"code_name": "PADI (PPPoE Active Discovery Initiation)"`,
		`"is_discovery": true`,
		`"type_name": "Service-Name"`,
		`"type_name": "Host-Uniq (client-chosen request cookie)"`,
		`"value_hex": "DEADBEEF"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestPPPoEDecodeHandler_Session_IPv4 pins a Session-stage
// PPPoE packet carrying an IPv4 PPP frame.
func TestPPPoEDecodeHandler_Session_IPv4(t *testing.T) {
	in := "11 00 5678 0016 0021" +
		"45000014 12340000 40110000 7F000001 7F000001"
	out, err := pppoeDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"is_session": true`) {
		t.Errorf("expected is_session true:\n%s", out)
	}
	if !strings.Contains(out, `"ppp_protocol_name": "IPv4"`) {
		t.Errorf("expected IPv4 protocol name:\n%s", out)
	}
	if !strings.Contains(out, `"session_id_hex": "0x5678"`) {
		t.Errorf("expected session id 0x5678:\n%s", out)
	}
}

func TestPPPoEDecodeHandler_PADT_TearDown(t *testing.T) {
	out, err := pppoeDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "11 A7 1234 0000"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "PADT") {
		t.Errorf("expected PADT:\n%s", out)
	}
}

func TestPPPoEDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := pppoeDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
