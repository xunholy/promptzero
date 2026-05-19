package tools

import (
	"context"
	"strings"
	"testing"
)

// TestSTPBPDUDecodeHandler_Configuration pins a classic STP
// Configuration BPDU through the Spec handler.
func TestSTPBPDUDecodeHandler_Configuration(t *testing.T) {
	in := "0000 00 00" +
		"00" +
		"8000 001122334455" +
		"00000000" +
		"8000 001122334455" +
		"8001" +
		"0000 1400 0200 0F00"
	out, err := stpBPDUDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"version_name": "STP (IEEE 802.1D)"`,
		`"bpdu_type_name": "Configuration BPDU"`,
		`"mac": "00:11:22:33:44:55"`,
		`"max_age_ms": 20000`,
		`"hello_time_ms": 2000`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSTPBPDUDecodeHandler_RSTP pins an RSTP BPDU.
func TestSTPBPDUDecodeHandler_RSTP(t *testing.T) {
	in := "0000 02 02" +
		"7C" +
		"8000 001122334455" +
		"00000000" +
		"8000 001122334455" +
		"8001" +
		"0000 1400 0200 0F00"
	out, err := stpBPDUDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"version_name": "RSTP (IEEE 802.1D-2004)"`) {
		t.Errorf("expected RSTP version:\n%s", out)
	}
	if !strings.Contains(out, `"port_role_name": "Designated"`) {
		t.Errorf("expected Designated port role:\n%s", out)
	}
}

// TestSTPBPDUDecodeHandler_TCN pins a TCN BPDU.
func TestSTPBPDUDecodeHandler_TCN(t *testing.T) {
	out, err := stpBPDUDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "00000080"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out,
		`"bpdu_type_name": "Topology Change Notification (TCN)"`) {
		t.Errorf("expected TCN:\n%s", out)
	}
}

func TestSTPBPDUDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := stpBPDUDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
