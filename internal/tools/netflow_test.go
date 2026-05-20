package tools

import (
	"context"
	"strings"
	"testing"
)

// TestNetFlowV5DecodeHandler_OneTCPFlow pins a canonical
// NetFlow v5 packet with a single ACK-only TCP flow.
func TestNetFlowV5DecodeHandler_OneTCPFlow(t *testing.T) {
	in := "00050001 000003E8 60000000 00000000 00000065 0001 0000" +
		"C0A80101 0A000001 C0A80101 0001 0002" +
		"00000064 00002710 00000064 000003E8" +
		"01BB D431 00 10 06 00 0000 0000 18 18 0000"
	out, err := netflowV5DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"version": 5`,
		`"count": 1`,
		`"src_address": "192.168.1.1"`,
		`"dst_address": "10.0.0.1"`,
		`"src_port": 443`,
		`"dst_port": 54321`,
		`"protocol_name": "TCP"`,
		`"packets": 100`,
		`"bytes": 10000`,
		`"duration_ms": 900`,
		`"ack": true`,
		`"src_prefix": "192.168.1.1/24"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestNetFlowV5DecodeHandler_UDPFlow pins a DNS-like UDP flow.
func TestNetFlowV5DecodeHandler_UDPFlow(t *testing.T) {
	in := "00050001 00000000 00000000 00000000 00000001 0001 0000" +
		"08080808 C0A80101 00000000 0000 0000" +
		"00000001 00000040 00000000 00000000" +
		"0035 8000 00 00 11 00 0000 0000 00 00 0000"
	out, err := netflowV5DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"protocol_name": "UDP"`,
		`"src_address": "8.8.8.8"`,
		`"src_port": 53`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestNetFlowV5DecodeHandler_SamplingMode pins the
// random-sampling mode decode (mode 2, N=1000).
func TestNetFlowV5DecodeHandler_SamplingMode(t *testing.T) {
	in := "00050000 00000001 00000064 00000000 00000064 0001 83E8"
	out, err := netflowV5DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"sampling_mode": 2`,
		`"sampling_mode_name": "1-in-N random"`,
		`"sampling_interval": 1000`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestNetFlowV5DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := netflowV5DecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
