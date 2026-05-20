package tools

import (
	"context"
	"strings"
	"testing"
)

// TestSFlowV5DecodeHandler_FlowSample pins a canonical Flow
// Sample with a Raw Packet Header record.
func TestSFlowV5DecodeHandler_FlowSample(t *testing.T) {
	in := "00000005 00000001 C0A80101" +
		"00000001 0000007B 000F4240 00000001" +
		"00000001 0000003C" +
		"00000001 00000064 00000400 00002710 00000000" +
		"00000001 00000002 00000001" +
		"00000001 00000014" +
		"00000001 0000005E 00000004 00000010 DEADBEEF"
	out, err := sflowV5DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"version": 5`,
		`"agent_address": "192.168.1.1"`,
		`"format_name": "Flow Sample"`,
		`"sampling_rate": 1024`,
		`"format_name": "Raw Packet Header"`,
		`"header_protocol_name": "Ethernet ISO 88023"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSFlowV5DecodeHandler_EthernetFrame pins Ethernet Frame
// Data record decoding.
func TestSFlowV5DecodeHandler_EthernetFrame(t *testing.T) {
	in := "00000005 00000001 C0A80101" +
		"00000001 0000007B 000F4240 00000001" +
		"00000001 0000003C" +
		"00000001 00000064 00000400 00002710 00000000" +
		"00000001 00000002 00000001" +
		"00000002 00000014" +
		"00000040 001122334455 AABBCCDDEEFF 00000800"
	out, err := sflowV5DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"format_name": "Ethernet Frame Data"`,
		`"src_mac": "00:11:22:33:44:55"`,
		`"dst_mac": "aa:bb:cc:dd:ee:ff"`,
		`"ether_type_hex": "0x0800"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSFlowV5DecodeHandler_CounterSample pins Counter Sample
// with Generic Interface Counters.
func TestSFlowV5DecodeHandler_CounterSample(t *testing.T) {
	gif := "00000064" +
		"00000006" +
		"00000000 3B9ACA00" +
		"00000001" +
		"00000003" +
		"00000000 0000C350" +
		"00000064" +
		"0000000A" + "00000005" +
		"00000000" + "00000000" + "00000000" +
		"00000000 0000C350" +
		"00000064" +
		"00000000" + "00000000" +
		"00000000" + "00000000" +
		"00000000"
	in := "00000005 00000001 C0A80101" +
		"00000001 0000007B 000F4240 00000001" +
		"00000002 0000006C" +
		"00000001 00000064 00000001" +
		"00000001 00000058" + gif
	out, err := sflowV5DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"format_name": "Counter Sample"`,
		`"format_name": "Generic Interface Counters"`,
		`"if_index": 100`,
		`"if_speed": 1000000000`,
		`"if_in_octets": 50000`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestSFlowV5DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := sflowV5DecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
