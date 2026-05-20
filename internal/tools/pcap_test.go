package tools

import (
	"context"
	"strings"
	"testing"
)

// TestPCAPDecodeHandler_LittleEndianEthernet pins a canonical
// little-endian microsecond Ethernet pcap with one 4-byte record.
func TestPCAPDecodeHandler_LittleEndianEthernet(t *testing.T) {
	// Global header: magic D4C3B2A1 LE → 0xa1b2c3d4 (LE µs);
	// version 2.4; snaplen 65535; network 1 (Ethernet).
	// Record: ts_sec=100 (0x64), ts_frac=0, caplen=4, origlen=4,
	// payload DEADBEEF.
	in := "D4C3B2A1 02000400 00000000 00000000 FFFF0000 01000000" +
		"64000000 00000000 04000000 04000000" +
		"DEADBEEF"
	out, err := pcapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"endianness": "little"`,
		`"timestamp_resolution": "microsecond"`,
		`"version_major": 2`,
		`"snap_length": 65535`,
		`"network_name": "LINKTYPE_ETHERNET"`,
		`"record_count": 1`,
		`"payload_hex": "DEADBEEF"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestPCAPDecodeHandler_BigEndianRadiotap pins a big-endian
// nanosecond Radiotap pcap.
func TestPCAPDecodeHandler_BigEndianNanosecond(t *testing.T) {
	// magic 0x4d3cb2a1 stored LE → bytes A1 B2 3C 4D when read
	// as LE → no wait: LE-stored uint32 0x4d3cb2a1 = bytes
	// A1 B2 3C 4D. After LittleEndian.Uint32 we get 0x4d3cb2a1
	// → big-endian nanosecond. Reader then reads the rest BE.
	in := "A1B23C4D 0002 0004" + // magic LE-stored + ver BE
		"00000000 00000000" + // thiszone + sigfigs BE
		"0000FFFF" + // snaplen BE = 65535
		"0000007F" // network BE = 127 (Radiotap)
	out, err := pcapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"endianness": "big"`,
		`"timestamp_resolution": "nanosecond"`,
		`"network_name": "LINKTYPE_IEEE802_11_RADIOTAP"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestPCAPDecodeHandler_CapsApplied pins the max_records +
// max_payload_bytes caps.
func TestPCAPDecodeHandler_CapsApplied(t *testing.T) {
	// 3 records, each with 4-byte payload.
	in := "D4C3B2A1 02000400 00000000 00000000 FFFF0000 01000000" +
		"01000000 00000000 04000000 04000000 11223344" +
		"02000000 00000000 04000000 04000000 55667788" +
		"03000000 00000000 04000000 04000000 99AABBCC"
	out, err := pcapDecodeHandler(context.Background(), nil,
		map[string]any{
			"hex":               in,
			"max_records":       2,
			"max_payload_bytes": 2,
		})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"record_count": 3`) {
		t.Errorf("expected record_count 3:\n%s", out)
	}
	if !strings.Contains(out, `"records_parsed_in_hex_preview": 2`) {
		t.Errorf("expected records_parsed_in_hex_preview 2:\n%s", out)
	}
	if !strings.Contains(out, `"payload_hex": "1122"`) {
		t.Errorf("expected truncated payload preview:\n%s", out)
	}
}

func TestPCAPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := pcapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
