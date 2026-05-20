package tools

import (
	"context"
	"strings"
	"testing"
)

// TestESPDecodeHandler pins a canonical ESP packet.
func TestESPDecodeHandler(t *testing.T) {
	in := "CAFEBABE 00000001 0102030405060708 090A0B0C0D0E0F10"
	out, err := espDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"spi_hex": "0xCAFEBABE"`,
		`"sequence_number": 1`,
		`"encrypted_payload_bytes": 16`,
		`"encrypted_payload_hex": "0102030405060708090A0B0C0D0E0F10"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestAHDecodeHandler pins a canonical AH packet with HMAC-
// SHA1-96 ICV (12 bytes).
func TestAHDecodeHandler(t *testing.T) {
	in := "06 04 0000 CAFEBABE 00000001 0102030405060708090A0B0C"
	out, err := ahDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"next_header": 6`,
		`"next_header_name": "TCP"`,
		`"payload_length_field": 4`,
		`"header_total_bytes": 24`,
		`"icv_bytes": 12`,
		`"spi_hex": "0xCAFEBABE"`,
		`"sequence_number": 1`,
		`"icv_hex": "0102030405060708090A0B0C"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestAHDecodeHandler_TunnelModeIPv6 pins the IPv6-tunnel-mode
// inner-header name.
func TestAHDecodeHandler_TunnelModeIPv6(t *testing.T) {
	in := "29 04 0000 CAFEBABE 00000001 0102030405060708090A0B0C"
	out, err := ahDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"next_header_name": "IPv6 (tunnel mode inner header)"`) {
		t.Errorf("expected IPv6 tunnel mode name:\n%s", out)
	}
}

func TestESPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := espDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestAHDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ahDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
