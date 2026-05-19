package tools

import (
	"context"
	"strings"
	"testing"
)

// TestQUICLongHeaderDecodeHandler_Initial pins a QUIC v1
// Initial packet through the Spec handler.
func TestQUICLongHeaderDecodeHandler_Initial(t *testing.T) {
	in := "C0 00000001 08 0102030405060708 00 00 04 AABBCCDD"
	out, err := quicLongHeaderDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"long_packet_type_name": "Initial"`,
		`"version_name": "QUIC v1 (RFC 9000)"`,
		`"dcid_hex": "0102030405060708"`,
		`"protected_payload_hex": "AABBCCDD"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestQUICLongHeaderDecodeHandler_VersionNegotiation pins a
// Version Negotiation packet.
func TestQUICLongHeaderDecodeHandler_VersionNegotiation(t *testing.T) {
	in := "C0 00000000 04 AABBCCDD 04 11223344 00000001 FF000022"
	out, err := quicLongHeaderDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"long_packet_type_name": "Version Negotiation"`) {
		t.Errorf("expected Version Negotiation:\n%s", out)
	}
	if !strings.Contains(out, `"supported_versions_hex": [`) {
		t.Errorf("expected supported_versions:\n%s", out)
	}
}

func TestQUICLongHeaderDecodeHandler_ShortHeaderNote(t *testing.T) {
	out, err := quicLongHeaderDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "40 DEADBEEF"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "short") {
		t.Errorf("expected short header note:\n%s", out)
	}
}

func TestQUICLongHeaderDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := quicLongHeaderDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
