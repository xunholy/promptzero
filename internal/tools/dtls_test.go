package tools

import (
	"context"
	"strings"
	"testing"
)

// dtlsRep returns a hex string repeating byte b n times.
func dtlsRep(n int, b byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, n*2)
	for i := 0; i < n; i++ {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0F]
	}
	return string(out)
}

// TestDTLSRecordDecodeHandler_ClientHello pins a DTLS 1.2
// ClientHello through the Spec handler.
func TestDTLSRecordDecodeHandler_ClientHello(t *testing.T) {
	in := "16FEFD0000000000000000003A" +
		"0100002E000000000000002E" +
		"FEFD" + dtlsRep(32, 0xAA) + "00" + "00" + "0004C02CC030" + "0100" + "0000"
	out, err := dtlsRecordDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"content_type_name": "Handshake"`,
		`"version": "DTLS 1.2"`,
		`"msg_type_name": "ClientHello"`,
		`"cipher_suite_count": 2`,
		`"cipher_suites_hex": "C02CC030"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestDTLSRecordDecodeHandler_HeartbleedHint pins the
// Heartbleed information-disclosure pattern detection.
func TestDTLSRecordDecodeHandler_HeartbleedHint(t *testing.T) {
	in := "18FEFD00010000000000070004010064FF"
	out, err := dtlsRecordDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "Heartbleed") {
		t.Errorf("expected Heartbleed hint:\n%s", out)
	}
	if !strings.Contains(out, "CVE-2014-0160") {
		t.Errorf("expected CVE reference:\n%s", out)
	}
}

func TestDTLSRecordDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := dtlsRecordDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestDTLSRecordDecodeHandler_RejectsTruncatedHeader(t *testing.T) {
	_, err := dtlsRecordDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "16FEFD0000"})
	if err == nil {
		t.Fatal("want error for truncated header")
	}
}
