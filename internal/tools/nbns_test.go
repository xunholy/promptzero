package tools

import (
	"context"
	"strings"
	"testing"
)

// nbnsEncodeName mirrors the test helper from internal/nbns —
// produces wire-format 32-byte encoding for a NetBIOS name +
// suffix-byte.
func nbnsEncodeName(name string, suffix byte) string {
	padded := make([]byte, 16)
	for i := 0; i < 15; i++ {
		if i < len(name) {
			padded[i] = name[i]
		} else {
			padded[i] = ' '
		}
	}
	padded[15] = suffix
	const digits = "0123456789ABCDEF"
	out := make([]byte, 64)
	for i := 0; i < 16; i++ {
		hi := 0x41 + (padded[i] >> 4)
		lo := 0x41 + (padded[i] & 0x0F)
		out[i*4] = digits[hi>>4]
		out[i*4+1] = digits[hi&0x0F]
		out[i*4+2] = digits[lo>>4]
		out[i*4+3] = digits[lo&0x0F]
	}
	return string(out)
}

// TestNBNSDecodeHandler_QueryWorkstation pins a canonical NBNS
// Workstation query.
func TestNBNSDecodeHandler_QueryWorkstation(t *testing.T) {
	enc := nbnsEncodeName("FILESERV01", 0x00)
	in := "1212 0110 0001 0000 0000 0000 " +
		"20 " + enc + " 00 0020 0001"
	out, err := nbnsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"transaction_id": 4626`,
		`"opcode_name": "QUERY"`,
		`"b_broadcast": true`,
		`"name": "FILESERV01"`,
		`"suffix_name": "Workstation"`,
		`"type_name": "NB"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestNBNSDecodeHandler_DomainControllerEnum pins enumeration of
// domain controllers via the suffix-0x1C lookup.
func TestNBNSDecodeHandler_DomainControllerEnum(t *testing.T) {
	enc := nbnsEncodeName("CORP", 0x1C)
	in := "AAAA 0110 0001 0000 0000 0000 " +
		"20 " + enc + " 00 0020 0001"
	out, err := nbnsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"name": "CORP"`,
		`"suffix_name": "Domain_Controllers"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestNBNSDecodeHandler_ResponseWithIP pins an NBNS response
// with compression pointer + NB-type RDATA carrying an IPv4.
func TestNBNSDecodeHandler_ResponseWithIP(t *testing.T) {
	enc := nbnsEncodeName("FILESERV01", 0x00)
	in := "1212 8580 0001 0001 0000 0000 " +
		"20 " + enc + " 00 0020 0001 " +
		"C00C 0020 0001 000003E8 0006 0000 C0A80101"
	out, err := nbnsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"qr_response": true`,
		`"aa_authoritative": true`,
		`"ttl": 1000`,
		`"192.168.1.1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestNBNSDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := nbnsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
