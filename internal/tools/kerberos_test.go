package tools

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

// derTag builds a single TLV: tag byte + length + content.
func krbDerTag(t byte, content []byte) []byte {
	l := krbDerLength(len(content))
	out := append([]byte{t}, l...)
	return append(out, content...)
}

func krbDerLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n < 0x100 {
		return []byte{0x81, byte(n)}
	}
	if n < 0x10000 {
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
	return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
}

func krbDerInteger(v int) []byte {
	if v == 0 {
		return krbDerTag(0x02, []byte{0x00})
	}
	var bytes []byte
	for v > 0 {
		bytes = append([]byte{byte(v & 0xFF)}, bytes...)
		v >>= 8
	}
	if bytes[0]&0x80 != 0 {
		bytes = append([]byte{0x00}, bytes...)
	}
	return krbDerTag(0x02, bytes)
}

func krbDerGS(s string) []byte {
	return krbDerTag(0x1B, []byte(s))
}

func krbDerSequence(items ...[]byte) []byte {
	var content []byte
	for _, it := range items {
		content = append(content, it...)
	}
	return krbDerTag(0x30, content)
}

func krbCtx(n int, content []byte) []byte {
	return krbDerTag(byte(0xA0|n), content)
}

func krbDerPrincipal(nameType int, parts ...string) []byte {
	var strs []byte
	for _, p := range parts {
		strs = append(strs, krbDerGS(p)...)
	}
	return krbDerSequence(
		krbCtx(0, krbDerInteger(nameType)),
		krbCtx(1, krbDerSequence(strs)),
	)
}

// TestKerberosDecodeHandler_ASREQRoastable pins an AS-REQ WITHOUT
// PA-ENC-TIMESTAMP — the AS-REP-roastable shape.
func TestKerberosDecodeHandler_ASREQRoastable(t *testing.T) {
	cname := krbDerPrincipal(1, "admin")
	realm := krbDerGS("CORP.EXAMPLE.COM")
	sname := krbDerPrincipal(2, "krbtgt", "CORP.EXAMPLE.COM")
	etypeSeq := krbDerSequence(
		krbDerInteger(18), krbDerInteger(17), krbDerInteger(23))
	reqBody := krbDerSequence(
		krbCtx(1, cname),
		krbCtx(2, realm),
		krbCtx(3, sname),
		krbCtx(8, etypeSeq),
	)
	kdcReq := krbDerSequence(
		krbCtx(1, krbDerInteger(5)),
		krbCtx(2, krbDerInteger(10)),
		krbCtx(4, reqBody),
	)
	msg := krbDerTag(0x6A, kdcReq)
	out, err := kerberosDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "AS-REQ"`,
		`"realm": "CORP.EXAMPLE.COM"`,
		`"client_name": "admin"`,
		`"server_name": "krbtgt/CORP.EXAMPLE.COM"`,
		`"pre_auth_required": false`,
		`"aes256-cts-hmac-sha1-96"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestKerberosDecodeHandler_TGSREQ pins a Kerberoasting recon
// shape — TGS-REQ targeting an SPN.
func TestKerberosDecodeHandler_TGSREQ(t *testing.T) {
	sname := krbDerPrincipal(2,
		"MSSQLSvc", "sql01.corp.example.com:1433")
	reqBody := krbDerSequence(
		krbCtx(2, krbDerGS("CORP.EXAMPLE.COM")),
		krbCtx(3, sname),
		krbCtx(8, krbDerSequence(krbDerInteger(23))),
	)
	kdcReq := krbDerSequence(
		krbCtx(1, krbDerInteger(5)),
		krbCtx(2, krbDerInteger(12)),
		krbCtx(4, reqBody),
	)
	msg := krbDerTag(0x6C, kdcReq)
	out, err := kerberosDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "TGS-REQ"`,
		`"server_name": "MSSQLSvc/sql01.corp.example.com:1433"`,
		`"rc4-hmac (legacy NT-compat; weak)"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestKerberosDecodeHandler_KRBErrorPreauthRequired pins the
// canonical "NOT AS-REP roastable" response.
func TestKerberosDecodeHandler_KRBErrorPreauthRequired(t *testing.T) {
	errBody := krbDerSequence(
		krbCtx(6, krbDerInteger(25)),
		krbCtx(9, krbDerGS("CORP.LOCAL")),
	)
	msg := krbDerTag(0x7E, errBody)
	out, err := kerberosDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "KRB-ERROR"`,
		`"error_code": 25`,
		`"error_code_name": "KDC_ERR_PREAUTH_REQUIRED"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestKerberosDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := kerberosDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
