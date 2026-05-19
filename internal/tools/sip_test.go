package tools

import (
	"context"
	"strings"
	"testing"
)

// TestSIPMessageDecodeHandler_INVITE pins a canonical INVITE
// request through the Spec handler.
func TestSIPMessageDecodeHandler_INVITE(t *testing.T) {
	msg := "INVITE sip:bob@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP alice.example.com;branch=z9hG4bK000\r\n" +
		"From: <sip:alice@example.com>;tag=abc\r\n" +
		"To: <sip:bob@example.com>\r\n" +
		"Call-ID: 12345\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	out, err := sipMessageDecodeHandler(context.Background(), nil, map[string]any{
		"message": msg,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"method": "INVITE"`) {
		t.Errorf("expected method INVITE:\n%s", out)
	}
	if !strings.Contains(out, `"request_uri": "sip:bob@example.com"`) {
		t.Errorf("expected request_uri:\n%s", out)
	}
	if !strings.Contains(out, `"call_id": "12345"`) {
		t.Errorf("expected call_id:\n%s", out)
	}
}

// TestSIPMessageDecodeHandler_200OK pins a 200 OK response.
func TestSIPMessageDecodeHandler_200OK(t *testing.T) {
	msg := "SIP/2.0 200 OK\r\n" +
		"Call-ID: 12345\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	out, err := sipMessageDecodeHandler(context.Background(), nil, map[string]any{
		"message": msg,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"is_response": true`) {
		t.Errorf("expected is_response true:\n%s", out)
	}
	if !strings.Contains(out, `"status_code": 200`) {
		t.Errorf("expected status_code 200:\n%s", out)
	}
	if !strings.Contains(out, `"status_name": "OK"`) {
		t.Errorf("expected status_name OK:\n%s", out)
	}
}

func TestSIPMessageDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := sipMessageDecodeHandler(context.Background(), nil, map[string]any{"message": ""})
	if err == nil {
		t.Fatal("want error for empty message")
	}
}

func TestSIPMessageDecodeHandler_RejectsMalformed(t *testing.T) {
	_, err := sipMessageDecodeHandler(context.Background(), nil, map[string]any{
		"message": "INVITE\r\n\r\n",
	})
	if err == nil {
		t.Fatal("want error for malformed request line")
	}
}
