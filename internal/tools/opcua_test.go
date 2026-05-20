package tools

import (
	"context"
	"strings"
	"testing"
)

// TestOPCUADecodeHandler_Hello pins the canonical HEL message.
func TestOPCUADecodeHandler_Hello(t *testing.T) {
	in := "48454C46 32000000 " +
		"00000000 00000100 00000100 00000004 00000000 " +
		"12000000 " +
		"6F70632E7463703A2F2F7372763A34383430"
	out, err := opcuaDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type": "HEL"`,
		`"message_type_name": "Hello"`,
		`"chunk_type_name": "Final"`,
		`"receive_buffer_size": 65536`,
		`"endpoint_url": "opc.tcp://srv:4840"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestOPCUADecodeHandler_Error pins the ERR message decode.
func TestOPCUADecodeHandler_Error(t *testing.T) {
	in := "45525246 18000000 " +
		"00000280 " +
		"04000000 66 61 69 6C"
	out, err := opcuaDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "Error"`,
		`"status_code_hex": "0x80020000"`,
		`"reason": "fail"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestOPCUADecodeHandler_Message pins the symmetric MSG header
// decode (SecureChannelId + TokenId + Sequence + RequestId).
func TestOPCUADecodeHandler_Message(t *testing.T) {
	in := "4D534746 20000000 " +
		"A4010000 05000000 64000000 07000000 " +
		"4142434445464748"
	out, err := opcuaDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "Message"`,
		`"secure_channel_id": 420`,
		`"token_id": 5`,
		`"sequence_number": 100`,
		`"request_id": 7`,
		`"service_body_hex": "4142434445464748"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestOPCUADecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := opcuaDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
