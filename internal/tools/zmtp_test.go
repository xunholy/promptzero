package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// zmGreeting builds a 64-byte ZMTP 3.x greeting for use in tests.
func zmGreeting(major, minor byte, mechanism string, asServer bool) []byte {
	b := make([]byte, 64)
	b[0] = 0xFF
	b[9] = 0x7F
	b[10] = major
	b[11] = minor
	copy(b[12:32], mechanism)
	if asServer {
		b[32] = 1
	}
	return b
}

// zmReadyCommand builds a short ZMTP READY command frame with the
// given (name, value) property pairs.
func zmReadyCommand(props [][2]string) []byte {
	var propBuf []byte
	for _, p := range props {
		propBuf = binary.BigEndian.AppendUint32(propBuf, uint32(len(p[0])))
		propBuf = append(propBuf, []byte(p[0])...)
		propBuf = binary.BigEndian.AppendUint32(propBuf, uint32(len(p[1])))
		propBuf = append(propBuf, []byte(p[1])...)
	}
	name := "READY"
	body := append([]byte{byte(len(name))}, append([]byte(name), propBuf...)...)
	frame := []byte{0x04, byte(len(body))}
	return append(frame, body...)
}

// TestZMTPDecodeHandler_NULLGreeting pins the canonical unauthenticated
// exposure shape.
func TestZMTPDecodeHandler_NULLGreeting(t *testing.T) {
	g := zmGreeting(3, 0, "NULL", false)
	out, err := zmtpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(g)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_greeting": true`,
		`"version_major": 3`,
		`"mechanism": "NULL"`,
		`"mechanism_name": "No authentication"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
	if strings.Contains(out, `"is_cleartext_auth"`) {
		t.Errorf("NULL should not set is_cleartext_auth in output:\n%s", out)
	}
}

// TestZMTPDecodeHandler_PLAINGreeting pins the cleartext-credential
// exposure classification.
func TestZMTPDecodeHandler_PLAINGreeting(t *testing.T) {
	g := zmGreeting(3, 1, "PLAIN", true)
	out, err := zmtpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(g)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_greeting": true`,
		`"mechanism": "PLAIN"`,
		`"mechanism_name": "Cleartext password"`,
		`"is_cleartext_auth": true`,
		`cleartext`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestZMTPDecodeHandler_GreetingPlusREADY pins the socket-type
// topology disclosure path.
func TestZMTPDecodeHandler_GreetingPlusREADY(t *testing.T) {
	g := zmGreeting(3, 0, "NULL", false)
	ready := zmReadyCommand([][2]string{
		{"Socket-Type", "DEALER"},
	})
	pkt := append(g, ready...)
	out, err := zmtpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_greeting": true`,
		`"socket_type": "DEALER"`,
		`"command_name": "READY"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestZMTPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := zmtpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
