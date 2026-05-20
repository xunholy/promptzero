package tools

import (
	"context"
	"strings"
	"testing"
)

// TestNTLMDecodeHandler_Negotiate pins a NEGOTIATE_MESSAGE
// with OEM Domain + Version.
func TestNTLMDecodeHandler_Negotiate(t *testing.T) {
	in := "4E544C4D53535000 01000000 02000002" +
		"0700 0700 28000000" +
		"0000 0000 28000000" +
		"0A 00 614A 000000 0F" +
		"4558414D504C45"
	out, err := ntlmDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "NEGOTIATE_MESSAGE"`,
		`"domain": "EXAMPLE"`,
		`"NEGOTIATE_VERSION"`,
		`"build": 19041`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestNTLMDecodeHandler_Challenge pins a CHALLENGE_MESSAGE
// with ServerChallenge + AV pair.
func TestNTLMDecodeHandler_Challenge(t *testing.T) {
	in := "4E544C4D53535000 02000000" +
		"0E000E0038000000" +
		"05028002" +
		"0102030405060708" +
		"0000000000000000" +
		"0C000C0046000000" +
		"0A 00 614A 000000 0F" +
		"45005800 41004D00 50004C00 4500" +
		"02000400 41004300" +
		"00000000"
	out, err := ntlmDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "CHALLENGE_MESSAGE"`,
		`"target_name": "EXAMPLE"`,
		`"server_challenge_hex": "0102030405060708"`,
		`"av_id_name": "MsvAvNbDomainName"`,
		`"value_text": "AC"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestNTLMDecodeHandler_Authenticate pins an AUTHENTICATE_
// MESSAGE with UserName="user".
func TestNTLMDecodeHandler_Authenticate(t *testing.T) {
	in := "4E544C4D53535000 03000000" +
		"0000 0000 40000000" +
		"0000 0000 40000000" +
		"0000 0000 40000000" +
		"0800 0800 40000000" +
		"0000 0000 48000000" +
		"0000 0000 48000000" +
		"01020000" +
		"75 00 73 00 65 00 72 00"
	out, err := ntlmDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "AUTHENTICATE_MESSAGE"`,
		`"user_name": "user"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestNTLMDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ntlmDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
