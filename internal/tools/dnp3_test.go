package tools

import (
	"context"
	"strings"
	"testing"
)

// TestDNP3DecodeHandler_ReadRequest pins a canonical READ.
func TestDNP3DecodeHandler_ReadRequest(t *testing.T) {
	in := "05 64 0A C2 6400 0100 DEAD C0 C1 01 01 3C BEEF"
	out, err := dnp3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"length": 10`,
		`"link_function_name": "CONFIRMED_USER_DATA"`,
		`"destination": 100`,
		`"source": 1`,
		`"app_function_name": "READ"`,
		`"object_data_hex": "013C"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestDNP3DecodeHandler_ResponseWithIIN pins RESPONSE + IIN
// decoded bits.
func TestDNP3DecodeHandler_ResponseWithIIN(t *testing.T) {
	in := "05 64 0B 43 0100 6400 DEAD C0 C0 81 10 02 00 BEEF"
	out, err := dnp3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"app_function_name": "RESPONSE"`,
		`"iin_hex": "0x0210"`,
		`"iin_bits_decoded": "NEED_TIME,OBJECT_UNKNOWN"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestDNP3DecodeHandler_LinkStatusOnly pins a pure data-link
// REQUEST_LINK_STATUS with no user data.
func TestDNP3DecodeHandler_LinkStatusOnly(t *testing.T) {
	in := "05 64 05 C9 6400 0100 DEAD"
	out, err := dnp3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"link_function_name": "REQUEST_LINK_STATUS"`) {
		t.Errorf("expected REQUEST_LINK_STATUS in output:\n%s", out)
	}
}

func TestDNP3DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := dnp3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
