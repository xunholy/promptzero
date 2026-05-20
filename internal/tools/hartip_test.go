package tools

import (
	"context"
	"strings"
	"testing"
)

// TestHARTIPDecodeHandler_SessionInitiate pins a canonical
// Session Initiate request.
func TestHARTIPDecodeHandler_SessionInitiate(t *testing.T) {
	in := "01 00 00 00 0001 0005 01 00000005"
	out, err := hartIPDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"version": 1`,
		`"message_type_name": "Request"`,
		`"message_id_name": "Session_Initiate"`,
		`"sequence_number": 1`,
		`"byte_count": 5`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestHARTIPDecodeHandler_HARTPDURequest pins HART_PDU
// carrying a HART command 0 Read Unique Identifier.
func TestHARTIPDecodeHandler_HARTPDURequest(t *testing.T) {
	in := "01 00 03 00 0010 0005 02 80 00 00 82"
	out, err := hartIPDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_id_name": "HART_PDU"`,
		`"hart_payload_hex": "0280000082"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestHARTIPDecodeHandler_PublishBurstNotify pins burst-mode.
func TestHARTIPDecodeHandler_PublishBurstNotify(t *testing.T) {
	in := "01 02 80 00 0001 0004 DEADBEEF"
	out, err := hartIPDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "Publish"`,
		`"message_id_name": "Publish_Burst_Notify"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestHARTIPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := hartIPDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
