package tools

import (
	"context"
	"strings"
	"testing"
)

// TestS7CommDecodeHandler_ReadVarJob pins a canonical Read_Var
// Job_Request.
func TestS7CommDecodeHandler_ReadVarJob(t *testing.T) {
	in := "03 00 00 1F 02 F0 80 " +
		"32 01 0000 0001 000E 0000 " +
		"04 01 12 0A 10 02 00 01 00 01 84 00 00 00"
	out, err := s7commDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"tpkt_version": 3`,
		`"cotp_pdu_type_name": "DT (Data)"`,
		`"rosctr_name": "Job_Request"`,
		`"function_name": "Read_Var"`,
		`"parameter_length": 14`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestS7CommDecodeHandler_AckDataResponse pins an Ack_Data
// response with No_Error class.
func TestS7CommDecodeHandler_AckDataResponse(t *testing.T) {
	in := "03 00 00 1B 02 F0 80 " +
		"32 03 0000 0001 0002 0006 00 00 " +
		"04 01 " +
		"FF 04 0010 ABCD"
	out, err := s7commDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"rosctr_name": "Ack_Data"`,
		`"error_class_name": "No_Error"`,
		`"function_name": "Read_Var"`,
		`"data_hex": "FF040010ABCD"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestS7CommDecodeHandler_CRConnectionRequest pins a COTP-only
// CR frame.
func TestS7CommDecodeHandler_CRConnectionRequest(t *testing.T) {
	in := "03 00 00 16 11 E0 00 00 00 01 00 " +
		"C0 01 0A C1 02 01 00 C2 02 01 02"
	out, err := s7commDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"cotp_pdu_type_name": "CR (Connection Request)"`) {
		t.Errorf("expected CR PDU type in output:\n%s", out)
	}
}

func TestS7CommDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := s7commDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
