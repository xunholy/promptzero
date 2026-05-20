package tools

import (
	"context"
	"strings"
	"testing"
)

// TestOpenFlowDecodeHandler_HelloVersionBitmap pins the canonical
// OF 1.3 HELLO with version bitmap.
func TestOpenFlowDecodeHandler_HelloVersionBitmap(t *testing.T) {
	in := "04 00 0010 00000001 0001 0008 00000012"
	out, err := openflowDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"version_name": "OF_1.3"`,
		`"type_name": "HELLO"`,
		`"hello_versions_supported"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestOpenFlowDecodeHandler_Error pins the FLOW_MOD_FAILED
// error type.
func TestOpenFlowDecodeHandler_Error(t *testing.T) {
	in := "04 01 000C 00000007 0005 0002 DEADBEEF"
	out, err := openflowDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "ERROR"`,
		`"error_type_name": "FLOW_MOD_FAILED"`,
		`"error_code": 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestOpenFlowDecodeHandler_FeaturesReply pins datapath_id +
// capabilities decode.
func TestOpenFlowDecodeHandler_FeaturesReply(t *testing.T) {
	in := "04 06 0020 00000001 " +
		"0000000000000001 00000100 FE 00 0000 0000004F 00000000"
	out, err := openflowDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "FEATURES_REPLY"`,
		`"datapath_id_hex": "0000000000000001"`,
		`"n_buffers": 256`,
		`"n_tables": 254`,
		`"FLOW_STATS"`,
		`"PORT_STATS"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestOpenFlowDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := openflowDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
