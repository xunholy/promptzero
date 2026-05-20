package tools

import (
	"context"
	"strings"
	"testing"
)

// TestPTPv2DecodeHandler_Sync pins a canonical one-step Sync.
func TestPTPv2DecodeHandler_Sync(t *testing.T) {
	in := "00 02 002C 00 00 0200 0000000000000000 00000000 " +
		"00112233445566778899" +
		"AABB 00 FD" +
		"000000000064 0000F424"
	out, err := ptpv2DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type": 0`,
		`"message_type_name": "Sync"`,
		`"version_ptp": 2`,
		`"message_length": 44`,
		`"sequence_id": 43707`, // 0xAABB
		`"log_message_interval": -3`,
		`"flags_decoded": "twoStep"`,
		`"seconds": 100`,
		`"nanoseconds": 62500`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestPTPv2DecodeHandler_Announce pins BMCA inputs.
func TestPTPv2DecodeHandler_Announce(t *testing.T) {
	in := "0B 02 0040 00 00 0018 0000000000000000 00000000 " +
		"00112233445566778899" +
		"00C8 00 01" +
		"000000000200 00000000 " +
		"0025 00 80 06 21 4E5D 80 AABBCCFFFEDDEEFF 0001 20"
	out, err := ptpv2DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "Announce"`,
		`"flags_decoded": "ptpTimescale,timeTraceable"`,
		`"current_utc_offset_seconds": 37`,
		`"grandmaster_clock_class": 6`,
		`"grandmaster_clock_accuracy_name": "within 100 ns"`,
		`"grandmaster_identity": "AA:BB:CC:FF:FE:DD:EE:FF"`,
		`"steps_removed": 1`,
		`"time_source_name": "GPS"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestPTPv2DecodeHandler_DelayResp pins the requestingPortIdentity
// copy-back tying Delay_Resp to its Delay_Req.
func TestPTPv2DecodeHandler_DelayResp(t *testing.T) {
	in := "09 02 0036 00 00 0000 0000000000000000 00000000 " +
		"DEADBEEFCAFEBABE0001" +
		"1234 00 7F" +
		"000000000064 0000F424 " +
		"11223344FFFE5566 0005"
	out, err := ptpv2DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "Delay_Resp"`,
		`"clock_identity": "11:22:33:44:FF:FE:55:66"`,
		`"port_number": 5`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestPTPv2DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ptpv2DecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
