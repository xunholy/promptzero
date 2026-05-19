package tools

import (
	"context"
	"strings"
	"testing"
)

// TestModbusDecodeHandler_RTU_ReadHoldingRegisters pins an
// RTU Read Holding Registers request through the Spec handler.
func TestModbusDecodeHandler_RTU_ReadHoldingRegisters(t *testing.T) {
	out, err := modbusDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "01 03 00 00 00 01 84 0A",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"format": "RTU"`) {
		t.Errorf("expected RTU format:\n%s", out)
	}
	if !strings.Contains(out, `"function_name": "Read Holding Registers"`) {
		t.Errorf("expected function name:\n%s", out)
	}
	if !strings.Contains(out, `"crc_valid": true`) {
		t.Errorf("expected crc_valid true:\n%s", out)
	}
}

// TestModbusDecodeHandler_TCP_ReadHoldingRegisters pins a TCP
// Read Holding Registers request through the Spec handler.
func TestModbusDecodeHandler_TCP_ReadHoldingRegisters(t *testing.T) {
	out, err := modbusDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "0001 0000 0006 01 03 0000 000A",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"format": "TCP"`) {
		t.Errorf("expected TCP format:\n%s", out)
	}
	if !strings.Contains(out, `"transaction_id": 1`) {
		t.Errorf("expected transaction_id 1:\n%s", out)
	}
}

func TestModbusDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := modbusDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestModbusDecodeHandler_RejectsBadLength(t *testing.T) {
	_, err := modbusDecodeHandler(context.Background(), nil, map[string]any{"hex": "01 03"})
	if err == nil {
		t.Fatal("want error for short hex")
	}
}
