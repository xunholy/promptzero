package tools

import (
	"context"
	"strings"
	"testing"
)

// TestTFTPDecodeHandler_RRQ pins a canonical Read Request
// for pxelinux.0 in octet mode.
func TestTFTPDecodeHandler_RRQ(t *testing.T) {
	in := "0001 70 78 65 6C 69 6E 75 78 2E 30 00 6F 63 74 65 74 00"
	out, err := tftpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"opcode_name": "RRQ (Read Request)"`,
		`"filename": "pxelinux.0"`,
		`"mode": "octet"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestTFTPDecodeHandler_RRQWithOptions pins option decoding.
func TestTFTPDecodeHandler_RRQWithOptions(t *testing.T) {
	in := "0001 626F6F742E696D67 00 6F63746574 00" +
		"626C6B73697A65 00 31343638 00" +
		"7473697A65 00 30 00"
	out, err := tftpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"name": "blksize"`,
		`"value": "1468"`,
		`"name_known": "Block Size (RFC 2348)"`,
		`"name": "tsize"`,
		`"name_known": "Transfer Size (RFC 2349)"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestTFTPDecodeHandler_DATA pins DATA decoding with text
// payload surfacing.
func TestTFTPDecodeHandler_DATA(t *testing.T) {
	in := "0003 0001 48656C6C6F2C20776F726C64210A"
	out, err := tftpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"opcode_name": "DATA"`,
		`"block_number": 1`,
		`"payload_bytes": 14`,
		`"payload_text": "Hello, world!\n"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestTFTPDecodeHandler_ERROR pins error code + message.
func TestTFTPDecodeHandler_ERROR(t *testing.T) {
	in := "0005 0001 46696C65206E6F7420666F756E64 00"
	out, err := tftpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"opcode_name": "ERROR"`,
		`"error_code": 1`,
		`"error_name": "File not found"`,
		`"error_message": "File not found"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestTFTPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := tftpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
