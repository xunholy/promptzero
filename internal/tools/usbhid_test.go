package tools

import (
	"context"
	"strings"
	"testing"
)

// TestUSBHIDClassifyHandler_HelloReconstruct pins reconstruction
// of "Hello" from a sequence of HID Keyboard reports.
func TestUSBHIDClassifyHandler_HelloReconstruct(t *testing.T) {
	in := "02 00 0B 00 00 00 00 00 " + // LShift + h → 'H'
		"00 00 00 00 00 00 00 00 " +
		"00 00 08 00 00 00 00 00 " + // e
		"00 00 00 00 00 00 00 00 " +
		"00 00 0F 00 00 00 00 00 " + // l
		"00 00 00 00 00 00 00 00 " +
		"00 00 0F 00 00 00 00 00 " + // l
		"00 00 00 00 00 00 00 00 " +
		"00 00 12 00 00 00 00 00 " + // o
		"00 00 00 00 00 00 00 00"
	out, err := usbHIDClassifyHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"reconstructed_text": "Hello"`,
		`"report_count": 10`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestUSBHIDClassifyHandler_WindowsRunDialog pins a GUI+r combo
// — the canonical opening keystroke of a Windows BadUSB payload.
func TestUSBHIDClassifyHandler_WindowsRunDialog(t *testing.T) {
	in := "08 00 15 00 00 00 00 00 " +
		"00 00 00 00 00 00 00 00"
	out, err := usbHIDClassifyHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "GUI R") {
		t.Errorf("expected GUI R combo in duckyscript:\n%s", out)
	}
}

// TestUSBHIDClassifyHandler_DuckyStringFolding pins that
// consecutive printable keys fold into a single STRING.
func TestUSBHIDClassifyHandler_DuckyStringFolding(t *testing.T) {
	in := "00 00 04 00 00 00 00 00 " + // a
		"00 00 00 00 00 00 00 00 " +
		"00 00 05 00 00 00 00 00 " + // b
		"00 00 00 00 00 00 00 00 " +
		"00 00 06 00 00 00 00 00 " + // c
		"00 00 00 00 00 00 00 00"
	out, err := usbHIDClassifyHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"duckyscript": "STRING abc"`) {
		t.Errorf("expected STRING abc:\n%s", out)
	}
}

func TestUSBHIDClassifyHandler_RejectsEmpty(t *testing.T) {
	_, err := usbHIDClassifyHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
