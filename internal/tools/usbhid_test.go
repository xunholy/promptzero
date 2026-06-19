package tools

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// buildUSBPcapAB assembles a minimal classic USBPcap (DLT 249) capture of the
// keystrokes "ab" — four Interrupt-IN records (down a, release, down b,
// release), each a 27-byte USBPCAP_BUFFER_PACKET_HEADER + 8 report bytes.
func buildUSBPcapAB() []byte {
	reports := [][]byte{
		{0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}, // a
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // release
		{0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00}, // b
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // release
	}
	gh := make([]byte, 24)
	copy(gh[0:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}) // LE microsecond magic
	binary.LittleEndian.PutUint16(gh[4:6], 2)
	binary.LittleEndian.PutUint16(gh[6:8], 4)
	binary.LittleEndian.PutUint32(gh[16:20], 65535)
	binary.LittleEndian.PutUint32(gh[20:24], 249) // DLT_USBPCAP
	out := gh
	for _, r := range reports {
		hdr := make([]byte, 27)
		binary.LittleEndian.PutUint16(hdr[0:2], 27) // headerLen
		hdr[21] = 0x81                              // Interrupt-IN endpoint
		hdr[22] = 1                                 // transfer = interrupt
		binary.LittleEndian.PutUint32(hdr[23:27], 8)
		pkt := append(hdr, r...)
		rh := make([]byte, 16)
		binary.LittleEndian.PutUint32(rh[8:12], uint32(len(pkt)))
		binary.LittleEndian.PutUint32(rh[12:16], uint32(len(pkt)))
		out = append(out, rh...)
		out = append(out, pkt...)
	}
	return out
}

// TestUSBHIDClassifyHandler_USBPcap pins the Windows USBPcap input path: a
// base64-encoded binary capture is decoded, the reports extracted, and the
// keystrokes reconstructed — with the source banner naming USBPcap.
func TestUSBHIDClassifyHandler_USBPcap(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(buildUSBPcapAB())
	out, err := usbHIDClassifyHandler(context.Background(), nil,
		map[string]any{"usbpcap": b64})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"reconstructed_text": "ab"`,
		"extracted 4 HID keyboard report(s) from USBPcap capture",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestUSBHIDClassifyHandler_RejectsMultipleInputs guards the exactly-one
// invariant across the three input modes.
func TestUSBHIDClassifyHandler_RejectsMultipleInputs(t *testing.T) {
	_, err := usbHIDClassifyHandler(context.Background(), nil,
		map[string]any{"hex": "0000040000000000", "usbpcap": "AAAA"})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("want 'exactly one' error, got %v", err)
	}
}

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
