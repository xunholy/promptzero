package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestVNCRFBDecodeHandler_VersionBanner(t *testing.T) {
	b := []byte("RFB 003.008\n")
	out, err := vncRFBDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(b)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_version_banner": true`,
		`"protocol_version": "003.008"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestVNCRFBDecodeHandler_NoAuthExposed(t *testing.T) {
	// 1-byte count=1 + 1-byte type=1 (None — no auth)
	b := []byte{0x01, 0x01}
	out, err := vncRFBDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(b)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"has_security_types": true`,
		`NO AUTHENTICATION REQUIRED`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestVNCRFBDecodeHandler_VNCAuthWeakDES(t *testing.T) {
	b := []byte{0x01, 0x02}
	out, err := vncRFBDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(b)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`DES`,
		`26200`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestVNCRFBDecodeHandler_AppleARD(t *testing.T) {
	b := []byte{0x01, 30}
	out, err := vncRFBDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(b)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "Apple Remote Desktop") {
		t.Errorf("Apple ARD (type 30) should be flagged:\n%s", out)
	}
}

func TestVNCRFBDecodeHandler_SecurityResultFailedWithReason(t *testing.T) {
	reason := "Authentication failure"
	b := []byte{0x00, 0x00, 0x00, 0x01}
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(reason)))
	b = append(b, lenBytes...)
	b = append(b, []byte(reason)...)
	out, err := vncRFBDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(b)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"security_result_failed": true`,
		`"security_failure_reason": "Authentication failure"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestVNCRFBDecodeHandler_ServerInitDesktopName(t *testing.T) {
	desktopName := "dc01.corp.example.com"
	b := make([]byte, 24+len(desktopName))
	binary.BigEndian.PutUint16(b[0:2], 1920)
	binary.BigEndian.PutUint16(b[2:4], 1080)
	b[4] = 32
	b[5] = 24
	b[7] = 1 // true colour
	binary.BigEndian.PutUint32(b[20:24], uint32(len(desktopName)))
	copy(b[24:], []byte(desktopName))
	out, err := vncRFBDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(b)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"has_server_init": true`,
		`"framebuffer_width": 1920`,
		`"framebuffer_height": 1080`,
		`"desktop_name": "dc01.corp.example.com"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestVNCRFBDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := vncRFBDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
