package flipper

import (
	"context"
	"strings"
	"testing"
	"time"
)

// IButtonEmulate and IButtonWrite now validate protocol and hexData
// before transport. Pre-fix, hallucinated protocols ("dallas", "Maxim")
// and malformed hex reached the firmware as opaque errors mid-stream
// after burning wall-clock on the emulation window.

func TestValidateIButtonHex(t *testing.T) {
	accept := []string{
		"01 02 03 04 05 06 07 08",
		"0102030405060708",
		"DEADBEEF",
		"deadbeef",
		"aa\tbb cc",
	}
	for _, h := range accept {
		if err := validateIButtonHex(h); err != nil {
			t.Errorf("validateIButtonHex(%q) = %v; want nil", h, err)
		}
	}

	reject := []string{
		"",
		"   ",
		"ABC",      // odd length
		"GG112233", // non-hex
		"0x12",     // 0x prefix not accepted
	}
	for _, h := range reject {
		if err := validateIButtonHex(h); err == nil {
			t.Errorf("validateIButtonHex(%q) = nil; want error", h)
		}
	}
}

func TestIButtonEmulate_RejectsBadProtocol(t *testing.T) {
	f := &Flipper{}
	for _, p := range []string{"dallas", "DALLAS", "Maxim", "", "Mifare"} {
		_, err := f.IButtonEmulateCtx(context.Background(), p, "01020304", time.Second)
		if err == nil {
			t.Errorf("expected error for protocol=%q; got nil", p)
			continue
		}
		if !strings.Contains(err.Error(), "protocol") {
			t.Errorf("protocol=%q err = %v; want protocol validation error", p, err)
		}
	}
}

func TestIButtonEmulate_RejectsBadHex(t *testing.T) {
	f := &Flipper{}
	_, err := f.IButtonEmulateCtx(context.Background(), "Dallas", "GG112233", time.Second)
	if err == nil {
		t.Fatal("expected error for non-hex data; got nil")
	}
	if !strings.Contains(err.Error(), "hex_data") {
		t.Errorf("err = %v; want hex_data validation error", err)
	}
}

func TestIButtonWrite_RejectsBadHex(t *testing.T) {
	f := &Flipper{}
	for _, h := range []string{"", "ABC", "GG"} {
		_, err := f.IButtonWrite(h)
		if err == nil {
			t.Errorf("expected error for hex=%q; got nil", h)
			continue
		}
		if !strings.Contains(err.Error(), "hex_data") {
			t.Errorf("hex=%q err = %v; want hex_data validation error", h, err)
		}
	}
}
