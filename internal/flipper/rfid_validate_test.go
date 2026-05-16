package flipper

import (
	"context"
	"strings"
	"testing"
	"time"
)

// RFIDEmulateCtx and RFIDWrite now validate that protocol is non-empty
// and data is hex before transport. Pre-fix, an LLM converting a
// captured fob to decimal (or trimming a digit) would silently emulate
// or write a corrupted tag for the full duration window.
//
// We deliberately do NOT allowlist the protocol name — the firmware
// table varies across forks.

func TestValidateRFIDArgs_AcceptsValid(t *testing.T) {
	cases := []struct {
		protocol string
		data     string
	}{
		{"EM4100", "DEADBEEF01"},
		{"HIDProx", "1A 2B 3C 4D 5E"},
		{"H10301", "00 04 70 00 00 00"},
		{"Indala", "abcdef"},
		{"AWID", "0102030405060708"},
	}
	for _, c := range cases {
		if err := validateRFIDArgs(c.protocol, c.data); err != nil {
			t.Errorf("validateRFIDArgs(%q, %q) = %v; want nil", c.protocol, c.data, err)
		}
	}
}

func TestValidateRFIDArgs_RejectsEmpty(t *testing.T) {
	if err := validateRFIDArgs("", "DEADBEEF"); err == nil {
		t.Error("expected error for empty protocol; got nil")
	}
	if err := validateRFIDArgs("EM4100", ""); err == nil {
		t.Error("expected error for empty data; got nil")
	}
	if err := validateRFIDArgs("EM4100", "    "); err == nil {
		t.Error("expected error for whitespace-only data; got nil")
	}
}

func TestValidateRFIDArgs_RejectsOddLength(t *testing.T) {
	for _, d := range []string{"ABC", "0102030", "1 2 3"} {
		if err := validateRFIDArgs("EM4100", d); err == nil {
			t.Errorf("expected error for odd-length data=%q; got nil", d)
		}
	}
}

func TestValidateRFIDArgs_RejectsNonHex(t *testing.T) {
	for _, d := range []string{"GG112233", "0xDEAD", "DEADXX"} {
		if err := validateRFIDArgs("EM4100", d); err == nil {
			t.Errorf("expected error for non-hex data=%q; got nil", d)
		}
	}
}

func TestRFIDEmulateCtx_RejectsBadData(t *testing.T) {
	f := &Flipper{}
	_, err := f.RFIDEmulateCtx(context.Background(), "EM4100", "GG112233", time.Second)
	if err == nil {
		t.Fatal("expected error for non-hex data; got nil")
	}
	if !strings.Contains(err.Error(), "RFID data") {
		t.Errorf("err = %v; want RFID data error", err)
	}
}

func TestRFIDEmulateCtx_RejectsEmptyProtocol(t *testing.T) {
	f := &Flipper{}
	_, err := f.RFIDEmulateCtx(context.Background(), "", "DEADBEEF", time.Second)
	if err == nil {
		t.Fatal("expected error for empty protocol; got nil")
	}
	if !strings.Contains(err.Error(), "protocol") {
		t.Errorf("err = %v; want protocol error", err)
	}
}

func TestRFIDWrite_RejectsBadData(t *testing.T) {
	f := &Flipper{}
	_, err := f.RFIDWrite("EM4100", "GG")
	if err == nil {
		t.Fatal("expected error for non-hex data; got nil")
	}
	if !strings.Contains(err.Error(), "RFID data") {
		t.Errorf("err = %v; want RFID data error", err)
	}
}

func TestRFIDWrite_RejectsEmptyProtocol(t *testing.T) {
	f := &Flipper{}
	_, err := f.RFIDWrite("   ", "DEADBEEF")
	if err == nil {
		t.Fatal("expected error for empty protocol; got nil")
	}
	if !strings.Contains(err.Error(), "protocol") {
		t.Errorf("err = %v; want protocol error", err)
	}
}
