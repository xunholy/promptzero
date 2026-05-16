package flipper

import (
	"strings"
	"testing"
)

// IRTxParsed validates protocol against the firmware allowlist before
// transport. Pre-fix, common LLM hallucinations ("Sony" for SIRC,
// "Panasonic" for Kaseikyo, lower-case "nec") reached the firmware as
// an opaque "unknown protocol" usage dump.

func TestIRProtocolNames_Sorted(t *testing.T) {
	got := IRProtocolNames()
	if len(got) == 0 {
		t.Fatal("IRProtocolNames returned empty list")
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("IRProtocolNames not sorted: %q >= %q at index %d", got[i-1], got[i], i)
		}
	}
}

func TestIRTxParsed_AcceptsAllowlistedProtocols(t *testing.T) {
	for _, proto := range IRProtocolNames() {
		if _, ok := validIRProtocols[proto]; !ok {
			t.Errorf("%q in IRProtocolNames but not validIRProtocols", proto)
		}
	}
}

func TestIRTxParsed_RejectsUnknownProtocol(t *testing.T) {
	f := &Flipper{}
	cases := []string{"Sony", "Panasonic", "Philips", "nec", "neC", "samsung32", "", "RC7"}
	for _, p := range cases {
		_, err := f.IRTxParsed(p, "00 04", "70 00 00 00")
		if err == nil {
			t.Errorf("expected error for protocol=%q; got nil", p)
			continue
		}
		if !strings.Contains(err.Error(), "protocol") {
			t.Errorf("protocol=%q err = %v; want protocol validation error", p, err)
		}
	}
}

func TestIRTxParsed_RejectsEmptyAddressOrCommand(t *testing.T) {
	f := &Flipper{}
	if _, err := f.IRTxParsed("NEC", "", "01"); err == nil || !strings.Contains(err.Error(), "address") {
		t.Errorf("expected address error for empty address; got %v", err)
	}
	if _, err := f.IRTxParsed("NEC", "00 04", "  "); err == nil || !strings.Contains(err.Error(), "command") {
		t.Errorf("expected command error for blank command; got %v", err)
	}
}
