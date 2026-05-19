package mpls

import (
	"strings"
	"testing"
)

func TestDecode_SingleLabel_IPv4(t *testing.T) {
	// Label=100 (0x64), TC=0, S=1, TTL=64.
	// Word = 100<<12 | 0<<9 | 1<<8 | 64 = 0x00064140.
	// Payload: IPv4 (first nibble 4).
	in := "00064140 45000028 12340000 40110000 C0A80101 C0A80102"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.LabelCount != 1 {
		t.Fatalf("expected 1 label, got %d", r.LabelCount)
	}
	l := r.Labels[0]
	if l.Label != 100 {
		t.Errorf("label: %d", l.Label)
	}
	if l.TC != 0 {
		t.Errorf("TC: %d", l.TC)
	}
	if !l.BottomOfStack {
		t.Errorf("S should be 1")
	}
	if l.TTL != 64 {
		t.Errorf("TTL: %d", l.TTL)
	}
	if !strings.Contains(r.PayloadGuess, "IPv4") {
		t.Errorf("payload guess: %q", r.PayloadGuess)
	}
}

func TestDecode_TwoLabels(t *testing.T) {
	// Outer: label=200 (0xC8), TC=0, S=0, TTL=128 → 0x000C8080.
	// Inner: label=300 (0x12C), TC=0, S=1, TTL=64 → 0x0012C140.
	in := "000C8080 0012C140 45000028"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.LabelCount != 2 {
		t.Fatalf("expected 2 labels, got %d", r.LabelCount)
	}
	if r.Labels[0].Label != 200 || r.Labels[0].BottomOfStack {
		t.Errorf("outer label: %+v", r.Labels[0])
	}
	if r.Labels[1].Label != 300 || !r.Labels[1].BottomOfStack {
		t.Errorf("inner label: %+v", r.Labels[1])
	}
	if r.HeaderBytes != 8 {
		t.Errorf("header bytes: %d", r.HeaderBytes)
	}
}

func TestDecode_IPv4ExplicitNULL(t *testing.T) {
	// Label 0 (IPv4 Explicit NULL), S=1, TTL=1.
	// Word = 0<<12 | 0<<9 | 1<<8 | 1 = 0x00000101.
	in := "00000101 45000028"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Labels[0].LabelName != "IPv4 Explicit NULL (RFC 3032)" {
		t.Errorf("name: %q", r.Labels[0].LabelName)
	}
	if !strings.Contains(r.PayloadGuess, "IPv4 (from IPv4 Explicit NULL") {
		t.Errorf("payload guess: %q", r.PayloadGuess)
	}
}

func TestDecode_IPv6ExplicitNULL(t *testing.T) {
	// Label 2 (IPv6 Explicit NULL), S=1.
	// Word = 2<<12 | 0<<9 | 1<<8 | 1 = 0x00002101.
	in := "00002101 60000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Labels[0].LabelName != "IPv6 Explicit NULL (RFC 3032)" {
		t.Errorf("name: %q", r.Labels[0].LabelName)
	}
	if !strings.Contains(r.PayloadGuess, "IPv6") {
		t.Errorf("payload guess: %q", r.PayloadGuess)
	}
}

func TestDecode_RouterAlertAtBottom_Violation(t *testing.T) {
	// Label 1 (Router Alert), S=1, TTL=64.
	// Word = 1<<12 | 0<<9 | 1<<8 | 64 = 0x00001140.
	in := "00001140 45000028"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "Router Alert") && strings.Contains(n, "bottom") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Router-Alert-at-bottom violation note in: %v", r.Notes)
	}
}

func TestDecode_TCField(t *testing.T) {
	// Label=100, TC=5 (Expedited Forwarding equivalent), S=1, TTL=64.
	// Word = 100<<12 | 5<<9 | 1<<8 | 64 = 0x00064B40.
	in := "00064B40 45000028"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Labels[0].TC != 5 {
		t.Errorf("TC: %d", r.Labels[0].TC)
	}
}

func TestDecode_EntropyLabelStack(t *testing.T) {
	// 3-label stack: ELI (7) + entropy label + real label.
	// ELI word: 7<<12 | 0<<9 | 0<<8 | 64 = 0x00007040.
	// Entropy word: 0x12345<<12 | 0 | 0 | 64 = 0x12345040.
	// Real label: 100, S=1, TTL=64 → 0x00064140.
	in := "00007040 12345040 00064140 45000028"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.LabelCount != 3 {
		t.Fatalf("expected 3 labels, got %d", r.LabelCount)
	}
	if r.Labels[0].LabelName != "Entropy Label Indicator (ELI, RFC 6790)" {
		t.Errorf("ELI name: %q", r.Labels[0].LabelName)
	}
	if r.Labels[1].Label != 0x12345 {
		t.Errorf("entropy label: 0x%X", r.Labels[1].Label)
	}
	if r.Labels[2].Label != 100 || !r.Labels[2].BottomOfStack {
		t.Errorf("real label: %+v", r.Labels[2])
	}
}

func TestDecode_NoBottomOfStack(t *testing.T) {
	// Two labels but neither has S=1 — error.
	// Label 100, TC=0, S=0, TTL=64 = 0x00064040, twice.
	_, err := Decode("00064040 00064040")
	if err == nil {
		t.Fatal("expected error for label stack without S=1")
	}
	if !strings.Contains(err.Error(), "S=1") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReservedLabelTable(t *testing.T) {
	cases := map[int]string{
		0:  "IPv4 Explicit NULL (RFC 3032)",
		1:  "Router Alert (RFC 3032)",
		2:  "IPv6 Explicit NULL (RFC 3032)",
		3:  "Implicit NULL (signalling only, never on wire)",
		7:  "Entropy Label Indicator (ELI, RFC 6790)",
		13: "Generic Associated Channel Label (GAL, RFC 5586)",
		14: "OAM Alert Label (RFC 3429)",
		15: "Extension Label (RFC 7274)",
	}
	for k, v := range cases {
		if got := reservedLabelName(k); got != v {
			t.Errorf("reservedLabelName(%d): got %q want %q", k, got, v)
		}
	}
	// Reserved range fallback.
	if got := reservedLabelName(5); !strings.Contains(got, "reserved") {
		t.Errorf("label 5 should be reserved range fallback, got %q", got)
	}
	// User-assigned (no name).
	if got := reservedLabelName(100); got != "" {
		t.Errorf("user label 100 should have no name, got %q", got)
	}
}

func TestDecode_PayloadHeuristic_EoMPLS(t *testing.T) {
	// Label 100, S=1, TTL=64. Payload first nibble = 0 (control word).
	in := "00064140 00000000 AABBCCDDEEFF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(r.PayloadGuess, "control word") {
		t.Errorf("payload guess: %q", r.PayloadGuess)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":     "",
		"odd hex":   "00064140 45000",
		"too short": "000641",
		"bad hex":   "ZZ064140",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
