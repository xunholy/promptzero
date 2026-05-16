package workflows

import (
	"strings"
	"testing"
)

// Tests pinning the pure-logic helpers feeding NFCBadgePipeline that
// the existing helpers_test.go did not yet cover: classifyNFCFamily
// (protocol-string → family), nfcFamilyHint (operator-facing next-
// step suggestion), and the full parseNFCDetectOutput walker.

func TestClassifyNFCFamily(t *testing.T) {
	cases := []struct {
		protocol string
		want     NFCFamily
	}{
		{"Mifare Classic 1K", NFCFamilyMIFAREClassic},
		{"MIFARE CLASSIC 4K", NFCFamilyMIFAREClassic},
		{"mifare classic", NFCFamilyMIFAREClassic},
		{"Mifare Ultralight", NFCFamilyUltralight},
		{"Mifare UL", NFCFamilyUltralight},
		{"NTAG215", NFCFamilyNTAG},
		{"NTAG", NFCFamilyNTAG},
		{"DESFire EV1", NFCFamilyDESFire},
		{"EMV Visa", NFCFamilyEMV},
		{"ISO14443-4A", NFCFamilyISO14443_4},
		{"iso14443-4", NFCFamilyISO14443_4},
		{"Plus SE", NFCFamilyUnknown},
		{"", NFCFamilyUnknown},
		{"unknown protocol", NFCFamilyUnknown},
	}
	for _, c := range cases {
		if got := classifyNFCFamily(c.protocol); got != c.want {
			t.Errorf("classifyNFCFamily(%q) = %d; want %d", c.protocol, got, c.want)
		}
	}
}

func TestNFCFamilyHint(t *testing.T) {
	// Each family must produce a non-empty hint.
	for _, f := range []NFCFamily{
		NFCFamilyMIFAREClassic,
		NFCFamilyUltralight,
		NFCFamilyNTAG,
		NFCFamilyDESFire,
		NFCFamilyEMV,
		NFCFamilyISO14443_4,
		NFCFamilyUnknown,
		NFCFamily(-1), // out-of-range sentinel routes through default
	} {
		h := nfcFamilyHint(f)
		if h == "" {
			t.Errorf("nfcFamilyHint(%d) = empty", f)
		}
	}
	// Cross-check the key operator-facing tokens that downstream
	// transcripts / scenarios depend on:
	if !strings.Contains(nfcFamilyHint(NFCFamilyMIFAREClassic), "mfkey32") {
		t.Error("MIFAREClassic hint should mention mfkey32")
	}
	if !strings.Contains(nfcFamilyHint(NFCFamilyUnknown), "manual triage") {
		t.Error("Unknown hint should mention manual triage")
	}
	if !strings.Contains(nfcFamilyHint(NFCFamilyEMV), "out-of-scope") {
		t.Error("EMV hint should mention out-of-scope-for-cloning")
	}
	if !strings.Contains(nfcFamilyHint(NFCFamilyDESFire), "keys") {
		t.Error("DESFire hint should mention keys requirement")
	}
}

func TestParseNFCDetectOutput_MIFAREClassic(t *testing.T) {
	out := `Protocol: Mifare Classic 1K
UID: 04 A3 5F 12
ATQA: 00 04
SAK: 08
`
	got := parseNFCDetectOutput(out)
	if got.Family != NFCFamilyMIFAREClassic {
		t.Errorf("Family = %d; want MIFAREClassic", got.Family)
	}
	if got.UID != "04 A3 5F 12" {
		t.Errorf("UID = %q; want '04 A3 5F 12'", got.UID)
	}
	if got.ATQA != "00 04" {
		t.Errorf("ATQA = %q; want '00 04'", got.ATQA)
	}
	if got.SAK != "08" {
		t.Errorf("SAK = %q; want '08'", got.SAK)
	}
	if got.Protocol != "Mifare Classic" {
		t.Errorf("Protocol = %q; want 'Mifare Classic'", got.Protocol)
	}
}

func TestParseNFCDetectOutput_NTAG215(t *testing.T) {
	out := `Detected: NTAG215
UID: 04 1A 2B 3C 4D 5E 6F
ATQA: 00 44
SAK: 00
`
	got := parseNFCDetectOutput(out)
	if got.Family != NFCFamilyNTAG {
		t.Errorf("Family = %d; want NTAG", got.Family)
	}
	if got.Protocol != "NTAG215" {
		t.Errorf("Protocol = %q; want NTAG215", got.Protocol)
	}
	if got.UID != "04 1A 2B 3C 4D 5E 6F" {
		t.Errorf("UID = %q", got.UID)
	}
}

func TestParseNFCDetectOutput_SAKFallback(t *testing.T) {
	// No protocol token, but SAK=09 → infer MIFARE Classic and synthesise
	// a protocol string from the family.
	out := `UID: 04 11 22 33
ATQA: 00 04
SAK: 09
`
	got := parseNFCDetectOutput(out)
	if got.Family != NFCFamilyMIFAREClassic {
		t.Errorf("Family = %d; want MIFAREClassic (inferred from SAK)", got.Family)
	}
	if got.Protocol != "Mifare Classic" {
		t.Errorf("Protocol = %q; want synthesised 'Mifare Classic'", got.Protocol)
	}
}

func TestParseNFCDetectOutput_UIDCasingNormalised(t *testing.T) {
	out := "UID: aa bb cc dd"
	got := parseNFCDetectOutput(out)
	if got.UID != "AA BB CC DD" {
		t.Errorf("UID = %q; want upper-cased 'AA BB CC DD'", got.UID)
	}
}

func TestParseNFCDetectOutput_EmptyAndUnknown(t *testing.T) {
	if got := parseNFCDetectOutput(""); got.Family != NFCFamilyUnknown {
		t.Errorf("empty input family = %d; want Unknown", got.Family)
	}
	// Unrecognised protocol + no SAK fallback path: UID still parsed
	// even when family stays Unknown.
	out := "Protocol: Plus SE\nUID: 11 22 33 44"
	got := parseNFCDetectOutput(out)
	if got.Family != NFCFamilyUnknown {
		t.Errorf("unknown protocol family = %d; want Unknown", got.Family)
	}
	if got.UID != "11 22 33 44" {
		t.Errorf("UID should still parse: got %q", got.UID)
	}
}

func TestParseNFCDetectOutput_DESFirePrecedence(t *testing.T) {
	// Protocol parses first, so DESFire wins over the SAK=20
	// (ISO14443-4) inference. Pin precedence so it doesn't quietly
	// flip in a future refactor.
	out := "Protocol: DESFire EV1\nUID: 04 AA BB CC DD EE FF\nSAK: 20"
	got := parseNFCDetectOutput(out)
	if got.Family != NFCFamilyDESFire {
		t.Errorf("Family = %d; want DESFire (protocol wins over SAK fallback)", got.Family)
	}
}

func TestParseNFCDetectOutput_ATQACasingNormalised(t *testing.T) {
	out := "Protocol: NTAG\nUID: 04 a1 b2\nATQA: 00 44\nSAK: 00"
	got := parseNFCDetectOutput(out)
	if got.ATQA != "00 44" {
		t.Errorf("ATQA = %q; want '00 44'", got.ATQA)
	}
}
