package fileformat

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildSub_HappyPath(t *testing.T) {
	raw, err := BuildSub(SubBuildParams{
		Frequency: 433920000,
		Protocol:  "Princeton",
		Key:       "00 00 00 1A 2B 3C 4D 00",
		Bit:       24,
		TE:        400,
	})
	if err != nil {
		t.Fatalf("BuildSub: %v", err)
	}
	// Round-trip: the parser must accept what we just built.
	parsed, err := ParseSub(raw)
	if err != nil {
		t.Fatalf("ParseSub on BuildSub output: %v", err)
	}
	if parsed.Frequency != 433920000 {
		t.Errorf("Frequency round-trip failed: %d", parsed.Frequency)
	}
	if parsed.Protocol != "Princeton" {
		t.Errorf("Protocol round-trip: %q", parsed.Protocol)
	}
	if parsed.Bit != 24 {
		t.Errorf("Bit round-trip: %d", parsed.Bit)
	}
	// Default preset was picked for a 433 MHz ISM-band file.
	if !strings.Contains(string(raw), "FuriHalSubGhzPresetOok650Async") {
		t.Errorf("expected OOK preset for 433 MHz, got: %s", raw)
	}
}

func TestBuildSub_RejectsZeroFreq(t *testing.T) {
	if _, err := BuildSub(SubBuildParams{Frequency: 0}); err == nil {
		t.Fatal("zero frequency should error")
	}
}

func TestBuildSub_RejectsOutOfBandFreq(t *testing.T) {
	if _, err := BuildSub(SubBuildParams{Frequency: 2_400_000_000}); err == nil {
		t.Fatal("2.4 GHz freq should reject (outside CC1101 range)")
	}
	if _, err := BuildSub(SubBuildParams{Frequency: 500_000}); err == nil {
		t.Fatal("500 kHz freq should reject (outside CC1101 range)")
	}
}

func TestBuildSub_RawMode(t *testing.T) {
	raw, err := BuildSub(SubBuildParams{
		Frequency: 433920000,
		RawData:   []int32{320, -180, 320, -180},
	})
	if err != nil {
		t.Fatalf("BuildSub: %v", err)
	}
	parsed, _ := ParseSub(raw)
	if parsed.Protocol != "RAW" {
		t.Errorf("Protocol should be RAW when RawData supplied, got %q", parsed.Protocol)
	}
	if len(parsed.RawData) != 4 {
		t.Errorf("RawData round-trip len = %d, want 4", len(parsed.RawData))
	}
}

func TestBuildSub_RejectsInvalidKey(t *testing.T) {
	if _, err := BuildSub(SubBuildParams{Frequency: 433920000, Key: "ZZZZ"}); err == nil {
		t.Fatal("non-hex key should reject")
	}
}

func TestBuildRFID_HappyPath(t *testing.T) {
	raw, err := BuildRFID(RFIDBuildParams{
		KeyType: "EM4100",
		Data:    "1A 2B 3C 4D 5E",
	})
	if err != nil {
		t.Fatalf("BuildRFID: %v", err)
	}
	parsed, err := ParseRFID(raw)
	if err != nil {
		t.Fatalf("ParseRFID: %v", err)
	}
	if parsed.KeyType != "EM4100" {
		t.Errorf("KeyType round-trip: %q", parsed.KeyType)
	}
	if parsed.Data != "1A 2B 3C 4D 5E" {
		t.Errorf("Data round-trip: %q", parsed.Data)
	}
}

func TestBuildRFID_MissingFields(t *testing.T) {
	if _, err := BuildRFID(RFIDBuildParams{Data: "1A 2B"}); err == nil {
		t.Error("missing KeyType should error")
	}
	if _, err := BuildRFID(RFIDBuildParams{KeyType: "EM4100"}); err == nil {
		t.Error("missing Data should error")
	}
}

func TestBuildRFID_NormalisesHex(t *testing.T) {
	// Caller passes lowercase with inconsistent spacing; builder
	// should emit canonical "AA BB CC ..." form.
	raw, err := BuildRFID(RFIDBuildParams{KeyType: "EM4100", Data: "1a2b3c4d5e"})
	if err != nil {
		t.Fatalf("BuildRFID: %v", err)
	}
	if !bytes.Contains(raw, []byte("1A 2B 3C 4D 5E")) {
		t.Errorf("expected canonical spacing, got: %s", raw)
	}
}

func TestBuildIR_Parsed(t *testing.T) {
	raw, err := BuildIR(IRBuildParams{
		Name: "TV",
		Signals: []IRSignal{
			{Name: "Power", Protocol: "NEC", Address: "00 00 00 00", Command: "45 00 00 00"},
		},
	})
	if err != nil {
		t.Fatalf("BuildIR: %v", err)
	}
	parsed, err := ParseIR(raw)
	if err != nil {
		t.Fatalf("ParseIR: %v", err)
	}
	if len(parsed.Signals) != 1 {
		t.Fatalf("Signals len = %d, want 1", len(parsed.Signals))
	}
	if parsed.Signals[0].Protocol != "NEC" {
		t.Errorf("Protocol round-trip: %q", parsed.Signals[0].Protocol)
	}
}

func TestBuildIR_Raw(t *testing.T) {
	raw, err := BuildIR(IRBuildParams{
		Signals: []IRSignal{
			{
				Name:      "pulse",
				Type:      "raw",
				Frequency: 38000,
				DutyCycle: 0.33,
				Data:      []int{100, -100, 100, -100},
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildIR (raw): %v", err)
	}
	parsed, _ := ParseIR(raw)
	if parsed.Signals[0].Frequency != 38000 {
		t.Errorf("raw Frequency round-trip: %d", parsed.Signals[0].Frequency)
	}
	if len(parsed.Signals[0].Data) != 4 {
		t.Errorf("raw Data round-trip len = %d, want 4", len(parsed.Signals[0].Data))
	}
}

func TestBuildIR_RejectsEmpty(t *testing.T) {
	if _, err := BuildIR(IRBuildParams{}); err == nil {
		t.Error("empty signals should error")
	}
}

func TestBuildIR_RejectsMissingParsedFields(t *testing.T) {
	_, err := BuildIR(IRBuildParams{
		Signals: []IRSignal{{Name: "x", Protocol: "NEC"}}, // missing Address/Command
	})
	if err == nil {
		t.Error("parsed signal without address/command should error")
	}
}

func TestBuildNFC_UIDOnly(t *testing.T) {
	raw, err := BuildNFC(NFCBuildParams{
		DeviceType: "Mifare Classic",
		UID:        "AA BB CC DD",
		ATQA:       "0004",
		SAK:        "08",
	})
	if err != nil {
		t.Fatalf("BuildNFC: %v", err)
	}
	parsed, err := ParseNFC(raw)
	if err != nil {
		t.Fatalf("ParseNFC: %v", err)
	}
	if parsed.UID != "AA BB CC DD" {
		t.Errorf("UID round-trip: %q", parsed.UID)
	}
	if parsed.DeviceType != "Mifare Classic" {
		t.Errorf("DeviceType round-trip: %q", parsed.DeviceType)
	}
}

func TestBuildNFC_WithBlocks(t *testing.T) {
	raw, err := BuildNFC(NFCBuildParams{
		DeviceType: "Mifare Classic",
		UID:        "AABBCCDD",
		Blocks: map[int]string{
			0: "AABBCCDD04080004112233445566778899",
			1: "00000000000000000000000000000000",
		},
	})
	if err != nil {
		t.Fatalf("BuildNFC: %v", err)
	}
	parsed, _ := ParseNFC(raw)
	if len(parsed.Blocks) != 2 {
		t.Fatalf("Blocks len = %d, want 2", len(parsed.Blocks))
	}
	// The parser maps the normalised hex string back.
	if parsed.Blocks[0] == "" {
		t.Error("Block 0 dropped on round-trip")
	}
}

func TestBuildNFC_InvalidUIDRejects(t *testing.T) {
	_, err := BuildNFC(NFCBuildParams{DeviceType: "NTAG213", UID: "ZZZZ"})
	if err == nil {
		t.Fatal("non-hex UID should reject")
	}
}

func TestBuildNFC_UIDLengthAgainstDeviceType(t *testing.T) {
	// Mifare Classic accepts 4 or 7 byte UIDs; NTAG must be 7.
	// A 4-byte UID on NTAG should reject, catching the exact mismatch
	// the reviewer flagged.
	cases := []struct {
		deviceType string
		uid        string
		wantErr    bool
		hint       string
	}{
		{"Mifare Classic", "AA BB CC DD", false, "Classic accepts 4-byte UID"},
		{"Mifare Classic 1K", "AA BB CC DD EE FF 00", false, "Classic also accepts 7-byte UID"},
		{"Mifare Classic 1K", "AA BB CC", true, "3-byte UID rejected for Classic"},
		{"NTAG213", "AA BB CC DD EE FF 00", false, "NTAG213 requires 7-byte UID"},
		{"NTAG213", "AA BB CC DD", true, "4-byte UID rejected for NTAG213"},
		{"NTAG215", "AA BB CC DD EE FF 00", false, "NTAG215 requires 7-byte UID"},
		{"Mifare Ultralight", "AA BB CC DD EE FF 00", false, "Ultralight requires 7-byte UID"},
		{"Mifare Ultralight", "AA BB CC DD", true, "4-byte UID rejected for Ultralight"},
		{"Unknown Proprietary Tag", "AA BB", false, "unknown device type is permissive"},
		{"DESFire", "AA BB CC DD", false, "DESFire accepts 4-byte UID"},
		{"DESFire", "AA BB CC DD EE FF 00", false, "DESFire accepts 7-byte UID"},
	}
	for _, c := range cases {
		_, err := BuildNFC(NFCBuildParams{DeviceType: c.deviceType, UID: c.uid})
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected error (UID=%q, type=%q)", c.hint, c.uid, c.deviceType)
			}
		} else {
			if err != nil {
				t.Errorf("%s: unexpected error: %v", c.hint, err)
			}
		}
	}
}

func TestNormaliseHexBytes(t *testing.T) {
	cases := []struct {
		in, want string
		err      bool
	}{
		{"AABB", "AA BB", false},
		{"aabb", "AA BB", false},
		{"aa bb cc", "AA BB CC", false},
		{"AA BB CC", "AA BB CC", false},
		{"AAB", "", true},                     // odd length
		{"ZZZZ", "", true},                    // non-hex
		{"", "", true},                        // empty
		{" AA  BB\tCC\t ", "AA BB CC", false}, // extra whitespace
	}
	for _, c := range cases {
		got, err := normaliseHexBytes(c.in)
		if c.err {
			if err == nil {
				t.Errorf("normaliseHexBytes(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normaliseHexBytes(%q) errored: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("normaliseHexBytes(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
