package flipper

import (
	"strings"
	"testing"
)

// ----- NFC detect -----

const nfcDetectNTAG215 = `[ISO14443-3a (NFC-A)]
UID: 04 A5 B3 1D 2C 4F 80
ATQA: 00 44
SAK: 00
Type: NTAG215
> `

const nfcDetectClassic1K = `[ISO14443-3a (NFC-A)]
UID: AA BB CC DD
ATQA: 00 04
SAK: 08
Type: MIFARE Classic 1K
`

const nfcDetectTimeout = `Scanning...
Target lost.
> `

func TestParseNFCDetect_NTAG215(t *testing.T) {
	r := ParseNFCDetect(nfcDetectNTAG215)
	if !r.Detected {
		t.Fatal("should have detected")
	}
	if r.UID != "04 A5 B3 1D 2C 4F 80" {
		t.Errorf("UID = %q", r.UID)
	}
	if r.ATQA != "00 44" {
		t.Errorf("ATQA = %q", r.ATQA)
	}
	if r.SAK != "00" {
		t.Errorf("SAK = %q", r.SAK)
	}
	if r.Type != "NTAG215" {
		t.Errorf("Type = %q", r.Type)
	}
	if r.Technology != "ISO14443-3a (NFC-A)" {
		t.Errorf("Technology = %q", r.Technology)
	}
}

func TestParseNFCDetect_Classic(t *testing.T) {
	r := ParseNFCDetect(nfcDetectClassic1K)
	if !r.Detected {
		t.Fatal("should have detected")
	}
	if r.UID != "AA BB CC DD" {
		t.Errorf("UID = %q", r.UID)
	}
	if !strings.Contains(r.Type, "MIFARE Classic") {
		t.Errorf("Type = %q", r.Type)
	}
}

func TestParseNFCDetect_Timeout(t *testing.T) {
	r := ParseNFCDetect(nfcDetectTimeout)
	if r.Detected {
		t.Fatalf("should not have detected; got %+v", r)
	}
	if r.UID != "" {
		t.Errorf("UID should be empty on timeout: %q", r.UID)
	}
}

func TestParseNFCDetect_Empty(t *testing.T) {
	r := ParseNFCDetect("")
	if r.Detected {
		t.Error("empty input should not detect")
	}
}

func TestParseNFCDetect_ColonSeparator(t *testing.T) {
	// Some firmware versions use colons as byte separators: "04:A5:B3:..."
	raw := `[ISO14443-3a]
UID: 04:A5:B3:1D:2C:4F:80
Type: NTAG215`
	r := ParseNFCDetect(raw)
	if r.UID != "04 A5 B3 1D 2C 4F 80" {
		t.Errorf("colon-separated UID not normalised: %q", r.UID)
	}
}

// ----- storage stat -----

func TestParseStorageStat_File(t *testing.T) {
	raw := `File, size: 1024
> `
	r := ParseStorageStat(raw)
	if !r.Exists {
		t.Fatal("should exist")
	}
	if r.IsDir {
		t.Error("should not be a directory")
	}
	if r.SizeBytes != 1024 {
		t.Errorf("SizeBytes = %d, want 1024", r.SizeBytes)
	}
}

func TestParseStorageStat_Directory(t *testing.T) {
	raw := `Directory
> `
	r := ParseStorageStat(raw)
	if !r.Exists {
		t.Fatal("directory should count as exists")
	}
	if !r.IsDir {
		t.Error("should be marked IsDir")
	}
}

func TestParseStorageStat_Error(t *testing.T) {
	raw := `Storage error: not found`
	r := ParseStorageStat(raw)
	if r.Exists {
		t.Error("storage error should not count as exists")
	}
	if r.Error != "not found" {
		t.Errorf("Error = %q", r.Error)
	}
}

func TestParseStorageStat_Empty(t *testing.T) {
	r := ParseStorageStat("")
	if r.Exists {
		t.Error("empty input should not exist")
	}
}

// ----- subghz receive -----

const sgRxSingleProtocol = `
[Protocol: Princeton]
  Frequency: 433920000
  Key: 00 00 00 1A 2B 3C 4D 00
  Bit: 24
  TE: 400
> `

const sgRxMultipleProtocols = `
[Protocol: CAME]
  Frequency: 433920000
  Key: 55 55 55 55 55 00 00 00
  Bit: 12
  RSSI: -62

[Protocol: Princeton]
  Frequency: 433920000
  Key: 00 00 00 1A 2B 3C 4D 00
  Bit: 24
  TE: 400
> `

func TestParseSubGHzReceive_SingleProtocol(t *testing.T) {
	r := ParseSubGHzReceive(sgRxSingleProtocol)
	if r.Count != 1 {
		t.Fatalf("Count = %d, want 1", r.Count)
	}
	c := r.Candidates[0]
	if c.Protocol != "Princeton" {
		t.Errorf("Protocol = %q", c.Protocol)
	}
	if c.Frequency != 433920000 {
		t.Errorf("Frequency = %d", c.Frequency)
	}
	if c.Bit != 24 {
		t.Errorf("Bit = %d", c.Bit)
	}
	if c.TE != 400 {
		t.Errorf("TE = %d", c.TE)
	}
	if !strings.Contains(c.Key, "1A 2B 3C 4D") {
		t.Errorf("Key = %q", c.Key)
	}
}

func TestParseSubGHzReceive_MultipleProtocols(t *testing.T) {
	r := ParseSubGHzReceive(sgRxMultipleProtocols)
	if r.Count != 2 {
		t.Fatalf("Count = %d, want 2", r.Count)
	}
	if r.Candidates[0].Protocol != "CAME" {
		t.Errorf("Candidates[0].Protocol = %q", r.Candidates[0].Protocol)
	}
	if r.Candidates[0].RSSI != -62 {
		t.Errorf("Candidates[0].RSSI = %d", r.Candidates[0].RSSI)
	}
	if r.Candidates[1].Protocol != "Princeton" {
		t.Errorf("Candidates[1].Protocol = %q", r.Candidates[1].Protocol)
	}
}

func TestParseSubGHzReceive_NoProtocols(t *testing.T) {
	raw := `Starting RX on 433920000Hz...
No signals detected.
> `
	r := ParseSubGHzReceive(raw)
	if r.Count != 0 {
		t.Errorf("Count = %d, want 0", r.Count)
	}
	if len(r.RawLines) < 2 {
		t.Errorf("expected raw lines, got %v", r.RawLines)
	}
}

func TestParseSubGHzReceive_Empty(t *testing.T) {
	r := ParseSubGHzReceive("")
	if r.Count != 0 {
		t.Errorf("Count = %d, want 0", r.Count)
	}
}

// ----- helpers -----

func TestNormaliseNFCHex(t *testing.T) {
	cases := map[string]string{
		"AABBCC":        "AA BB CC",
		"aa bb cc":      "AA BB CC",
		"AA:BB:CC":      "AA BB CC",
		" aa  bb\tcc\t": "AA BB CC",
		"":              "",
		"AABBC":         "AABBC", // odd-length pass-through
	}
	for in, want := range cases {
		if got := normaliseNFCHex(in); got != want {
			t.Errorf("normaliseNFCHex(%q) = %q, want %q", in, got, want)
		}
	}
}
