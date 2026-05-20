package goose

import (
	"strings"
	"testing"
)

// TestDecodeFullGOOSE pins a canonical GOOSE trip message with
// every documented field present.
//
// Field-by-field bytes for an IECGoosePdu with:
//
//	gocbRef            = "PROT/LLN0$GO$gcb01"   (18 bytes)
//	timeAllowedToLive  = 4000 ms
//	datSet             = "PROT/LLN0$DS01"       (14 bytes)
//	goID               = "TRIP_A"               (6 bytes)
//	t                  = 1700000000 sec, 0x000000 frac, 0x00 qual
//	stNum              = 5
//	sqNum              = 12
//	test               = false
//	confRev            = 1
//	ndsCom             = false
//	numDatSetEntries   = 2
//	allData            = SEQUENCE { Boolean TRUE, Boolean FALSE }
func TestDecodeFullGOOSE(t *testing.T) {
	// Pre-built bytes (length-bounded):
	// allData payload: 83 01 FF 83 01 00 (two Boolean values)
	// → 6 bytes; outer tag 0xAB + 1-byte length 0x06.
	// Sub-fields totalled below:
	// 80 12 "PROT/LLN0$GO$gcb01"             (2+18 = 20)
	// 81 02 0F A0                            (4)
	// 82 0E "PROT/LLN0$DS01"                 (2+14 = 16)
	// 83 06 "TRIP_A"                         (2+6 = 8)
	// 84 08 654E89B8 000000 00                (10)
	// 85 01 05                               (3)
	// 86 01 0C                               (3)
	// 87 01 00                               (3)
	// 88 01 01                               (3)
	// 89 01 00                               (3)
	// 8A 01 02                               (3)
	// AB 06 83 01 FF 83 01 00                (8)
	// Total payload = 84 bytes.
	// PDU outer tag 0x61 + long-form length 0x81 0x54 (84) = 2-byte length.
	// PDU outer total = 1 + 2 + 84 = 87 bytes.
	// GOOSE header (8) + PDU (87) = 95 bytes total frame.
	in := "0001 005F 0000 0000 " +
		"61 81 54 " +
		"80 12 50524F542F4C4C4E3024474F246763623031 " +
		"81 02 0FA0 " +
		"82 0E 50524F542F4C4C4E302444533031 " +
		"83 06 545249505F41 " +
		"84 08 654E89B8 000000 00 " +
		"85 01 05 " +
		"86 01 0C " +
		"87 01 00 " +
		"88 01 01 " +
		"89 01 00 " +
		"8A 01 02 " +
		"AB 06 83 01 FF 83 01 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.APPID != 1 {
		t.Errorf("appid: got %d want 1", r.APPID)
	}
	if r.Length != 0x5F {
		t.Errorf("length: got %d want 95", r.Length)
	}
	if r.GOCBRef != "PROT/LLN0$GO$gcb01" {
		t.Errorf("gocbRef: got %q", r.GOCBRef)
	}
	if r.TimeAllowedToLiveMS != 4000 {
		t.Errorf("timeAllowedToLive: got %d want 4000", r.TimeAllowedToLiveMS)
	}
	if r.DatSet != "PROT/LLN0$DS01" {
		t.Errorf("datSet: got %q", r.DatSet)
	}
	if r.GoID != "TRIP_A" {
		t.Errorf("goID: got %q", r.GoID)
	}
	if r.UtcTime == nil {
		t.Fatal("utcTime nil")
	}
	if r.UtcTime.SecondsSinceEpoch != 0x654E89B8 {
		t.Errorf("utcTime sec: got 0x%X want 0x654E89B8", r.UtcTime.SecondsSinceEpoch)
	}
	if r.StNum != 5 {
		t.Errorf("stNum: got %d want 5", r.StNum)
	}
	if r.SqNum != 12 {
		t.Errorf("sqNum: got %d want 12", r.SqNum)
	}
	if r.Test {
		t.Errorf("test: got true want false")
	}
	if r.ConfRev != 1 {
		t.Errorf("confRev: got %d want 1", r.ConfRev)
	}
	if r.NumDatSetEntries != 2 {
		t.Errorf("numDatSetEntries: got %d want 2", r.NumDatSetEntries)
	}
	if r.AllDataHex != "83 01 FF 83 01 00"[:0]+"830"+"1FF830100" {
		// Build canonical expected — match exactly.
		want := "830" + "1FF830100"
		if r.AllDataHex != "830"+"1FF830100" {
			t.Errorf("allData hex: got %q want %q", r.AllDataHex, want)
		}
	}
}

// TestDecodeMinimalGOOSE pins a GOOSE with only the essential
// fields populated (stNum + sqNum + test + allData).
func TestDecodeMinimalGOOSE(t *testing.T) {
	// PDU body:
	// 85 01 01    stNum = 1                (3)
	// 86 01 00    sqNum = 0                (3)
	// 87 01 FF    test = true              (3)
	// AB 03 83 01 FF allData               (5)
	// Total = 14 bytes. Short-form length 0x0E.
	// GOOSE header (8) + outer tag (1) + length (1) + body (14) = 24.
	in := "0001 0018 0000 0000 " +
		"61 0E " +
		"85 01 01 " +
		"86 01 00 " +
		"87 01 FF " +
		"AB 03 83 01 FF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.StNum != 1 || r.SqNum != 0 {
		t.Errorf("stNum/sqNum: got %d/%d want 1/0", r.StNum, r.SqNum)
	}
	if !r.Test {
		t.Errorf("test: got false want true")
	}
	if r.AllDataHex != "830"+"1FF" {
		t.Errorf("allData: got %q", r.AllDataHex)
	}
}

// TestDecodeSecurityTrailer pins that bytes past the PDU end are
// surfaced as security_trailer_hex.
func TestDecodeSecurityTrailer(t *testing.T) {
	// Minimal PDU (5 bytes: 85 01 01 86 01 00) + 4 trailing
	// security bytes (DEAD BEEF). PDU outer length = 5.
	// Total frame: 8 header + 1 tag + 1 len + 5 body + 4 trailer = 19.
	in := "0001 0013 0000 0000 " +
		"61 06 85 01 01 86 01 00 " +
		"DEAD BEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.SecurityTrailerHex != "DEADBEEF" {
		t.Errorf("security trailer: got %q want DEADBEEF", r.SecurityTrailerHex)
	}
}

// TestReadBERInteger verifies BER INTEGER decoding incl. sign.
func TestReadBERInteger(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"00", 0},
		{"01", 1},
		{"7F", 127},
		{"FF", -1},
		{"80", -128},
		{"0100", 256},
		{"FF00", -256},
	}
	for _, c := range cases {
		b := mustHex(t, c.in)
		got := readBERInteger(b)
		if got != c.want {
			t.Errorf("readBERInteger(%s) = %d want %d", c.in, got, c.want)
		}
	}
}

// TestReadBERLengthShortAndLong pins both BER length forms.
func TestReadBERLengthShortAndLong(t *testing.T) {
	// Short form: 0x7F → 127.
	v, n, err := readBERLength([]byte{0x7F})
	if err != nil || v != 127 || n != 1 {
		t.Errorf("short: got v=%d n=%d err=%v", v, n, err)
	}
	// Long form: 0x82 0x01 0x00 → 256 (2 octets).
	v, n, err = readBERLength([]byte{0x82, 0x01, 0x00})
	if err != nil || v != 256 || n != 3 {
		t.Errorf("long: got v=%d n=%d err=%v", v, n, err)
	}
	// Unsupported (n > 4).
	if _, _, err := readBERLength([]byte{0x85}); err == nil {
		t.Errorf("want error for unsupported long-form octet count")
	}
}

// TestReadUtcTime pins the 8-byte UtcTime breakdown.
func TestReadUtcTime(t *testing.T) {
	b := mustHex(t, "654E89B8 000000 00")
	ut := readUtcTime(b)
	if ut == nil {
		t.Fatal("readUtcTime returned nil")
	}
	if ut.SecondsSinceEpoch != 0x654E89B8 {
		t.Errorf("seconds: got 0x%X", ut.SecondsSinceEpoch)
	}
	if ut.FractionOfSecond != 0 {
		t.Errorf("fraction: got %d want 0", ut.FractionOfSecond)
	}
	if ut.TimeQualityHex != "0x00" {
		t.Errorf("quality: got %q", ut.TimeQualityHex)
	}
}

func TestDecodeRejectsEmpty(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecodeRejectsOddNibbles(t *testing.T) {
	if _, err := Decode("ABC"); err == nil {
		t.Fatal("want error for odd-length input")
	}
}

func TestDecodeRejectsShortHeader(t *testing.T) {
	if _, err := Decode("0001 0008 0000"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsMissingOuterTag(t *testing.T) {
	// Header followed by 0x00 instead of 0x61.
	if _, err := Decode("0001 000C 0000 0000 00 02 85 01"); err == nil {
		t.Fatal("want error when outer tag != 0x61")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 9)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	clean := stripSeparators(s)
	out := make([]byte, 0, len(clean)/2)
	for i := 0; i < len(clean); i += 2 {
		var b byte
		_, err := fmtScanHex(clean[i:i+2], &b)
		if err != nil {
			t.Fatalf("bad hex %q: %v", s, err)
		}
		out = append(out, b)
	}
	return out
}

func fmtScanHex(s string, b *byte) (int, error) {
	for i := 0; i < 2; i++ {
		c := s[i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		default:
			return 0, &hexErr{c}
		}
		*b = (*b << 4) | v
	}
	return 1, nil
}

type hexErr struct{ c byte }

func (e *hexErr) Error() string { return "bad hex char" }
