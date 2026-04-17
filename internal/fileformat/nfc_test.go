package fileformat

import (
	"reflect"
	"strings"
	"testing"
)

const nfcFixture = `Filetype: Flipper NFC device
Version: 4
Device type: Mifare Classic
UID: 04 A2 B3 C4 D5 E6 F7
ATQA: 00 04
SAK: 08
Mifare Classic type: 1K
Block 0: 04 A2 B3 C4 D5 E6 F7 08 04 00 62 63 64 65 66 67
Block 1: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Block 4: FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00
`

func TestParseNFC(t *testing.T) {
	n, err := ParseNFC([]byte(nfcFixture))
	if err != nil {
		t.Fatalf("ParseNFC: %v", err)
	}
	if n.UID != "04 A2 B3 C4 D5 E6 F7" || n.SAK != "08" {
		t.Fatalf("unexpected fields: %+v", n)
	}
	if n.Blocks[4] != "FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00" {
		t.Fatalf("block 4: %q", n.Blocks[4])
	}
	if n.MifareType != "1K" {
		t.Fatalf("MifareType: %q", n.MifareType)
	}
}

func TestNFC_RoundTrip(t *testing.T) {
	assertNFCRoundTrip(t, nfcFixture)
}

func TestNFC_CRLFAndComments(t *testing.T) {
	crlf := "# dump\r\n\r\n" + strings.ReplaceAll(nfcFixture, "\n", "\r\n")
	assertNFCRoundTrip(t, crlf)
}

func TestNFC_MissingFinalNewline(t *testing.T) {
	assertNFCRoundTrip(t, strings.TrimRight(nfcFixture, "\n"))
}

func TestNFC_EditBlockAndUID(t *testing.T) {
	n, err := ParseNFC([]byte(nfcFixture))
	if err != nil {
		t.Fatal(err)
	}
	edits := map[string]interface{}{
		"uid":     "DE AD BE EF",
		"block_4": "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	}
	if err := applyNFCEdits(n, edits); err != nil {
		t.Fatalf("applyNFCEdits: %v", err)
	}
	if n.UID != "DE AD BE EF" {
		t.Fatalf("UID not applied: %q", n.UID)
	}
	if n.Blocks[4] != "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" {
		t.Fatalf("block 4 not edited")
	}
}

func TestNFC_RejectUnknownEdit(t *testing.T) {
	n, _ := ParseNFC([]byte(nfcFixture))
	if err := applyNFCEdits(n, map[string]interface{}{"uids": "bad"}); err == nil {
		t.Fatalf("expected error for unknown key")
	}
}

func assertNFCRoundTrip(t *testing.T, fixture string) {
	t.Helper()
	a, err := ParseNFC([]byte(fixture))
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	b, err := ParseNFC(a.Marshal())
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("round-trip mismatch\nA: %+v\nB: %+v", a, b)
	}
}
