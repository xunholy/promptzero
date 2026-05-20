package tftp

import (
	"strings"
	"testing"
)

func TestDecode_RRQ_OctetMode(t *testing.T) {
	// RRQ for "pxelinux.0" in octet mode, no options.
	in := "0001 70 78 65 6C 69 6E 75 78 2E 30 00 6F 63 74 65 74 00"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "RRQ (Read Request)" {
		t.Errorf("opcode: %q", r.OpcodeName)
	}
	if r.RRQ == nil {
		t.Fatal("RRQ body nil")
	}
	if r.RRQ.Filename != "pxelinux.0" {
		t.Errorf("filename: %q", r.RRQ.Filename)
	}
	if r.RRQ.Mode != "octet" {
		t.Errorf("mode: %q", r.RRQ.Mode)
	}
}

func TestDecode_RRQ_WithOptions(t *testing.T) {
	// RRQ for "boot.img" octet + blksize=1468 + tsize=0.
	in := "0001 626F6F742E696D67 00 6F63746574 00" +
		"626C6B73697A65 00 31343638 00" +
		"7473697A65 00 30 00"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RRQ.Filename != "boot.img" {
		t.Errorf("filename: %q", r.RRQ.Filename)
	}
	if len(r.RRQ.Options) != 2 {
		t.Fatalf("options: %+v", r.RRQ.Options)
	}
	if r.RRQ.Options[0].Name != "blksize" ||
		r.RRQ.Options[0].Value != "1468" ||
		r.RRQ.Options[0].NameKnown != "Block Size (RFC 2348)" {
		t.Errorf("blksize: %+v", r.RRQ.Options[0])
	}
	if r.RRQ.Options[1].Name != "tsize" ||
		r.RRQ.Options[1].Value != "0" ||
		r.RRQ.Options[1].NameKnown != "Transfer Size (RFC 2349)" {
		t.Errorf("tsize: %+v", r.RRQ.Options[1])
	}
}

func TestDecode_WRQ_NetASCIIMode(t *testing.T) {
	// WRQ for "config.txt" in netascii mode.
	in := "0002 636F6E6669672E747874 00 6E65746173636969 00"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "WRQ (Write Request)" {
		t.Errorf("opcode: %q", r.OpcodeName)
	}
	if r.WRQ.Filename != "config.txt" || r.WRQ.Mode != "netascii" {
		t.Errorf("body: %+v", r.WRQ)
	}
}

func TestDecode_DATA_WithTextPayload(t *testing.T) {
	// DATA block 1 with "Hello, world!\n" payload (14 bytes).
	in := "0003 0001 48656C6C6F2C20776F726C64210A"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.DATA == nil {
		t.Fatal("DATA body nil")
	}
	if r.DATA.BlockNumber != 1 {
		t.Errorf("block: %d", r.DATA.BlockNumber)
	}
	if r.DATA.PayloadBytes != 14 {
		t.Errorf("payload bytes: %d", r.DATA.PayloadBytes)
	}
	if r.DATA.PayloadText != "Hello, world!\n" {
		t.Errorf("payload text: %q", r.DATA.PayloadText)
	}
}

func TestDecode_DATA_PayloadCap(t *testing.T) {
	// DATA block with a 100-byte payload, capped to 32.
	in := "0003 0001 " + strings.Repeat("AA", 100)
	r, err := Decode(in, DecodeOpts{MaxPayloadBytes: 32})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.DATA.PayloadBytes != 100 {
		t.Errorf("payload bytes: %d", r.DATA.PayloadBytes)
	}
	if r.DATA.PayloadBytesShown != 32 {
		t.Errorf("payload shown: %d", r.DATA.PayloadBytesShown)
	}
}

func TestDecode_ACK_BlockNumber(t *testing.T) {
	in := "0004 0005"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ACK == nil || r.ACK.BlockNumber != 5 {
		t.Errorf("ACK: %+v", r.ACK)
	}
}

func TestDecode_ERROR_FileNotFound(t *testing.T) {
	// Error code 1 + message "File not found".
	in := "0005 0001 46696C65206E6F7420666F756E64 00"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ERROR == nil {
		t.Fatal("ERROR body nil")
	}
	if r.ERROR.ErrorCode != 1 || r.ERROR.ErrorName != "File not found" {
		t.Errorf("code: %d %q", r.ERROR.ErrorCode, r.ERROR.ErrorName)
	}
	if r.ERROR.ErrorMessage != "File not found" {
		t.Errorf("message: %q", r.ERROR.ErrorMessage)
	}
}

func TestDecode_OACK_WithOptions(t *testing.T) {
	// OACK with blksize=1468.
	in := "0006 626C6B73697A65 00 31343638 00"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OACK == nil {
		t.Fatal("OACK body nil")
	}
	if len(r.OACK.Options) != 1 ||
		r.OACK.Options[0].Name != "blksize" ||
		r.OACK.Options[0].Value != "1468" {
		t.Errorf("OACK options: %+v", r.OACK.Options)
	}
}

func TestDecode_OpcodeNameTable(t *testing.T) {
	cases := map[int]string{
		1: "RRQ (Read Request)",
		2: "WRQ (Write Request)",
		3: "DATA",
		4: "ACK",
		5: "ERROR",
		6: "OACK (Option Acknowledgment, RFC 2347)",
	}
	for k, v := range cases {
		if got := opcodeName(k); got != v {
			t.Errorf("opcodeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_ErrorNameTable(t *testing.T) {
	cases := map[int]string{
		0: "Not defined",
		1: "File not found",
		2: "Access violation",
		3: "Disk full or allocation exceeded",
		4: "Illegal TFTP operation",
		5: "Unknown transfer ID",
		6: "File already exists",
		7: "No such user",
		8: "Option negotiation failure (RFC 2347)",
	}
	for k, v := range cases {
		if got := errorName(k); got != v {
			t.Errorf("errorName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_UncataloguedOpcode_Note(t *testing.T) {
	// Opcode 99.
	in := "0063"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "uncatalogued") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected uncatalogued note in: %v", r.Notes)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "00 0",
		"short":   "00",
		"bad hex": "ZZ 01",
	}
	for name, in := range cases {
		_, err := Decode(in, DefaultDecodeOpts())
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
