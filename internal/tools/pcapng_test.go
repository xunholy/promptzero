package tools

import (
	"context"
	"strings"
	"testing"
)

// TestPCAPngDecodeHandler_SHB_IDB_EPB pins a canonical
// PCAPng file with one SHB + IDB + EPB.
func TestPCAPngDecodeHandler_SHB_IDB_EPB(t *testing.T) {
	in := "0A0D0D0A 1C000000" +
		"4D3C2B1A 01000000 FFFFFFFFFFFFFFFF" +
		"1C000000" +
		"01000000 14000000" +
		"0100 0000 FFFF0000" +
		"14000000" +
		"06000000 24000000" +
		"00000000 00000000 64000000 04000000 04000000" +
		"DEADBEEF" +
		"24000000"
	out, err := pcapngDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"endianness": "little"`,
		`"major_version": 1`,
		`"link_type_name": "LINKTYPE_ETHERNET"`,
		`"snap_length": 65535`,
		`"payload_hex": "DEADBEEF"`,
		`"SHB": 1`,
		`"IDB": 1`,
		`"EPB": 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestPCAPngDecodeHandler_BigEndian pins a BE SHB-only file.
func TestPCAPngDecodeHandler_BigEndian(t *testing.T) {
	in := "0A0D0D0A 0000001C" +
		"1A2B3C4D 0001 0000 FFFFFFFFFFFFFFFF" +
		"0000001C"
	out, err := pcapngDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"endianness": "big"`) {
		t.Errorf("expected big endian:\n%s", out)
	}
}

// TestPCAPngDecodeHandler_OptionsTextSurfaced pins SHB options
// with text values exposed as ValueText.
func TestPCAPngDecodeHandler_OptionsTextSurfaced(t *testing.T) {
	in := "0A0D0D0A 38000000" +
		"4D3C2B1A 01000000 FFFFFFFFFFFFFFFF" +
		"0100 0500 68656C6C6F 000000" +
		"0200 0600 7838365F3634 0000" +
		"0000 0000" +
		"38000000"
	out, err := pcapngDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"value_text": "hello"`,
		`"value_text": "x86_64"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestPCAPngDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := pcapngDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
