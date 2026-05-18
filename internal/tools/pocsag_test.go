package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestPocsagDecodeHandler_BitsHappyPath sends a small synthesised
// bit-stream — sync + address + numeric message + idle padding —
// and confirms the Spec handler decodes it into JSON the agent can
// re-render. Mirrors internal/pocsag's TestDecode_BitStream.
func TestPocsagDecodeHandler_BitsHappyPath(t *testing.T) {
	// SyncWord 0x7CD215D8, then a single batch with one address
	// codeword (RIC 0x12340, fn=0) + one message codeword (digits
	// "12345" with the spec's LSB-first nibble packing), then 14
	// idle codewords to round out the batch. Codeword values were
	// computed by the internal/pocsag test helpers; documented inline
	// so the test reads without cross-referencing.
	const (
		sync = "01111100110100100001010111011000" // 0x7CD215D8
		// Address codeword 0x048D0001:
		//   addrMSB = RIC 0x12340 >> 3 = 0x2468
		//   data    = (addrMSB << 2) | fn=0 = 0x91A0
		//   w       = (data << 11) & 0x7FFFF800 = 0x048D0000
		//   parity  = OnesCount(0x048D0000) % 2 = 1
		addrWord = "00000100100011010000000000000001" // 0x048D0001
		// Numeric "12345" → LSB-reversed-nibble packing per spec:
		//   '1'=0001→8, '2'=0010→4, '3'=0011→C, '4'=0100→2, '5'=0101→A
		//   packed MSB-first: 0x84C2A (20 bits)
		// Message codeword 0xC2615000:
		//   w      = (1 << 31) | (0x84C2A << 11) = 0xC2615000
		//   parity = OnesCount(0xC2615000) % 2 = 0
		msgWord = "11000010011000010101000000000000" // 0xC2615000
		idle    = "01111010100010011100000110010111" // 0x7A89C197
	)
	stream := sync + addrWord + msgWord + strings.Repeat(idle, 14)
	out, err := pocsagDecodeHandler(context.Background(), nil, map[string]any{"bits": stream})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var got struct {
		Pages []struct {
			Address    uint32 `json:"address"`
			AddressHex string `json:"address_hex"`
			Function   int    `json:"function"`
			Encoding   string `json:"encoding"`
			Message    string `json:"message"`
		} `json:"pages"`
		PageCount int `json:"page_count"`
		Batches   int `json:"batches"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}
	if got.PageCount != 1 {
		t.Fatalf("PageCount = %d; want 1\n%s", got.PageCount, out)
	}
	if got.Pages[0].Address != 0x12340 {
		t.Errorf("Address = 0x%X; want 0x12340", got.Pages[0].Address)
	}
	if got.Pages[0].Encoding != "numeric" {
		t.Errorf("Encoding = %q; want 'numeric'", got.Pages[0].Encoding)
	}
	if got.Pages[0].Message != "12345" {
		t.Errorf("Message = %q; want '12345'", got.Pages[0].Message)
	}
}

// TestPocsagDecodeHandler_CodewordsHappyPath uses the codewords
// input path — directly passing the same address + message
// codewords as hex.
func TestPocsagDecodeHandler_CodewordsHappyPath(t *testing.T) {
	addr := uint32(0x048D0001)
	msg := uint32(0xC2615000)
	in := fmt.Sprintf("%08X %08X", addr, msg)
	out, err := pocsagDecodeHandler(context.Background(), nil, map[string]any{"codewords": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"page_count": 1`) {
		t.Errorf("expected page_count=1 in JSON:\n%s", out)
	}
}

func TestPocsagDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := pocsagDecodeHandler(context.Background(), nil, map[string]any{})
	if err == nil {
		t.Fatal("want error for missing bits/codewords")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("err = %v", err)
	}
}

func TestPocsagDecodeHandler_RejectsBoth(t *testing.T) {
	_, err := pocsagDecodeHandler(context.Background(), nil, map[string]any{
		"bits":      "0101",
		"codewords": "ABCDEF01",
	})
	if err == nil {
		t.Fatal("want error when both bits and codewords are set")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Errorf("err = %v", err)
	}
}
