package tools

import (
	"strings"
	"testing"
)

// FuzzDecodeEM4100Frame exercises the 64-bit EM4100 wire-frame decoder on
// arbitrary bit-strings — the header/row/column parity walk must never index
// out of range regardless of length or content.
func FuzzDecodeEM4100Frame(f *testing.F) {
	seeds := []string{
		"",
		strings.Repeat("0", 64),
		"111111111" + strings.Repeat("0", 55),
		"111111111" + strings.Repeat("11110", 10) + "0000" + "0",
		strings.Repeat("1", 64),
		"111111111",
		"abc",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeEM4100Frame(s) })
}
