// SPDX-License-Identifier: AGPL-3.0-or-later

package quic

import (
	"encoding/hex"
	"strings"
	"testing"
)

// cryptoFrame builds a QUIC CRYPTO frame (type 0x06 + varint offset + varint
// length + data). offset and len are kept < 64 so each is a single-byte QUIC
// varint, which is all these reassembly tests need.
func cryptoFrame(offset uint64, data string) []byte {
	if offset >= 64 || len(data) >= 64 {
		panic("test helper only supports 1-byte varints (<64)")
	}
	f := []byte{0x06, byte(offset), byte(len(data))}
	return append(f, []byte(data)...)
}

func streamHex(s string) string { return strings.ToUpper(hex.EncodeToString([]byte(s))) }

func hasNote(notes []string, substr string) bool {
	for _, n := range notes {
		if strings.Contains(n, substr) {
			return true
		}
	}
	return false
}

// TestCryptoReassembly covers the CRYPTO-stream reassembly: ordering,
// duplicates, overlaps, inconsistency detection, and gaps.
func TestCryptoReassembly(t *testing.T) {
	cases := []struct {
		name         string
		payload      []byte
		wantStream   string // "" = expect empty / no stream
		wantContig   bool   // false => expect the non-contiguous note
		inconsistent bool   // expect the inconsistent-overlap note
	}{
		{
			name:       "in-order contiguous",
			payload:    concat(cryptoFrame(0, "ABC"), cryptoFrame(3, "DEF")),
			wantStream: "ABCDEF", wantContig: true,
		},
		{
			name:       "out-of-order reassembles by offset",
			payload:    concat(cryptoFrame(3, "DEF"), cryptoFrame(0, "ABC")),
			wantStream: "ABCDEF", wantContig: true,
		},
		{
			name:       "exact duplicate is idempotent",
			payload:    concat(cryptoFrame(0, "ABC"), cryptoFrame(0, "ABC"), cryptoFrame(3, "DEF")),
			wantStream: "ABCDEF", wantContig: true,
		},
		{
			name:       "overlapping consistent fragment extends the tail",
			payload:    concat(cryptoFrame(0, "ABCDE"), cryptoFrame(3, "DExyz")),
			wantStream: "ABCDExyz", wantContig: true,
		},
		{
			name:         "inconsistent same-offset overlap is noted, first kept",
			payload:      concat(cryptoFrame(0, "ABC"), cryptoFrame(0, "XYZ")),
			wantStream:   "ABC", // A < X, so "ABC" wins the deterministic order
			wantContig:   true,
			inconsistent: true,
		},
		{
			name:       "gap is non-contiguous, partial stream",
			payload:    concat(cryptoFrame(0, "ABC"), cryptoFrame(10, "XYZ")),
			wantStream: "ABC", wantContig: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var d DecryptedInitial
			parseFrames(c.payload, &d)
			if d.CryptoStreamHex != streamHex(c.wantStream) {
				t.Errorf("stream = %q; want %q (%s)", d.CryptoStreamHex, streamHex(c.wantStream), c.wantStream)
			}
			gotContig := !hasNote(d.Notes, "non-contiguous")
			if gotContig != c.wantContig {
				t.Errorf("contiguous = %v; want %v (notes: %v)", gotContig, c.wantContig, d.Notes)
			}
			if got := hasNote(d.Notes, "inconsistent"); got != c.inconsistent {
				t.Errorf("inconsistent-note = %v; want %v (notes: %v)", got, c.inconsistent, d.Notes)
			}
		})
	}
}

// TestCryptoReassembly_Deterministic is the regression guard for the
// tiebreak-less sort: same-offset fragments must reassemble to the same stream
// regardless of their order in the packet (an attacker controls that order).
func TestCryptoReassembly_Deterministic(t *testing.T) {
	a := concat(cryptoFrame(0, "ABC"), cryptoFrame(0, "XYZ"), cryptoFrame(3, "DEF"))
	b := concat(cryptoFrame(0, "XYZ"), cryptoFrame(3, "DEF"), cryptoFrame(0, "ABC"))

	var da, db DecryptedInitial
	parseFrames(a, &da)
	parseFrames(b, &db)
	if da.CryptoStreamHex != db.CryptoStreamHex {
		t.Errorf("reassembly order-dependent: %q vs %q", da.CryptoStreamHex, db.CryptoStreamHex)
	}
	// Both must deterministically keep "ABC" (A < X) then "DEF".
	if want := streamHex("ABCDEF"); da.CryptoStreamHex != want {
		t.Errorf("stream = %q; want %q", da.CryptoStreamHex, want)
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
