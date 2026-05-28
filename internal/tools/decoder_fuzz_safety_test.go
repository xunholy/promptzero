package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/risk"
)

// malformedHexInputs is the battery of degenerate hex strings fed to
// every hex-taking decoder. Operators routinely paste truncated
// tcpdump lines, partial captures, mis-copied hex, or stray
// non-hex characters — none of these may panic a decoder.
var malformedHexInputs = []string{
	"",
	"0",
	"00",
	"01",
	"ff",
	"0011",
	"ffffffffffffffff",
	"0000000000000000",
	"aabbccddeeff",
	"zz",                       // non-hex
	"0x",                       // bare prefix
	"  ",                       // whitespace only
	"00:11:gg",                 // mixed valid/invalid separators
	"ﾊ",                        // multibyte UTF-8
	strings.Repeat("00", 4096), // large all-zero buffer
	strings.Repeat("ff", 4096), // large all-FF buffer (max length fields)
	// "Lying length field" cases — valid hex, plausible header, but an
	// internal length/count field that exceeds the remaining bytes.
	// This class surfaced the AH ICVBytes panic (v0.354.0). The first
	// few bytes commonly hold a length, count, or offset that a parser
	// trusts before slicing.
	"ff00000000000000",                 // leading 0xff length byte, short body
	"0000ffff0000ffff",                 // alternating zero/max 16-bit fields
	"ffffffff00000000ffffffff",         // max 32-bit length up front
	"01ffffffffffffff",                 // 1-byte then max run
	strings.Repeat("ff00", 1024),       // alternating max/zero bytes
	"080000ffffffffffffffffffffffffff", // plausible header + truncated tail
}

// isPureHexDecoder reports whether a Spec is a pure offline decoder
// that takes a single hex payload and nothing else: required set is
// exactly {"hex"}, it runs on the host (GroupHostTools), and it is
// Low-risk. Those three together exclude hardware-transmit tools like
// nfc_raw_frame (risk.High, GroupFlipperNFC) which only require "hex"
// but dereference Deps.Flipper and would (correctly) panic on a nil
// Deps. Pure decoders ignore Deps, so they can be safely swept with
// a nil Deps in a panic-safety sweep.
func isPureHexDecoder(s Spec) bool {
	if len(s.Required) != 1 || s.Required[0] != "hex" {
		return false
	}
	if s.Group != GroupHostTools || s.Risk != risk.Low {
		return false
	}
	// Confirm the schema actually declares a "hex" property so we
	// don't pass "hex" to a tool whose Required got mis-set.
	var parsed struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(s.Schema, &parsed); err != nil {
		return false
	}
	_, ok := parsed.Properties["hex"]
	return ok
}

// TestHexDecoders_MalformedInputNeverPanics drives every registered
// decoder whose sole required parameter is "hex" with a battery of
// degenerate inputs and asserts none panics. This is a cross-cutting
// regression guard: a new decoder added without bounds-checking on a
// short buffer would pass its own happy-path tests but trip here.
//
// Errors are expected and fine — the contract is "return an error or
// a benign Result, never panic".
func TestHexDecoders_MalformedInputNeverPanics(t *testing.T) {
	specs := All()
	tested := 0
	for _, s := range specs {
		if s.Handler == nil || !isPureHexDecoder(s) {
			continue
		}
		tested++
		for _, in := range malformedHexInputs {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s panicked on input %q: %v", s.Name, in, r)
					}
				}()
				_, _ = s.Handler(context.Background(), nil, map[string]any{"hex": in})
			}()
		}
	}
	// Sanity floor: we expect dozens of hex-only decoders. If this
	// drops to near-zero the filter regressed and the guard is inert.
	if tested < 50 {
		t.Errorf("only %d hex-only decoders exercised; expected 50+ — filter may have regressed", tested)
	}
	t.Logf("panic-safety swept %d hex-only decoders", tested)
}

// malformedTextInputs is the battery of degenerate strings fed to
// text/string-taking decoders (NMEA sentences, JWT tokens, SIP/HTTP
// messages, syslog lines, Wiegand/DCF77 bit strings, X.509 PEM, etc.).
// These parsers split on delimiters, decode base64 segments, and index
// into the result — all places a short or malformed input can trip a
// bounds error.
var malformedTextInputs = []string{
	"",
	" ",
	"\n",
	"\r\n",
	"\t",
	"0",
	"1",
	"a",
	".",
	":",
	",",
	"::::",
	"....",
	"\x00",
	"\x00\x00\x00",
	"=",                        // lone base64 pad
	"..",                       // empty JWT segments
	"...",                      // empty JWT segments
	"%%%",                      // stray percent (URL-ish)
	"AAAA",                     // valid base64 but meaningless
	"ﾊ",                        // multibyte UTF-8
	"\xff\xfe",                 // invalid UTF-8 bytes
	strings.Repeat("1", 8192),  // long bit/text run
	strings.Repeat("A.", 4096), // many segments
}

// pureTextDecoderParam returns the sole required parameter name of a
// pure offline text decoder (GroupHostTools + risk.Low, exactly one
// required param that is NOT "hex" and is declared in the schema), or
// "" when the Spec is not such a decoder. Mirrors isPureHexDecoder but
// for the string-input family.
func pureTextDecoderParam(s Spec) string {
	if len(s.Required) != 1 {
		return ""
	}
	req := s.Required[0]
	if req == "hex" {
		return ""
	}
	if s.Group != GroupHostTools || s.Risk != risk.Low {
		return ""
	}
	var parsed struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(s.Schema, &parsed); err != nil {
		return ""
	}
	if _, ok := parsed.Properties[req]; !ok {
		return ""
	}
	return req
}

// TestTextDecoders_MalformedInputNeverPanics drives every registered
// pure offline decoder whose sole required parameter is a non-hex
// string (sentence / packet / script / uuid / bits / message / token
// / line / input) with a battery of degenerate inputs and asserts
// none panics. Companion to the hex guard for the string-input family.
func TestTextDecoders_MalformedInputNeverPanics(t *testing.T) {
	tested := 0
	for _, s := range All() {
		param := pureTextDecoderParam(s)
		if s.Handler == nil || param == "" {
			continue
		}
		tested++
		for _, in := range malformedTextInputs {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s panicked on %s=%q: %v", s.Name, param, in, r)
					}
				}()
				_, _ = s.Handler(context.Background(), nil, map[string]any{param: in})
			}()
		}
	}
	if tested < 8 {
		t.Errorf("only %d text decoders exercised; expected 8+ — filter may have regressed", tested)
	}
	t.Logf("panic-safety swept %d text decoders", tested)
}
