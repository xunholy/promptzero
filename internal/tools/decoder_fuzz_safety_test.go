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
