package workflows

import (
	"strings"
	"testing"
)

// Tests for the pure helpers feeding the garage-door workflow:
// parseSubGHzDecode, looksLikeEmptyCapture, subGHzAttackPath. The
// workflow branches on these — quiet drift would silently classify a
// rolling-code remote as fixed (suggesting an unworkable replay) or
// vice versa.

func TestParseSubGHzDecode_FixedProtocol(t *testing.T) {
	out := "Protocol: Princeton\nKey: 0F AA BB CC"
	got := parseSubGHzDecode(out)
	if got.Protocol != "Princeton" {
		t.Errorf("Protocol = %q; want Princeton", got.Protocol)
	}
	if got.KeyHex != "0F AA BB CC" {
		t.Errorf("KeyHex = %q", got.KeyHex)
	}
	if got.Rolling {
		t.Error("Princeton must NOT be classified as rolling")
	}
}

func TestParseSubGHzDecode_RollingProtocols(t *testing.T) {
	// One representative per known rolling protocol.
	rolling := []string{
		"Protocol: KeeLoq\nKey: 11 22 33 44",
		"Protocol: Somfy Telis\nKey: AA",
		"Protocol: Nice Flor-S\nKey: BB",
		"Protocol: Faac SLH\nKey: CC",
		"Protocol: BFT Mitto\nKey: DD",
		"Protocol: Hormann Bisecur\nKey: EE",
	}
	for _, out := range rolling {
		got := parseSubGHzDecode(out)
		if !got.Rolling {
			t.Errorf("expected Rolling=true for %q; got %+v", strings.Split(out, "\n")[0], got)
		}
	}
}

func TestParseSubGHzDecode_KeyHexUppercased(t *testing.T) {
	out := "Protocol: Princeton\nKey: 0f aa bb cc"
	got := parseSubGHzDecode(out)
	if got.KeyHex != "0F AA BB CC" {
		t.Errorf("KeyHex = %q; want uppercased", got.KeyHex)
	}
}

func TestParseSubGHzDecode_NoMatch(t *testing.T) {
	got := parseSubGHzDecode("random noise here")
	if got.Protocol != "" || got.KeyHex != "" || got.Rolling {
		t.Errorf("expected zero result; got %+v", got)
	}
}

func TestLooksLikeEmptyCapture(t *testing.T) {
	empty := []string{
		"",
		"   ",
		"No signal detected",
		"NO DATA",
		"Capture: nothing captured during sweep",
		"No packets received",
		"No raw data on the wire",
		"short",
	}
	for _, in := range empty {
		if !looksLikeEmptyCapture(in) {
			t.Errorf("looksLikeEmptyCapture(%q) = false; want true", in)
		}
	}

	nonEmpty := []string{
		// Long output — clearly a real capture.
		"Capture started\nProtocol: Princeton\nKey: 0F AA BB CC DD EE FF 00\nCapture stopped\n",
	}
	for _, in := range nonEmpty {
		if looksLikeEmptyCapture(in) {
			t.Errorf("looksLikeEmptyCapture(%q) = true; want false", in)
		}
	}
}

func TestSubGHzAttackPath_RollingProducesNoReplay(t *testing.T) {
	info := SubGHzDecodeInfo{Protocol: "KeeLoq", Rolling: true}
	got := subGHzAttackPath(info, "/ext/subghz/captured.sub")
	if !strings.Contains(got, "rolling code") {
		t.Errorf("rolling protocol path missing 'rolling code': %q", got)
	}
	if strings.Contains(got, "subghz_transmit") {
		t.Errorf("rolling protocol path should NOT suggest replay: %q", got)
	}
}

func TestSubGHzAttackPath_FixedSuggestsReplay(t *testing.T) {
	info := SubGHzDecodeInfo{Protocol: "Princeton", Rolling: false}
	got := subGHzAttackPath(info, "/ext/subghz/captured.sub")
	if !strings.Contains(got, "subghz_transmit") {
		t.Errorf("fixed protocol path missing replay suggestion: %q", got)
	}
	if !strings.Contains(got, "/ext/subghz/captured.sub") {
		t.Errorf("fixed protocol path missing file path: %q", got)
	}
}

func TestSubGHzAttackPath_UnknownProtocolSuggestsRawReplay(t *testing.T) {
	info := SubGHzDecodeInfo{Protocol: "", Rolling: false}
	got := subGHzAttackPath(info, "/ext/subghz/unknown.sub")
	if !strings.Contains(got, "unknown protocol") {
		t.Errorf("unknown protocol path missing 'unknown protocol': %q", got)
	}
	if !strings.Contains(got, "subghz_transmit") {
		t.Errorf("unknown protocol path should still suggest raw replay: %q", got)
	}
}
