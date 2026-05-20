package usbhid

import (
	"strings"
	"testing"
)

// TestDecodeHelloWorld pins reconstruction of "Hello" — five
// printable key-downs separated by key-release ("zero") reports.
//
// Sequence:
//   - Shift held + h pressed   → "H"
//   - all released
//   - e pressed                → "e"
//   - release
//   - l pressed                → "l"
//   - release
//   - l pressed                → "l"
//   - release
//   - o pressed                → "o"
//   - release
func TestDecodeHelloWorld(t *testing.T) {
	in := "02 00 0B 00 00 00 00 00 " + // LShift + h
		"00 00 00 00 00 00 00 00 " + // release
		"00 00 08 00 00 00 00 00 " + // e
		"00 00 00 00 00 00 00 00 " + // release
		"00 00 0F 00 00 00 00 00 " + // l
		"00 00 00 00 00 00 00 00 " + // release
		"00 00 0F 00 00 00 00 00 " + // l (must register as new
		// key-down after the release in between).
		"00 00 00 00 00 00 00 00 " + // release
		"00 00 12 00 00 00 00 00 " + // o
		"00 00 00 00 00 00 00 00" // release
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ReconstructedText != "Hello" {
		t.Errorf("reconstructedText: got %q want %q", r.ReconstructedText, "Hello")
	}
	if len(r.KeyDownEvents) != 5 {
		t.Errorf("keyDownEvents: got %d want 5", len(r.KeyDownEvents))
	}
}

// TestDecodeEnter pins a standalone Enter — the DuckyScript
// transcript should emit "ENTER" not the literal char.
func TestDecodeEnter(t *testing.T) {
	in := "00 00 28 00 00 00 00 00 " +
		"00 00 00 00 00 00 00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.DuckyScript, "ENTER") {
		t.Errorf("duckyscript missing ENTER: %q", r.DuckyScript)
	}
	if r.ReconstructedText != "" {
		t.Errorf("expected empty text (Enter is non-printable), got %q",
			r.ReconstructedText)
	}
}

// TestDecodeModifiedKey pins a Gui+r combo (Windows Run dialog
// keyboard shortcut, classic BadUSB opener).
func TestDecodeModifiedKey(t *testing.T) {
	// Modifier bitmap LGui (0x08) + key 'r' (0x15).
	in := "08 00 15 00 00 00 00 00 " +
		"00 00 00 00 00 00 00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.KeyDownEvents) != 1 {
		t.Fatalf("keyDownEvents: got %d want 1", len(r.KeyDownEvents))
	}
	e := r.KeyDownEvents[0]
	if e.Name != "r" {
		t.Errorf("key name: got %q want r", e.Name)
	}
	found := false
	for _, m := range e.Modifiers {
		if m == "Gui" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Gui modifier, got %v", e.Modifiers)
	}
	if !strings.Contains(r.DuckyScript, "GUI") {
		t.Errorf("duckyscript missing GUI: %q", r.DuckyScript)
	}
}

// TestDecodeNumberRowShifted pins Shift+number → punctuation.
func TestDecodeNumberRowShifted(t *testing.T) {
	// LShift + 1 (0x1E) → "!".
	in := "02 00 1E 00 00 00 00 00 " +
		"00 00 00 00 00 00 00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ReconstructedText != "!" {
		t.Errorf("reconstructedText: got %q want !", r.ReconstructedText)
	}
}

// TestDecodeCapsLockToggle pins Caps Lock state tracking.
func TestDecodeCapsLockToggle(t *testing.T) {
	// CapsLock press + release, then "a" (should render "A"),
	// then CapsLock press + release, then "a" (should render
	// "a").
	in := "00 00 39 00 00 00 00 00 " + // CapsLock down
		"00 00 00 00 00 00 00 00 " + // release
		"00 00 04 00 00 00 00 00 " + // 'a'
		"00 00 00 00 00 00 00 00 " +
		"00 00 39 00 00 00 00 00 " + // CapsLock down again
		"00 00 00 00 00 00 00 00 " + // release
		"00 00 04 00 00 00 00 00 " + // 'a'
		"00 00 00 00 00 00 00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ReconstructedText != "Aa" {
		t.Errorf("reconstructedText: got %q want Aa", r.ReconstructedText)
	}
}

// TestDecodeSpace pins the Space key rendering.
func TestDecodeSpace(t *testing.T) {
	in := "00 00 04 00 00 00 00 00 " + // 'a'
		"00 00 00 00 00 00 00 00 " +
		"00 00 2C 00 00 00 00 00 " + // Space
		"00 00 00 00 00 00 00 00 " +
		"00 00 05 00 00 00 00 00 " + // 'b'
		"00 00 00 00 00 00 00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ReconstructedText != "a b" {
		t.Errorf("reconstructedText: got %q want %q", r.ReconstructedText, "a b")
	}
}

// TestDecodeDuckyScriptStringFolding pins that consecutive
// printable characters fold into a single STRING directive.
func TestDecodeDuckyScriptStringFolding(t *testing.T) {
	in := "00 00 04 00 00 00 00 00 " + // 'a'
		"00 00 00 00 00 00 00 00 " +
		"00 00 05 00 00 00 00 00 " + // 'b'
		"00 00 00 00 00 00 00 00 " +
		"00 00 06 00 00 00 00 00 " + // 'c'
		"00 00 00 00 00 00 00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.DuckyScript != "STRING abc" {
		t.Errorf("duckyscript: got %q want %q", r.DuckyScript, "STRING abc")
	}
}

// TestKeyNameTable spot-checks alphabet + digits + functions +
// special keys.
func TestKeyNameTable(t *testing.T) {
	cases := map[int]string{
		0x04: "a", 0x1D: "z",
		0x1E: "1", 0x27: "0",
		0x28: "Enter", 0x29: "Escape", 0x2A: "Backspace",
		0x2B: "Tab", 0x2C: "Space",
		0x3A: "F1", 0x45: "F12",
		0x4F: "Right", 0x52: "Up",
	}
	for k, v := range cases {
		if got := keyName(k); got != v {
			t.Errorf("keyName(0x%02X) = %q want %q", k, got, v)
		}
	}
}

// TestRenderCharShiftPunctuation pins every shifted punctuation
// variant.
func TestRenderCharShiftPunctuation(t *testing.T) {
	cases := map[int]struct {
		base, shifted string
	}{
		0x2D: {"-", "_"},
		0x2E: {"=", "+"},
		0x2F: {"[", "{"},
		0x30: {"]", "}"},
		0x31: {"\\", "|"},
		0x33: {";", ":"},
		0x34: {"'", "\""},
		0x35: {"`", "~"},
		0x36: {",", "<"},
		0x37: {".", ">"},
		0x38: {"/", "?"},
	}
	for k, want := range cases {
		if got := renderChar(k, false, false); got != want.base {
			t.Errorf("renderChar(0x%02X, no-shift) = %q want %q", k, got, want.base)
		}
		if got := renderChar(k, true, false); got != want.shifted {
			t.Errorf("renderChar(0x%02X, shift) = %q want %q", k, got, want.shifted)
		}
	}
}

// TestDecodeModifierBitmap covers every modifier flag.
func TestDecodeModifierBitmap(t *testing.T) {
	want := map[byte][]string{
		0x01: {"LCtrl"},
		0x02: {"LShift"},
		0x04: {"LAlt"},
		0x08: {"LGui"},
		0x10: {"RCtrl"},
		0x20: {"RShift"},
		0x40: {"RAlt"},
		0x80: {"RGui"},
	}
	for k, v := range want {
		got := decodeModifiers(k)
		if len(got) != 1 || got[0] != v[0] {
			t.Errorf("decodeModifiers(0x%02X) = %v want %v", k, got, v)
		}
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

func TestDecodeRejectsNonReportMultiple(t *testing.T) {
	// 9 bytes — not a multiple of 8.
	if _, err := Decode("00 00 04 00 00 00 00 00 04"); err == nil {
		t.Fatal("want error when input is not a multiple of 8 bytes")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 7)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
