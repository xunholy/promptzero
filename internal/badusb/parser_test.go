package badusb

import (
	"strings"
	"testing"
)

// TestParse_BasicScript pins a typical "open Run dialog, type
// notepad, hit enter" payload — covers the four most common
// commands.
func TestParse_BasicScript(t *testing.T) {
	src := `REM open Run dialog
DELAY 500
GUI r
DELAY 200
STRING notepad
ENTER
`
	got := Parse(src)
	if got.LineCount != 7 {
		t.Errorf("LineCount = %d; want 7 (6 content + trailing blank)",
			got.LineCount)
	}
	if got.IssueCount != 0 {
		t.Errorf("IssueCount = %d; want 0\nlines: %+v", got.IssueCount, got.Lines)
	}
	if got.CommandCount != 5 {
		t.Errorf("CommandCount = %d; want 5", got.CommandCount)
	}
	// Comment + trailing blank
	if got.CommentCount != 2 {
		t.Errorf("CommentCount = %d; want 2 (1 REM + 1 trailing blank)",
			got.CommentCount)
	}
	// Estimated time = 500 (DELAY) + 0 (GUI r) + 200 (DELAY) +
	// 7 (STRING "notepad" = 7 chars * 1ms) + 0 (ENTER) = 707 ms
	if got.EstimatedTotalMS != 707 {
		t.Errorf("EstimatedTotalMS = %d; want 707", got.EstimatedTotalMS)
	}
}

// TestParse_DefaultDelay confirms DEFAULTDELAY shifts the
// pacing for subsequent commands.
func TestParse_DefaultDelay(t *testing.T) {
	src := `DEFAULTDELAY 100
GUI r
STRING test
`
	got := Parse(src)
	if got.DefaultDelayMS != 100 {
		t.Errorf("DefaultDelayMS = %d; want 100", got.DefaultDelayMS)
	}
	// First DEFAULTDELAY line: 0 (DEFAULTDELAY itself doesn't add)
	// GUI r: 100 (default delay added — DEFAULTDELAY takes effect)
	// STRING test: 100 + 4 (typing) = 104
	// Total: 0 + 100 + 104 = 204
	if got.EstimatedTotalMS != 204 {
		t.Errorf("EstimatedTotalMS = %d; want 204", got.EstimatedTotalMS)
	}
}

// TestParse_UnknownCommandFlagged surfaces an Issue on
// unrecognised commands.
func TestParse_UnknownCommandFlagged(t *testing.T) {
	src := `DELAY 100
FROBNICATE
`
	got := Parse(src)
	if got.IssueCount != 1 {
		t.Fatalf("IssueCount = %d; want 1\n%+v", got.IssueCount, got.Lines)
	}
	// Find the FROBNICATE line.
	var found bool
	for _, l := range got.Lines {
		if l.Command == "FROBNICATE" {
			found = true
			if l.Kind != "invalid" {
				t.Errorf("FROBNICATE Kind = %q; want 'invalid'", l.Kind)
			}
			if !strings.Contains(l.Issue, "unknown") {
				t.Errorf("FROBNICATE Issue = %q", l.Issue)
			}
		}
	}
	if !found {
		t.Error("FROBNICATE line not found in parsed output")
	}
}

// TestParse_BadDelayArg surfaces an Issue when DELAY's argument
// isn't a non-negative integer.
func TestParse_BadDelayArg(t *testing.T) {
	src := `DELAY abc
DELAY -50
`
	got := Parse(src)
	if got.IssueCount != 2 {
		t.Errorf("IssueCount = %d; want 2", got.IssueCount)
	}
	for _, l := range got.Lines {
		if l.Command == "DELAY" && l.Args != "" {
			if !strings.Contains(l.Issue, "non-negative integer") {
				t.Errorf("DELAY %q Issue = %q", l.Args, l.Issue)
			}
		}
	}
}

// TestParse_EmptyStringFlagged — STRING with no argument is
// flagged as invalid (operator probably meant to write
// something).
func TestParse_EmptyStringFlagged(t *testing.T) {
	src := `STRING
`
	got := Parse(src)
	if got.IssueCount != 1 {
		t.Errorf("IssueCount = %d; want 1", got.IssueCount)
	}
	for _, l := range got.Lines {
		if l.Command == "STRING" {
			if !strings.Contains(l.Issue, "requires text") {
				t.Errorf("STRING Issue = %q", l.Issue)
			}
		}
	}
}

// TestParse_ModifierKeyCombo accepts both bare modifiers and
// modifier+key combos.
func TestParse_ModifierKeyCombo(t *testing.T) {
	src := `GUI
GUI r
CTRL c
ALT TAB
CTRL-ALT-DEL
`
	got := Parse(src)
	if got.IssueCount != 0 {
		t.Errorf("IssueCount = %d; want 0\nlines: %+v",
			got.IssueCount, got.Lines)
	}
	if got.CommandCount != 5 {
		t.Errorf("CommandCount = %d; want 5", got.CommandCount)
	}
}

// TestParse_BadModifierArg flags an argument to a modifier that
// isn't a recognised key.
func TestParse_BadModifierArg(t *testing.T) {
	src := `GUI BLERGH
`
	got := Parse(src)
	if got.IssueCount != 1 {
		t.Errorf("IssueCount = %d; want 1", got.IssueCount)
	}
}

// TestParse_FunctionKeysNoArgs — F1-F12 take no arguments.
func TestParse_FunctionKeysNoArgs(t *testing.T) {
	src := `F1
F12
`
	got := Parse(src)
	if got.IssueCount != 0 {
		t.Errorf("IssueCount = %d; want 0\n%+v", got.IssueCount, got.Lines)
	}
}

// TestParse_FunctionKeysRejectArgs — single-key commands flag
// stray arguments.
func TestParse_FunctionKeysRejectArgs(t *testing.T) {
	src := `ENTER foo
`
	got := Parse(src)
	if got.IssueCount != 1 {
		t.Errorf("IssueCount = %d; want 1", got.IssueCount)
	}
}

// TestParse_RepeatRequiresPositiveInt — REPEAT 0 / negative /
// non-numeric should all flag.
func TestParse_RepeatRequiresPositiveInt(t *testing.T) {
	src := `REPEAT 5
REPEAT 0
REPEAT abc
`
	got := Parse(src)
	if got.IssueCount != 2 {
		t.Errorf("IssueCount = %d; want 2 (0 and abc rejected, 5 ok)",
			got.IssueCount)
	}
}

// TestParse_REMCommentVariants — REM preserves the comment
// content, even when there's no space after REM. Trailing
// newline produces an additional blank line counted in
// CommentCount.
func TestParse_REMCommentVariants(t *testing.T) {
	src := `REM this is a comment
REM
`
	got := Parse(src)
	// 2 REMs + 1 trailing blank = 3 (blank lines counted as
	// comments in our taxonomy).
	if got.CommentCount != 3 {
		t.Errorf("CommentCount = %d; want 3", got.CommentCount)
	}
	for _, l := range got.Lines {
		if l.Number == 1 && l.Args != "this is a comment" {
			t.Errorf("REM Args = %q; want 'this is a comment'", l.Args)
		}
	}
}

// TestParse_BlankLinesIgnored — blank lines + lines with only
// whitespace are classified as "blank" and don't contribute to
// issues.
func TestParse_BlankLinesIgnored(t *testing.T) {
	src := `DELAY 100


DELAY 200
`
	got := Parse(src)
	if got.IssueCount != 0 {
		t.Errorf("IssueCount = %d; want 0", got.IssueCount)
	}
	if got.CommandCount != 2 {
		t.Errorf("CommandCount = %d; want 2", got.CommandCount)
	}
}

// TestParse_CaseInsensitiveCommands — DuckyScript commands are
// case-insensitive on the wire; the parser uppercases them.
func TestParse_CaseInsensitiveCommands(t *testing.T) {
	src := `delay 500
String hello
enter
`
	got := Parse(src)
	if got.IssueCount != 0 {
		t.Errorf("IssueCount = %d; want 0", got.IssueCount)
	}
	for _, l := range got.Lines {
		if l.Command != "DELAY" && l.Command != "STRING" && l.Command != "ENTER" &&
			l.Command != "" {
			t.Errorf("Command not uppercased: %q", l.Command)
		}
	}
}

// TestParse_CRLF — Windows line endings should still parse
// correctly (CR stripped).
func TestParse_CRLF(t *testing.T) {
	src := "DELAY 100\r\nSTRING hi\r\n"
	got := Parse(src)
	if got.IssueCount != 0 {
		t.Errorf("CRLF: IssueCount = %d; want 0\nlines: %+v",
			got.IssueCount, got.Lines)
	}
}

// TestParse_EmptyScript — empty input yields an empty result
// (no error, no commands).
func TestParse_EmptyScript(t *testing.T) {
	got := Parse("")
	if got.LineCount != 1 {
		// A single empty string still produces one blank "line".
		t.Errorf("LineCount = %d; want 1", got.LineCount)
	}
	if got.CommandCount != 0 {
		t.Errorf("CommandCount = %d; want 0", got.CommandCount)
	}
	if got.IssueCount != 0 {
		t.Errorf("IssueCount = %d; want 0", got.IssueCount)
	}
}

// TestParse_StringTypingEstimate confirms STRING contributes
// 1 ms per character to the total.
func TestParse_StringTypingEstimate(t *testing.T) {
	src := `STRING This is a 20-char str
`
	got := Parse(src)
	// "This is a 20-char str" = 21 chars. EstimatedMS = 21.
	if got.EstimatedTotalMS != 21 {
		t.Errorf("EstimatedTotalMS = %d; want 21", got.EstimatedTotalMS)
	}
}

// TestParse_StringWithLeadingWhitespacePreserved — operators
// sometimes want to type a leading space. The parser strips
// from the line head but preserves intra-arg whitespace.
func TestParse_StringWithIntraSpaces(t *testing.T) {
	src := `STRING hello world test
`
	got := Parse(src)
	if got.Lines[0].Args != "hello world test" {
		t.Errorf("Args = %q; want 'hello world test'", got.Lines[0].Args)
	}
}
