// Package badusb parses DuckyScript / BadUSB payload scripts
// into structured line-by-line views — command + arguments +
// validation status. Pure offline parser; no transport, no
// hardware.
//
// Wrap-vs-native judgement: DuckyScript v1 is a public language
// (Hak5's USB Rubber Ducky reference, mirrored by Flipper Zero
// BadUSB and the broader BadUSB ecosystem). The parser is a
// line-based lexer + command-dispatch table. Wrapping a FAP for
// this would require an SD-card install + a firmware-fork
// dependency for a pure parser. We implement natively so
// operators get a pre-deployment syntax check that surfaces:
//   - Unknown commands
//   - Invalid argument types (e.g. DELAY needs a positive int)
//   - Total estimated execution time
//   - Line-numbered diagnostics
//
// Pairs with the existing internal/validator/badusb.go (which
// does severity-pattern scanning for malicious payloads) —
// together they cover the syntactic + semantic validation
// surface.
//
// What this package covers:
//   - Line tokenisation: command (first whitespace-delimited
//     word) + arguments (the rest, preserved as a single string
//     for STRING / STRINGLN; split for key-combo commands)
//   - Command catalog: ~50 documented DuckyScript v1 commands
//     (DELAY / STRING / GUI / CTRL / ALT / SHIFT / ENTER / TAB
//     / ESC / function keys / navigation / locks / modifiers /
//     REPEAT / REM / DEFAULTDELAY)
//   - Per-command argument validation (DELAY → positive int,
//     STRING → free text, key combos → single key, etc.)
//   - Comment + blank line handling
//   - Estimated execution time calculation (DELAY + DEFAULTDELAY
//     between commands + per-keystroke STRING typing time)
//
// What this package does NOT cover (deliberately out of scope):
//   - DuckyScript v3 (Hak5's extended dialect: variables,
//     conditionals, loops, language layouts) — separate parser
//     when callers materialise
//   - Severity-pattern scanning (powershell -enc, rm -rf, etc.)
//     — covered by internal/validator/badusb.go
//   - Script execution (operators bring the Flipper transport)
package badusb

import (
	"fmt"
	"strconv"
	"strings"
)

// Line is one parsed DuckyScript line.
type Line struct {
	// Number is the 1-based line number in the source.
	Number int `json:"number"`
	// Source is the original line content, leading/trailing
	// whitespace stripped.
	Source string `json:"source"`
	// Kind is "blank", "comment", "command", or "invalid".
	Kind string `json:"kind"`
	// Command is the uppercase command name (empty for blank /
	// comment lines).
	Command string `json:"command,omitempty"`
	// Args is the raw argument string after the command word.
	// For STRING / STRINGLN / REM this preserves the full
	// remaining text; for key-combo commands it's the additional
	// key name(s).
	Args string `json:"args,omitempty"`
	// Issue is non-empty when the line failed validation
	// (unknown command, invalid argument format).
	Issue string `json:"issue,omitempty"`
	// EstimatedMS is the per-line execution-time estimate added
	// to the total. 0 for blank / comment / pure-modifier lines.
	EstimatedMS int `json:"estimated_ms"`
}

// Script is the top-level parsed result.
type Script struct {
	// Lines is the ordered list of parsed lines.
	Lines []Line `json:"lines"`
	// LineCount is len(Lines).
	LineCount int `json:"line_count"`
	// CommandCount counts non-blank non-comment lines.
	CommandCount int `json:"command_count"`
	// CommentCount counts REM / blank lines.
	CommentCount int `json:"comment_count"`
	// IssueCount counts lines with validation issues.
	IssueCount int `json:"issue_count"`
	// EstimatedTotalMS is the sum of per-line estimates.
	EstimatedTotalMS int `json:"estimated_total_ms"`
	// DefaultDelayMS reflects the script's effective
	// DEFAULTDELAY value (default 0; updated when the script
	// sets it).
	DefaultDelayMS int `json:"default_delay_ms"`
}

// Parse parses a DuckyScript source string into a Script. The
// input is split on '\n'; '\r' is stripped. The parser is
// tolerant of leading/trailing whitespace on each line and of
// mixed-case command names.
func Parse(source string) Script {
	// Per-keystroke typing time we use to estimate STRING
	// execution. Real-world Flipper / Rubber Ducky firmwares
	// type at ~1000 chars/sec on Windows targets (no per-key
	// delay configured); 1 ms/char is a good operator estimate.
	const stringMSPerChar = 1
	out := Script{}
	defaultDelay := 0
	for i, raw := range strings.Split(source, "\n") {
		raw = strings.TrimRight(raw, "\r")
		line := Line{
			Number: i + 1,
			Source: strings.TrimSpace(raw),
		}
		switch {
		case line.Source == "":
			line.Kind = "blank"
			out.CommentCount++
		case strings.HasPrefix(line.Source, "REM"):
			line.Kind = "comment"
			if len(line.Source) > 3 {
				line.Command = "REM"
				line.Args = strings.TrimSpace(line.Source[3:])
			} else {
				line.Command = "REM"
			}
			out.CommentCount++
		default:
			line.Kind = "command"
			parts := strings.SplitN(line.Source, " ", 2)
			line.Command = strings.ToUpper(parts[0])
			if len(parts) > 1 {
				line.Args = strings.TrimSpace(parts[1])
			}
			ms, err := validateCommand(line.Command, line.Args)
			if err != nil {
				line.Issue = err.Error()
				line.Kind = "invalid"
				out.IssueCount++
			} else {
				// Add the default-delay between commands (set by
				// a previous DEFAULTDELAY / DEFAULT_DELAY) so the
				// estimate reflects script-wide pacing.
				ms += defaultDelay
			}
			// Special handling: STRING typing time is per-char.
			if line.Command == "STRING" || line.Command == "STRINGLN" {
				ms += stringMSPerChar * len(line.Args)
			}
			// Special handling: DEFAULTDELAY updates pacing for
			// subsequent commands.
			if line.Command == "DEFAULTDELAY" || line.Command == "DEFAULT_DELAY" {
				if v, perr := strconv.Atoi(line.Args); perr == nil && v >= 0 {
					defaultDelay = v
				}
			}
			line.EstimatedMS = ms
			out.CommandCount++
			out.EstimatedTotalMS += ms
		}
		out.Lines = append(out.Lines, line)
	}
	out.LineCount = len(out.Lines)
	out.DefaultDelayMS = defaultDelay
	return out
}

// validateCommand checks the command+args pair against the
// DuckyScript v1 catalog and returns the per-line execution
// estimate (in milliseconds) plus an error when the args don't
// match the expected shape.
//
// Returns 0 ms for commands whose execution time isn't directly
// per-line (modifiers, locks, function keys — they're a single
// USB-HID report, fast enough to round to 0 within the operator's
// estimate budget).
func validateCommand(cmd, args string) (int, error) {
	switch cmd {
	case "DELAY":
		v, err := strconv.Atoi(args)
		if err != nil || v < 0 {
			return 0, fmt.Errorf("DELAY requires a non-negative integer in milliseconds")
		}
		return v, nil
	case "DEFAULTDELAY", "DEFAULT_DELAY":
		v, err := strconv.Atoi(args)
		if err != nil || v < 0 {
			return 0, fmt.Errorf("DEFAULTDELAY requires a non-negative integer in milliseconds")
		}
		return 0, nil
	case "STRING", "STRINGLN":
		if args == "" {
			return 0, fmt.Errorf("%s requires text to type", cmd)
		}
		return 0, nil
	case "REPEAT":
		v, err := strconv.Atoi(args)
		if err != nil || v < 1 {
			return 0, fmt.Errorf("REPEAT requires a positive integer")
		}
		return 0, nil
	}
	if _, ok := singleKeys[cmd]; ok {
		if args != "" {
			return 0, fmt.Errorf("%s does not take arguments", cmd)
		}
		return 0, nil
	}
	if _, ok := modifierKeys[cmd]; ok {
		// Modifier-only line is legal (e.g. "GUI" alone), or it
		// can have a single key argument ("GUI r" = Win+R).
		if args != "" {
			// Args should be a single key — either a single
			// printable char or a named key.
			if len(args) > 1 {
				_, isNamed := singleKeys[strings.ToUpper(args)]
				_, isModifier := modifierKeys[strings.ToUpper(args)]
				if !isNamed && !isModifier {
					return 0, fmt.Errorf("%s argument %q is not a recognised single key or modifier", cmd, args)
				}
			}
		}
		return 0, nil
	}
	return 0, fmt.Errorf("unknown command %q", cmd)
}

// singleKeys is the catalog of DuckyScript commands that
// represent a single keystroke and take no arguments. Values are
// the canonical name; lookup is case-insensitive (callers
// uppercase before lookup).
var singleKeys = map[string]struct{}{
	"ENTER":       {},
	"TAB":         {},
	"ESC":         {},
	"ESCAPE":      {},
	"SPACE":       {},
	"BACKSPACE":   {},
	"DELETE":      {},
	"INSERT":      {},
	"HOME":        {},
	"END":         {},
	"PAGEUP":      {},
	"PAGEDOWN":    {},
	"UP":          {},
	"UPARROW":     {},
	"DOWN":        {},
	"DOWNARROW":   {},
	"LEFT":        {},
	"LEFTARROW":   {},
	"RIGHT":       {},
	"RIGHTARROW":  {},
	"CAPSLOCK":    {},
	"NUMLOCK":     {},
	"SCROLLLOCK":  {},
	"PRINTSCREEN": {},
	"PAUSE":       {},
	"BREAK":       {},
	"MENU":        {},
	"APP":         {},
	"F1":          {}, "F2": {}, "F3": {}, "F4": {},
	"F5": {}, "F6": {}, "F7": {}, "F8": {},
	"F9": {}, "F10": {}, "F11": {}, "F12": {},
}

// modifierKeys is the catalog of DuckyScript modifier commands
// — they can stand alone (issue the modifier briefly) or take a
// single-key argument for a combo. Lookup is case-insensitive.
var modifierKeys = map[string]struct{}{
	"GUI":     {}, // Win / Cmd
	"WINDOWS": {}, // alias for GUI
	"META":    {}, // alias for GUI
	"CTRL":    {},
	"CONTROL": {}, // alias for CTRL
	"ALT":     {},
	"SHIFT":   {},
	"COMMAND": {}, // Mac alias for GUI
	"OPTION":  {}, // Mac alias for ALT
	// Compound modifiers (Hak5 syntax — single command, multiple
	// modifier prefixes joined by '-'):
	"GUI-CTRL":        {},
	"GUI-ALT":         {},
	"GUI-SHIFT":       {},
	"CTRL-ALT":        {},
	"CTRL-SHIFT":      {},
	"ALT-SHIFT":       {},
	"CTRL-ALT-DEL":    {},
	"CTRL-ALT-DELETE": {},
}
