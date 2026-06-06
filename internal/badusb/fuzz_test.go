// SPDX-License-Identifier: AGPL-3.0-or-later

package badusb

import "testing"

// FuzzParse asserts the DuckyScript parser never panics on any input —
// it consumes attacker / operator-controlled payload text. Completes the
// repo-wide no-panic fuzz coverage of the decoder/parser packages.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"REM a comment\nDELAY 500\nGUI r\nSTRING cmd.exe\nENTER",
		"STRINGLN hello world",
		"DEFAULTDELAY 200\nGUI r\nDELAY 100\nSTRING notepad\nENTER",
		"DELAY 100\nREPEAT 5",
		"REPEAT 3",           // REPEAT with nothing to repeat
		"DELAY\nSTRING",      // missing args
		"REPEAT 99999999999", // huge repeat count
		"DELAY -1\nGUI",
		"\r\n\r\n",
		"NOTACOMMAND foo bar",
		"",
		"REM",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _ = Parse(s) })
}
