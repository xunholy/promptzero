// SPDX-License-Identifier: AGPL-3.0-or-later

package usbhid

import "testing"

func TestExtractUsbmonReports_KeyboardStream(t *testing.T) {
	// A small usbmon capture: submit lines (skipped), a control transfer
	// (skipped), an interrupt-OUT LED report (skipped), and three
	// Interrupt-IN keyboard callbacks: 'a' down, key up, 'b' down.
	capture := `ffff8801ab33e3c0 1369381455 S Ii:1:003:1 -115 8 <
ffff8800c0ffee00 1369381460 C Ci:1:003:0 0 18 = 12011001 00000008
ffff8801ab33e3c0 1369381512 C Ii:1:003:1 0 8 = 00000400 00000000
ffff8801deadbeef 1369381540 C Io:1:003:2 0 1 = 02
ffff8801ab33e3c0 1369381600 C Ii:1:003:1 0 8 = 00000000 00000000
ffff8801ab33e3c0 1369381700 C Ii:1:003:1 0 8 = 00000500 00000000`

	hexReports, count, err := ExtractUsbmonReports(capture)
	if err != nil {
		t.Fatalf("ExtractUsbmonReports: %v", err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3 (two key-down + one key-up callback)", count)
	}
	want := "000004000000000000000000000000000000050000000000"
	if hexReports != want {
		t.Errorf("hexReports = %q, want %q", hexReports, want)
	}

	// The extracted reports must feed Decode and reconstruct "ab".
	res, err := Decode(hexReports)
	if err != nil {
		t.Fatalf("Decode(extracted): %v", err)
	}
	if res.ReconstructedText != "ab" {
		t.Errorf("ReconstructedText = %q, want %q", res.ReconstructedText, "ab")
	}
}

func TestExtractUsbmonReports_NoKeyboardData(t *testing.T) {
	// Only a mouse (4-byte Interrupt-IN) and control traffic — no 8-byte
	// keyboard reports. Must error rather than silently return empty.
	capture := `ffff8801ab33e3c0 1369381512 C Ii:1:004:1 0 4 = 00010100
ffff8800c0ffee00 1369381460 C Ci:1:003:0 0 18 = 12011001 00000008`
	if _, _, err := ExtractUsbmonReports(capture); err == nil {
		t.Fatal("expected error for capture with no 8-byte keyboard reports, got nil")
	}
}

func TestExtractUsbmonReports_SkipsUncapturedData(t *testing.T) {
	// '<' marker means data was not captured; such lines must be skipped,
	// leaving only the one real report.
	capture := `ffff8801ab33e3c0 1369381455 C Ii:1:003:1 0 8 <
ffff8801ab33e3c0 1369381512 C Ii:1:003:1 0 8 = 00000400 00000000`
	hexReports, count, err := ExtractUsbmonReports(capture)
	if err != nil {
		t.Fatalf("ExtractUsbmonReports: %v", err)
	}
	if count != 1 || hexReports != "0000040000000000" {
		t.Errorf("got count=%d hex=%q, want count=1 hex=%q", count, hexReports, "0000040000000000")
	}
}
