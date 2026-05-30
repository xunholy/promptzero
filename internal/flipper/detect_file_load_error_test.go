package flipper

import "testing"

// TestDetectFileLoadError covers the firmware file-load banners across the
// file-taking commands (subghz tx_from_file / decode_raw, ir decode,
// rfid raw_analyze), all of which print the failure to stdout with no CLI
// error. Successful output (decoded fields, keystore/sending banners) must
// not trip a false positive.
func TestDetectFileLoadError(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		wantErr bool
	}{
		{"subghz tx error", `Load_keystore keeloq_mfcodes OK
subghz tx_from_file: Error open file /ext/subghz/x.sub`, true},
		{"ir decode error", `Failed to open file for reading: "/ext/infrared/x.ir"`, true},
		{"rfid analyze error", "Failed to open file", true},
		{"rfid emulate error", `File not found: "/ext/lfrfid/x.rfid"`, true},
		{"storage error", "Storage error: file/dir not exist", true},
		{"clean subghz tx", "Load_keystore keeloq_mfcodes OK\nSending...", false},
		{"clean ir decode", "Protocol: NEC\nAddress: 00\nCommand: 16", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := detectFileLoadError(c.out)
			if (err != nil) != c.wantErr {
				t.Errorf("detectFileLoadError(%q) err=%v; wantErr=%v", c.out, err, c.wantErr)
			}
		})
	}
}
