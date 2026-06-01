// SPDX-License-Identifier: AGPL-3.0-or-later

package hashcat

import "testing"

// TestPMKID_CanonicalVector anchors the builder against hashcat's own
// published mode-22000 example hash. The ESSID field there is the ASCII
// "hashcat-essid" (hex 686173686361742d6573736964), a strong check that the
// canonical line is reproduced byte-for-byte.
func TestPMKID_CanonicalVector(t *testing.T) {
	got, err := PMKID(
		"4d4fe7aac3a2cecab195321ceb99a7d0",
		"fc690c158264",
		"f4747f87f9f4",
		[]byte("hashcat-essid"),
	)
	if err != nil {
		t.Fatalf("PMKID: %v", err)
	}
	want := "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***"
	if got != want {
		t.Errorf("PMKID line =\n %s\nwant\n %s", got, want)
	}
}

// TestPMKID_NormalisesInput confirms separators / case / 0x prefixes on the
// hex fields are tolerated and the output is lower-cased.
func TestPMKID_NormalisesInput(t *testing.T) {
	a, err := PMKID("4D4FE7AAC3A2CECAB195321CEB99A7D0", "FC:69:0C:15:82:64", "0xf4747f87f9f4", []byte("net"))
	if err != nil {
		t.Fatalf("PMKID: %v", err)
	}
	b, err := PMKID("4d4fe7aac3a2cecab195321ceb99a7d0", "fc690c158264", "f4747f87f9f4", []byte("net"))
	if err != nil {
		t.Fatalf("PMKID: %v", err)
	}
	if a != b {
		t.Errorf("input normalisation diverged:\n %s\n %s", a, b)
	}
}

// TestPMKID_ESSIDHexEncoding checks the ESSID is hex-encoded, not passed raw.
func TestPMKID_ESSIDHexEncoding(t *testing.T) {
	got, err := PMKID("4d4fe7aac3a2cecab195321ceb99a7d0", "fc690c158264", "f4747f87f9f4", []byte("AB"))
	if err != nil {
		t.Fatalf("PMKID: %v", err)
	}
	// "AB" -> 4142, and the three trailing empty fields -> ***.
	want := "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*4142***"
	if got != want {
		t.Errorf("PMKID line = %s, want %s", got, want)
	}
}

func TestPMKID_Errors(t *testing.T) {
	good := "4d4fe7aac3a2cecab195321ceb99a7d0"
	cases := []struct {
		name           string
		pmkid, ap, sta string
		essid          []byte
	}{
		{"short pmkid", "4d4fe7aa", "fc690c158264", "f4747f87f9f4", []byte("n")},
		{"bad pmkid hex", "zz4fe7aac3a2cecab195321ceb99a7d0", "fc690c158264", "f4747f87f9f4", []byte("n")},
		{"short ap", good, "fc690c", "f4747f87f9f4", []byte("n")},
		{"short sta", good, "fc690c158264", "f474", []byte("n")},
		{"empty essid", good, "fc690c158264", "f4747f87f9f4", nil},
		{"oversize essid", good, "fc690c158264", "f4747f87f9f4", make([]byte, 33)},
	}
	for _, c := range cases {
		if _, err := PMKID(c.pmkid, c.ap, c.sta, c.essid); err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}
