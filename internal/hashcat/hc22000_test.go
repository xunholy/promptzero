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

// TestEAPOL_CanonicalVector anchors the type-02 builder against hashcat's own
// published mode-22000 EAPOL example (ESSID hex decodes to "TP-LINK_HASHCAT_TEST").
func TestEAPOL_CanonicalVector(t *testing.T) {
	const eapol = "0103007502010a0000000000000000000148ce2ccba9c1fda130ff2fbbfb4fd3b063d1a93920b0f7df54a5cbf787b16171000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac028000"
	got, err := EAPOL(
		"024022795224bffca545276c3762686f",
		"6466b38ec3fc",
		"225edc49b7aa",
		[]byte("TP-LINK_HASHCAT_TEST"),
		"10e3be3b005a629e89de088d6a2fdc489db83ad4764f2d186b9cde15446e972e",
		eapol,
		"a2",
	)
	if err != nil {
		t.Fatalf("EAPOL: %v", err)
	}
	want := "WPA*02*024022795224bffca545276c3762686f*6466b38ec3fc*225edc49b7aa*" +
		"54502d4c494e4b5f484153484341545f54455354*" +
		"10e3be3b005a629e89de088d6a2fdc489db83ad4764f2d186b9cde15446e972e*" + eapol + "*a2"
	if got != want {
		t.Errorf("EAPOL line =\n %s\nwant\n %s", got, want)
	}
}

// TestEAPOL_NormalisesInput confirms separators / case / 0x on hex fields are tolerated.
func TestEAPOL_NormalisesInput(t *testing.T) {
	const eapol = "0103007502010a00"
	a, err := EAPOL("024022795224BFFCA545276C3762686F", "64:66:b3:8e:c3:fc", "0x225edc49b7aa",
		[]byte("net"), "10E3BE3B005A629E89DE088D6A2FDC489DB83AD4764F2D186B9CDE15446E972E", "0x"+eapol, "A2")
	if err != nil {
		t.Fatalf("EAPOL: %v", err)
	}
	b, err := EAPOL("024022795224bffca545276c3762686f", "6466b38ec3fc", "225edc49b7aa",
		[]byte("net"), "10e3be3b005a629e89de088d6a2fdc489db83ad4764f2d186b9cde15446e972e", eapol, "a2")
	if err != nil {
		t.Fatalf("EAPOL: %v", err)
	}
	if a != b {
		t.Errorf("input normalisation diverged:\n %s\n %s", a, b)
	}
}

func TestEAPOL_Errors(t *testing.T) {
	const (
		mic    = "024022795224bffca545276c3762686f"
		ap     = "6466b38ec3fc"
		sta    = "225edc49b7aa"
		anonce = "10e3be3b005a629e89de088d6a2fdc489db83ad4764f2d186b9cde15446e972e"
		eapol  = "0103007502010a00"
		mp     = "a2"
	)
	cases := []struct {
		name                            string
		mic, ap, sta, anonce, eapol, mp string
		essid                           []byte
	}{
		{"short mic", "024022", ap, sta, anonce, eapol, mp, []byte("n")},
		{"short anonce", mic, ap, sta, "10e3be", eapol, mp, []byte("n")},
		{"bad mp len", mic, ap, sta, anonce, eapol, "a2a2", []byte("n")},
		{"empty eapol", mic, ap, sta, anonce, "", mp, []byte("n")},
		{"empty essid", mic, ap, sta, anonce, eapol, mp, nil},
		{"oversize essid", mic, ap, sta, anonce, eapol, mp, make([]byte, 33)},
	}
	for _, c := range cases {
		if _, err := EAPOL(c.mic, c.ap, c.sta, c.essid, c.anonce, c.eapol, c.mp); err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}
