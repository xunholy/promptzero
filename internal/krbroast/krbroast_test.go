// SPDX-License-Identifier: AGPL-3.0-or-later

package krbroast

import "testing"

// Hand-built, spec-conformant DERs with known enc-parts (the EncryptedData
// parse is the one verified against an impacket Ticket); the line format is the
// canonical hashcat 18200 / 13100.
const (
	// AS-REP for svc_user@CORP.LOCAL, [6] enc-part etype 23,
	// cipher = aabb…8899 (checksum) ‖ 0a0b…1314 (edata).
	asrepHex  = "6b81ba3081b7a003020105a10302010ba30c1b0a434f52502e4c4f43414ca4153013a003020101a10c300a1b087376635f75736572a55e615c305aa003020105a10c1b0a434f52502e4c4f43414ca221301fa003020103a11830161b04485454501b0e7765622e636f72702e6c6f63616ca3223020a003020117a103020102a214041201020304656e637279707465642d626c6f62a6263024a003020117a21d041baabbccddeeff001122334455667788990a0b0c0d0e0f1011121314"
	wantASREP = "$krb5asrep$23$svc_user@CORP.LOCAL:aabbccddeeff00112233445566778899$0a0b0c0d0e0f1011121314"

	// TGS-REP whose service ticket (MSSQLSvc/db.corp.local) enc-part is
	// etype 23, cipher = 1122…5566 (checksum) ‖ 778899aabbccddee (edata).
	tgsrepHex = "6d81aa3081a7a003020105a10302010da30c1b0a434f52502e4c4f43414ca4153013a003020101a10c300a1b087376635f75736572a5626160305ea003020105a10c1b0a434f52502e4c4f43414ca2243022a003020102a11b30191b084d5353514c5376631b0d64622e636f72702e6c6f63616ca3233021a003020117a21a041811223344556677889900112233445566778899aabbccddeea6123010a003020112a209040773657373696f6e"
	wantTGS   = "$krb5tgs$23$*svc_user$CORP.LOCAL$MSSQLSvc/db.corp.local*$11223344556677889900112233445566$778899aabbccddee"
)

func TestASREPRoast(t *testing.T) {
	r, err := RoastLine(asrepHex)
	if err != nil {
		t.Fatalf("RoastLine: %v", err)
	}
	if r.Attack != "AS-REP roast" || r.HashcatMode != 18200 {
		t.Errorf("attack/mode = %q / %d", r.Attack, r.HashcatMode)
	}
	if r.Line != wantASREP {
		t.Errorf("line mismatch:\n got  %q\n want %q", r.Line, wantASREP)
	}
}

func TestKerberoast(t *testing.T) {
	r, err := RoastLine(tgsrepHex)
	if err != nil {
		t.Fatalf("RoastLine: %v", err)
	}
	if r.Attack != "Kerberoast" || r.HashcatMode != 13100 {
		t.Errorf("attack/mode = %q / %d", r.Attack, r.HashcatMode)
	}
	if r.SPN != "MSSQLSvc/db.corp.local" {
		t.Errorf("spn = %q", r.SPN)
	}
	if r.Line != wantTGS {
		t.Errorf("line mismatch:\n got  %q\n want %q", r.Line, wantTGS)
	}
}

// AES vectors (etype 18 TGS / etype 17 AS-REP) with the checksum as the LAST
// 12 bytes, anchored to impacket's GetUserSPNs / GetNPUsers AES format.
const (
	tgsAESHex  = "6d81af3081aca003020105a10302010da30c1b0a434f52502e4c4f43414ca410300ea003020101a10730051b03737663a56f616d306ba003020105a10c1b0a434f52502e4c4f43414ca2293027a003020102a120301e1b084d5353514c5376631b1264622e636f72702e6c6f63616c3a31343333a32b3029a003020112a222042000112233445566778899aabbccddeeff00112233a1a2a3a4a5a6a7a8a9aaabaca60f300da003020112a206040473657373"
	wantTGSAES = "$krb5tgs$18$svc$CORP.LOCAL$*MSSQLSvc/db.corp.local~1433*$a1a2a3a4a5a6a7a8a9aaabac$00112233445566778899aabbccddeeff00112233"

	asrepAESHex  = "6b81c83081c5a003020105a10302010ba30c1b0a434f52502e4c4f43414ca4133011a003020101a10a30081b066e7075736572a56f616d306ba003020105a10c1b0a434f52502e4c4f43414ca2293027a003020102a120301e1b084d5353514c5376631b1264622e636f72702e6c6f63616c3a31343333a32b3029a003020112a222042000112233445566778899aabbccddeeff00112233a1a2a3a4a5a6a7a8a9aaabaca6253023a003020111a21c041aaabbccddeeff0011223344556677b1b2b3b4b5b6b7b8b9babbbc"
	wantASREPAES = "$krb5asrep$17$npuser$CORP.LOCAL$b1b2b3b4b5b6b7b8b9babbbc$aabbccddeeff0011223344556677"
)

// TestKerberoastAES anchors the AES (etype 18) Kerberoast line: checksum is the
// last 12 bytes, SPN ':'→'~', hashcat -m 19700.
func TestKerberoastAES(t *testing.T) {
	r, err := RoastLine(tgsAESHex)
	if err != nil {
		t.Fatalf("RoastLine: %v", err)
	}
	if r.HashcatMode != 19700 {
		t.Errorf("mode = %d, want 19700 (AES256)", r.HashcatMode)
	}
	if r.SPN != "MSSQLSvc/db.corp.local~1433" {
		t.Errorf("spn = %q (expected ':'→'~')", r.SPN)
	}
	if r.Line != wantTGSAES {
		t.Errorf("line mismatch:\n got  %q\n want %q", r.Line, wantTGSAES)
	}
}

// TestASREPRoastAES anchors the AES (etype 17) AS-REP line (checksum last 12).
func TestASREPRoastAES(t *testing.T) {
	r, err := RoastLine(asrepAESHex)
	if err != nil {
		t.Fatalf("RoastLine: %v", err)
	}
	if r.Line != wantASREPAES {
		t.Errorf("line mismatch:\n got  %q\n want %q", r.Line, wantASREPAES)
	}
	// No standard hashcat mode for AES AS-REP roast.
	if r.HashcatMode != 0 {
		t.Errorf("AES AS-REP should not claim a hashcat mode, got %d", r.HashcatMode)
	}
}

func TestRejectsNonRep(t *testing.T) {
	// An AS-REQ ([APPLICATION 10]) is not a roastable response.
	if _, err := RoastLine("6a03020100"); err == nil {
		t.Error("want error for a non-AS-REP/TGS-REP message")
	}
	if _, err := RoastLine("notkerberos"); err == nil {
		t.Error("want error for non-Kerberos input")
	}
}
