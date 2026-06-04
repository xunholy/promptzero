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

func TestRejectsNonRep(t *testing.T) {
	// An AS-REQ ([APPLICATION 10]) is not a roastable response.
	if _, err := RoastLine("6a03020100"); err == nil {
		t.Error("want error for a non-AS-REP/TGS-REP message")
	}
	if _, err := RoastLine("notkerberos"); err == nil {
		t.Error("want error for non-Kerberos input")
	}
}
