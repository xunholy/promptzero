// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import "testing"

// TestDecodeCVMList_HandVector: X=0, Y=0, then two rules — 4203 and 1F03.
//   - 0x42: bit 0x40 set (apply next if unsuccessful), method 0x02 (enciphered
//     PIN online); condition 0x03 (if terminal supports the CVM).
//   - 0x1F: bit 0x40 clear (fail if unsuccessful), method 0x1F (no CVM);
//     condition 0x03.
func TestDecodeCVMList_HandVector(t *testing.T) {
	c, err := DecodeCVMListHex("000000000000000042031F03")
	if err != nil {
		t.Fatal(err)
	}
	if c.AmountX != 0 || c.AmountY != 0 {
		t.Errorf("X/Y = %d/%d, want 0/0", c.AmountX, c.AmountY)
	}
	if len(c.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(c.Rules))
	}
	r0 := c.Rules[0]
	if r0.MethodCode != 0x02 || !r0.ApplyNextIfUnsuccessful {
		t.Errorf("rule0 method/applyNext = %02X/%v, want 02/true", r0.MethodCode, r0.ApplyNextIfUnsuccessful)
	}
	if r0.Method != "Enciphered PIN verified online" || r0.Condition != "If terminal supports the CVM" {
		t.Errorf("rule0 names = %q / %q", r0.Method, r0.Condition)
	}
	r1 := c.Rules[1]
	if r1.MethodCode != 0x1F || r1.ApplyNextIfUnsuccessful {
		t.Errorf("rule1 method/applyNext = %02X/%v, want 1F/false", r1.MethodCode, r1.ApplyNextIfUnsuccessful)
	}
	if r1.Method != "No CVM required" {
		t.Errorf("rule1 method = %q, want No CVM required", r1.Method)
	}
}

// TestDecodeCVMList_Amounts: non-zero X with an under-X condition.
func TestDecodeCVMList_Amounts(t *testing.T) {
	// X = 0x00000BB8 = 3000, Y = 0, rule 4406 (method 0x04, condition 0x06 = under X).
	c, err := DecodeCVMListHex("00000BB8000000004406")
	if err != nil {
		t.Fatal(err)
	}
	if c.AmountX != 3000 {
		t.Errorf("X = %d, want 3000", c.AmountX)
	}
	if c.Rules[0].MethodCode != 0x04 || c.Rules[0].Condition != "If transaction is in the application currency and is under X value" {
		t.Errorf("rule = %+v", c.Rules[0])
	}
}

// TestDecodeCVMList_UnknownCodes: RFU/proprietary method and condition codes
// are surfaced raw, not guessed.
func TestDecodeCVMList_UnknownCodes(t *testing.T) {
	// method 0x10 (not in table), condition 0x7F (not in table).
	c, err := DecodeCVMListHex("0000000000000000107F")
	if err != nil {
		t.Fatal(err)
	}
	r := c.Rules[0]
	if r.MethodCode != 0x10 {
		t.Fatalf("method code = %02X, want 10", r.MethodCode)
	}
	if r.Method == "" || r.Method[:3] != "RFU" {
		t.Errorf("unknown method should be flagged RFU, got %q", r.Method)
	}
	if r.Condition[:3] != "RFU" {
		t.Errorf("unknown condition should be flagged RFU, got %q", r.Condition)
	}
}

func TestDecodeCVMList_Errors(t *testing.T) {
	bad := []string{
		"",                       // empty
		"0000000000",             // < 8 bytes
		"0000000000000000420300", // odd trailing (5 bytes after amounts)
	}
	for i, s := range bad {
		if _, err := DecodeCVMListHex(s); err == nil {
			t.Errorf("case %d (%q): expected error", i, s)
		}
	}
}
