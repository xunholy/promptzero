// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import "testing"

func TestDecodeCVMResults_Vectors(t *testing.T) {
	// 0x1F 0x00 0x02: "No CVM required" (0x1F), condition "Always" (0x00),
	// result "Successful" (0x02).
	r, err := DecodeCVMResultsHex("1F0002")
	if err != nil {
		t.Fatal(err)
	}
	if r.CVMCode != 0x1F || r.CVMPerformed != "No CVM required" {
		t.Errorf("performed = %d/%q", r.CVMCode, r.CVMPerformed)
	}
	if r.CVMCondition != "Always" {
		t.Errorf("condition = %q", r.CVMCondition)
	}
	if r.Result != "Successful" {
		t.Errorf("result = %q, want Successful", r.Result)
	}
	if r.ApplyNextIfUnsuccessful {
		t.Errorf("0x1F has bit 0x40 clear; ApplyNext should be false")
	}

	// 0x42 0x03 0x01: online PIN (0x02) with the apply-next bit (0x40) set,
	// condition "If terminal supports the CVM" (0x03), result "Failed".
	r2, err := DecodeCVMResultsHex("420301")
	if err != nil {
		t.Fatal(err)
	}
	if r2.CVMCode != 0x02 || !r2.ApplyNextIfUnsuccessful {
		t.Errorf("0x42: code=%d applyNext=%v, want 2/true", r2.CVMCode, r2.ApplyNextIfUnsuccessful)
	}
	if r2.CVMPerformed != "Enciphered PIN verified online" {
		t.Errorf("0x42 method = %q", r2.CVMPerformed)
	}
	if r2.Result != "Failed" {
		t.Errorf("result = %q, want Failed", r2.Result)
	}
}

func TestDecodeCVMResults_RFU(t *testing.T) {
	// Unknown method/condition/result codes are flagged RFU, never guessed.
	r, err := DecodeCVMResultsHex("3FFFFF")
	if err != nil {
		t.Fatal(err)
	}
	if r.CVMPerformed == "" || r.CVMCondition == "" || r.Result == "" {
		t.Errorf("RFU fields should be labelled, got %+v", r)
	}
	if r.Result != "RFU (0xFF)" {
		t.Errorf("result = %q, want RFU (0xFF)", r.Result)
	}
}

func TestDecodeCVMResults_Rejects(t *testing.T) {
	for _, bad := range []string{"", "9F34", "1F00", "1F000201", "zz"} {
		if _, err := DecodeCVMResultsHex(bad); err == nil {
			t.Errorf("DecodeCVMResultsHex(%q): expected error, got nil", bad)
		}
	}
}
