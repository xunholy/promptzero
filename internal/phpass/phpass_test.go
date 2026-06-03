// SPDX-License-Identifier: AGPL-3.0-or-later

package phpass

import "testing"

// Reference hash from passlib (the oracle): phpass, salt "abcdefgh", rounds=11
// ('9'), password "password".
const refHash = "$P$9abcdefghreUCnbbQX76dJT2aHvsT6."

func TestVerify(t *testing.T) {
	if ok, err := Verify(refHash, "password"); err != nil || !ok {
		t.Errorf("reference hash should verify: ok=%v err=%v", ok, err)
	}
	if ok, _ := Verify(refHash, "wrong"); ok {
		t.Error("wrong password must not verify")
	}
}

// TestComputeMatchesOracle confirms Compute reproduces the passlib hash exactly.
func TestComputeMatchesOracle(t *testing.T) {
	// '9' is itoa64 index 11.
	got, err := Compute("$P$", 11, "abcdefgh", "password")
	if err != nil {
		t.Fatal(err)
	}
	if got != refHash {
		t.Errorf("Compute = %s, want %s", got, refHash)
	}
}

func TestComputeRoundTrip(t *testing.T) {
	for _, magic := range []string{"$P$", "$H$"} {
		h, err := Compute(magic, 8, "saltsalt", "hunter2")
		if err != nil {
			t.Fatalf("%s compute: %v", magic, err)
		}
		if ok, err := Verify(h, "hunter2"); err != nil || !ok {
			t.Errorf("%s round-trip verify failed: %v", magic, err)
		}
		if ok, _ := Verify(h, "nope"); ok {
			t.Errorf("%s wrong password verified", magic)
		}
	}
}

func TestVerify_Errors(t *testing.T) {
	for _, bad := range []string{
		"", "$P$", "$1$tooshort", "$X$9abcdefghAAAAAAAAAAAAAAAAAAAAAA",
		"$P$" + string(itoa64[30]) + "abcdefghAAAAAAAAAAAAAAAAAAAAAA", // 2^30 over cap
	} {
		if _, err := Verify(bad, "x"); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}
