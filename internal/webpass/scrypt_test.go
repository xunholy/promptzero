// SPDX-License-Identifier: AGPL-3.0-or-later

package webpass

import "testing"

// Reference hash from the Werkzeug library (the oracle): scrypt, default params,
// password "password".
const werkzeugScrypt = "scrypt:32768:8:1$pqUT1Bmj$f9f4c54fcdbf5dae6446bdfea07c11fb92f593472d94ec7571c18160d6774778d252252f06cadd70a365f14981a8e5901c58bb8822076f2cabf6c03812c02933"

func TestVerify_WerkzeugScrypt(t *testing.T) {
	if ok, err := Verify(werkzeugScrypt, "password"); err != nil || !ok {
		t.Errorf("werkzeug scrypt verify: ok=%v err=%v", ok, err)
	}
	if ok, _ := Verify(werkzeugScrypt, "wrong"); ok {
		t.Error("wrong password must not verify (scrypt)")
	}
	if Scheme(werkzeugScrypt) != "werkzeug" {
		t.Errorf("scrypt scheme = %q, want werkzeug", Scheme(werkzeugScrypt))
	}
}

func TestComputeScryptRoundTrip(t *testing.T) {
	h, err := ComputeScrypt(16384, 8, 1, "saltsalt", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := Verify(h, "hunter2"); err != nil || !ok {
		t.Errorf("scrypt round-trip verify failed: %v", err)
	}
	if ok, _ := Verify(h, "nope"); ok {
		t.Error("wrong password verified (scrypt round-trip)")
	}
}

func TestVerify_ScryptErrors(t *testing.T) {
	for _, bad := range []string{
		"scrypt:32768:8:1", "scrypt:x:8:1$s$aa", "scrypt:32768:8:1$s$zz",
		"scrypt:99999999:8:1$s$aabb", // memory cap
	} {
		if _, err := Verify(bad, "x"); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}
