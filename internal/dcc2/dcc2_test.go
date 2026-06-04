// SPDX-License-Identifier: AGPL-3.0-or-later

package dcc2

import "testing"

// TestComputeHashcatVector pins the canonical hashcat mode-2100 example
// ($DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f, password "hashcat") — the
// independent anchor.
func TestComputeHashcatVector(t *testing.T) {
	got, err := Compute("tom", "hashcat", 10240)
	if err != nil {
		t.Fatal(err)
	}
	want := "$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f"
	if got != want {
		t.Errorf("Compute(tom,hashcat) = %q, want %q", got, want)
	}
}

// TestComputeMoreVectors pins additional pycryptodome-confirmed vectors.
func TestComputeMoreVectors(t *testing.T) {
	cases := []struct{ user, pw, want string }{
		{"Administrator", "P@ssw0rd", "$DCC2$10240#Administrator#dfb35a65f92d8af602f08e358a58dc42"},
		{"test1", "test1", "$DCC2$10240#test1#607bbe89611e37446e736f7856515bf8"},
	}
	for _, c := range cases {
		got, err := Compute(c.user, c.pw, 0) // default iterations
		if err != nil {
			t.Fatalf("Compute(%s): %v", c.user, err)
		}
		if got != c.want {
			t.Errorf("Compute(%s,%s) = %q, want %q", c.user, c.pw, got, c.want)
		}
	}
}

func TestVerify(t *testing.T) {
	h := "$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f"
	r, err := Verify("hashcat", h)
	if err != nil || !r.Matched {
		t.Errorf("Verify(correct) = %v, %v; want matched", r, err)
	}
	if r.Username != "tom" || r.Iterations != 10240 {
		t.Errorf("verify metadata: %+v", r)
	}
	if bad, _ := Verify("wrong", h); bad.Matched {
		t.Error("wrong password matched")
	}
}

// TestUsernameCaseInsensitiveSalt confirms the salt is the lowercased username
// (so the same password under TOM and tom yields the same hash).
func TestUsernameCaseInsensitiveSalt(t *testing.T) {
	lo, _ := Compute("tom", "hashcat", 10240)
	hi, _ := Compute("TOM", "hashcat", 10240)
	// The displayed username differs in case, but the hash digest must match.
	pl, _ := Parse(lo)
	ph, _ := Parse(hi)
	if pl.Hash != ph.Hash {
		t.Errorf("case-different usernames must hash identically: %s vs %s", pl.Hash, ph.Hash)
	}
}

func TestRoundTrip(t *testing.T) {
	for _, pw := range []string{"", "a", "hunter2", "P@ssw0rd!", "naïve"} {
		h, err := Compute("svc_acct", pw, 10240)
		if err != nil {
			t.Fatal(err)
		}
		if r, _ := Verify(pw, h); !r.Matched {
			t.Errorf("round-trip %q: not matched", pw)
		}
		if r, _ := Verify(pw+"x", h); r.Matched {
			t.Errorf("round-trip %q: wrong password matched", pw)
		}
	}
}

func TestRejectsMalformed(t *testing.T) {
	for _, c := range []string{
		"",
		"$1$abc",          // wrong scheme
		"$DCC2$10240#tom", // missing hash field
		"$DCC2$abc#tom#e4e938d12fe5974dc42a90120bd9c90f",  // bad iterations
		"$DCC2$10240#tom#zz",                              // too short / non-hex
		"$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90", // 31 hex
	} {
		if _, err := Verify("x", c); err == nil {
			t.Errorf("Verify(_, %q): want error, got nil", c)
		}
	}
}
