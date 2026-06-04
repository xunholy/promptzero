// SPDX-License-Identifier: AGPL-3.0-or-later

package ciscopw

import "testing"

// Published vectors. The first is the canonical hashcat mode-9200 example
// (password "hashcat"); the second was recovered to "cisco". Both are
// reproduced byte-for-byte by Type8Compute.
const (
	type8Hashcat = "$8$TnGX/fE4KGHOVU$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk"
	type8Cisco   = "$8$dsYGNam3K1SIJO$7nv/35M/qr6t.dVc7UY9zrJDWRVqncHub1PE9UlMQFs"
)

func TestType8ComputeVectors(t *testing.T) {
	cases := []struct{ pw, salt, want string }{
		{"hashcat", "TnGX/fE4KGHOVU", type8Hashcat},
		{"cisco", "dsYGNam3K1SIJO", type8Cisco},
	}
	for _, c := range cases {
		got, err := Type8Compute(c.pw, c.salt)
		if err != nil {
			t.Fatalf("Type8Compute(%q): %v", c.pw, err)
		}
		if got != c.want {
			t.Errorf("Type8Compute(%q):\n got  %q\n want %q", c.pw, got, c.want)
		}
	}
}

func TestType8Verify(t *testing.T) {
	ok, err := Type8Verify("hashcat", type8Hashcat)
	if err != nil || !ok {
		t.Errorf("Verify(correct) = %v, %v; want true, nil", ok, err)
	}
	if ok, _ := Type8Verify("Hashcat", type8Hashcat); ok {
		t.Error("wrong password matched")
	}
	ok, err = Type8Verify("cisco", type8Cisco)
	if err != nil || !ok {
		t.Errorf("Verify(cisco) = %v, %v; want true, nil", ok, err)
	}
}

func TestType8RoundTrip(t *testing.T) {
	for _, pw := range []string{"", "a", "hunter2", "P@ssw0rd!", "naïve"} {
		h, err := Type8Compute(pw, "") // random salt
		if err != nil {
			t.Fatalf("Compute(%q): %v", pw, err)
		}
		ok, err := Type8Verify(pw, h)
		if err != nil || !ok {
			t.Errorf("round-trip %q: %v, %v", pw, ok, err)
		}
		if bad, _ := Type8Verify(pw+"x", h); bad {
			t.Errorf("round-trip %q: wrong password matched", pw)
		}
	}
}

func TestType8DigestShape(t *testing.T) {
	h, _ := Type8Compute("x", "TnGX/fE4KGHOVU")
	// $8$ + 14 salt + $ + 43 digest = 61 chars.
	if len(h) != 3+14+1+43 {
		t.Errorf("hash length = %d, want 61: %q", len(h), h)
	}
}

func TestType8RejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"$9$abc",                     // type 9, not 8
		"$8$TnGX/fE4KGHOVU",          // missing digest
		"$8$short$" + "x",            // salt too short
		"$8$TnGX/fE4KGHOVU$tooshort", // digest too short
		"$8$TnGX/fE4KGHOV!$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk", // '!' not in alphabet
	}
	for _, c := range cases {
		if _, err := Type8Verify("x", c); err == nil {
			t.Errorf("Type8Verify(_, %q): want error, got nil", c)
		}
	}
}

func TestType8ComputeRejectsBadSalt(t *testing.T) {
	if _, err := Type8Compute("x", "tooshort"); err == nil {
		t.Fatal("want error for a salt that is not 14 chars")
	}
	if _, err := Type8Compute("x", "TnGX/fE4KGHOV!"); err == nil {
		t.Fatal("want error for a salt with a non-alphabet char")
	}
}
