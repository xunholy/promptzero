package shadow

import (
	"strings"
	"testing"
)

// Real crypt hashes (openssl passwd -6/-5/-1) plus published example hashes for
// the schemes Python 3.13 / this host cannot generate. Classification is by the
// documented crypt id, so the example hashes exercise the prefix logic exactly.
const (
	h6 = "$6$abcdefgh$M/eYsB4rVXAm3ZNc88J.UD9rCKAT6FB1rahiwJCHtEndQNORCub5qhjxn50qbqVVthkM.9HpEwtf0t.iV9uH0/"
	h5 = "$5$abcdefgh$XEPmEiAJvPG31m/DaIsyckkv.Sxd.8NrmElXxCKFQr/"
	h1 = "$1$abcdefgh$vhxKZ/s1ygZHyCEDPyqtQ/"
	// bcrypt example for "password" (widely published test vector).
	hBcrypt = "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	hYescr  = "$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X3DX6M94c7o.9agCG9G317fhZg9SqC.5i5rd.RhAtQ7"
	hDes    = "rl.3StKT.4T8M"
)

func shadowFile() string {
	return strings.Join([]string{
		"# a comment",
		"root:" + h6 + ":19000:0:99999:7:::",
		"admin:" + h5 + ":19000:0:99999:7:::",
		"legacy:" + h1 + ":18000:0:99999:7:::",
		"bcryptu:" + hBcrypt + ":19000:0:99999:7:::",
		"yu:" + hYescr + ":19000:::::",
		"oldunix:" + hDes + ":17000:0:99999:7:::",
		"svc:!" + h6 + ":19000:0:99999:7:::",
		"daemon:*:18000:0:99999:7:::",
		"bin:!!:18000:0:99999:7:::",
		"guest::19000:0:99999:7:::",
		"",
	}, "\n")
}

func byUser(r *Result) map[string]Entry {
	m := map[string]Entry{}
	for _, e := range r.Entries {
		m[e.User] = e
	}
	return m
}

func TestDecode_Schemes(t *testing.T) {
	r, err := Decode(shadowFile())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	m := byUser(r)
	cases := []struct {
		user, scheme string
		mode         int
		crackable    bool
	}{
		{"root", "sha512crypt", 1800, true},
		{"admin", "sha256crypt", 7400, true},
		{"legacy", "md5crypt", 500, true},
		{"bcryptu", "bcrypt", 3200, true},
		{"oldunix", "descrypt (traditional DES)", 1500, true},
	}
	for _, c := range cases {
		e := m[c.user]
		if e.HashScheme != c.scheme || e.HashcatMode != c.mode || e.Crackable != c.crackable || e.Status != "active" {
			t.Errorf("%s = %+v, want scheme=%q mode=%d crackable=%v active", c.user, e, c.scheme, c.mode, c.crackable)
		}
	}
}

func TestDecode_YescryptJohnOnly(t *testing.T) {
	r, _ := Decode(shadowFile())
	e := byUser(r)["yu"]
	if e.HashScheme != "yescrypt" || e.HashcatMode != 0 || e.JohnFormat != "yescrypt" || !e.Crackable {
		t.Errorf("yescrypt entry = %+v", e)
	}
	if !strings.Contains(e.Note, "John") {
		t.Errorf("yescrypt note should point to John (no native hashcat mode): %q", e.Note)
	}
}

func TestDecode_LockedButCrackable(t *testing.T) {
	r, _ := Decode(shadowFile())
	e := byUser(r)["svc"]
	if !e.Locked || e.Status != "locked" || !e.Crackable || e.HashScheme != "sha512crypt" {
		t.Errorf("svc (locked w/ hash) = %+v, want locked+crackable sha512crypt", e)
	}
}

func TestDecode_StatusMarkers(t *testing.T) {
	r, _ := Decode(shadowFile())
	m := byUser(r)
	if e := m["daemon"]; e.Status != "disabled" || e.Crackable {
		t.Errorf("daemon = %+v, want disabled non-crackable", e)
	}
	if e := m["bin"]; e.Status != "locked" || !e.Locked || e.Crackable {
		t.Errorf("bin = %+v, want locked-no-hash", e)
	}
	if e := m["guest"]; e.Status != "no-password" || e.Crackable {
		t.Errorf("guest = %+v, want no-password", e)
	}
}

func TestDecode_Counts(t *testing.T) {
	r, _ := Decode(shadowFile())
	// crackable: root, admin, legacy, bcryptu, yu, oldunix, svc = 7
	// locked: svc, bin = 2 ; no-password: guest = 1
	if r.CrackableCount != 7 || r.LockedCount != 2 || r.NoPasswordCount != 1 {
		t.Errorf("counts crackable=%d locked=%d nopw=%d, want 7/2/1", r.CrackableCount, r.LockedCount, r.NoPasswordCount)
	}
}

func TestDecode_AgingFields(t *testing.T) {
	r, _ := Decode(shadowFile())
	e := byUser(r)["root"]
	if e.LastChangeDays != 19000 || e.MaxAgeDays != 99999 {
		t.Errorf("aging = last=%d max=%d, want 19000/99999", e.LastChangeDays, e.MaxAgeDays)
	}
}

// A passwd-style line (field 2 == "x") must be reported shadowed, never as a hash.
func TestDecode_PasswdRedirect(t *testing.T) {
	r, err := Decode("root:x:0:0:root:/root:/bin/bash\n")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	e := r.Entries[0]
	if e.Status != "shadowed" || e.Crackable {
		t.Errorf("passwd line = %+v, want shadowed non-crackable", e)
	}
}

func TestDecode_Rejects(t *testing.T) {
	for name, in := range map[string]string{
		"empty":     "",
		"one field": "justonetoken\nanother\n",
		"prose":     "this is not a shadow file at all\n",
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(shadowFile())
	f.Add("root:$6$x$y:1:2:3:4:5:6:7")
	f.Add("a:!:0")
	f.Add("")
	f.Fuzz(func(_ *testing.T, in string) {
		_, _ = Decode(in)
	})
}
