// SPDX-License-Identifier: AGPL-3.0-or-later

package mysqlpw

import "testing"

// Oracle vectors: the universally-published MySQL PASSWORD() example and the
// hashcat-300 example, cross-checked with python hashlib SHA1(SHA1(pw)).
const (
	pwPassword = "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19" // PASSWORD('password')
	pw123456   = "*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9" // PASSWORD('123456')
)

func TestComputeVectors(t *testing.T) {
	cases := map[string]string{
		"password": pwPassword,
		"123456":   pw123456,
	}
	for pw, want := range cases {
		if got := Compute(pw); got != want {
			t.Errorf("Compute(%q) = %q, want %q", pw, got, want)
		}
	}
}

func TestComputeIsUppercase41(t *testing.T) {
	h := Compute("anything")
	if len(h) != 41 || h[0] != '*' {
		t.Errorf("hash shape wrong: %q (len %d)", h, len(h))
	}
}

func TestVerify(t *testing.T) {
	ok, err := Verify("password", pwPassword)
	if err != nil || !ok {
		t.Errorf("Verify(correct) = %v, %v; want true, nil", ok, err)
	}
	ok, err = Verify("wrong", pwPassword)
	if err != nil || ok {
		t.Errorf("Verify(wrong) = %v, %v; want false, nil", ok, err)
	}
}

// TestVerifyAcceptsBareAndLowercase ensures the '*' prefix is optional and hex
// case is ignored.
func TestVerifyAcceptsBareAndLowercase(t *testing.T) {
	bare := "2470c0c06dee42fd1618bb99005adca2ec9d1e19" // no '*', lowercase
	ok, err := Verify("password", bare)
	if err != nil || !ok {
		t.Errorf("Verify(bare lowercase) = %v, %v; want true, nil", ok, err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"",     // empty
		"*",    // just prefix
		"*XYZ", // too short / non-hex
		"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E1",   // 39 hex
		"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E199", // 41 hex
		"*ZZ70C0C06DEE42FD1618BB99005ADCA2EC9D1E19",  // non-hex digit
	} {
		if _, err := Verify("password", bad); err == nil {
			t.Errorf("Verify(_, %q): want error, got nil", bad)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	for _, pw := range []string{"", "a", "hunter2", "p@ssw0rd!", "日本語"} {
		h := Compute(pw)
		ok, err := Verify(pw, h)
		if err != nil || !ok {
			t.Errorf("round-trip %q: %v, %v", pw, ok, err)
		}
		if ok, _ := Verify(pw+"x", h); ok {
			t.Errorf("round-trip %q: wrong password matched", pw)
		}
	}
}
