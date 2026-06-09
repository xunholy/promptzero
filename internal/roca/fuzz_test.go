package roca

import "testing"

// FuzzDetect drives arbitrary input through the parser to assert it never
// panics and never returns both a nil error and a nil result.
func FuzzDetect(f *testing.F) {
	seeds := []string{
		"",
		"0",
		"123456789",
		"0xdeadbeef",
		"ssh-rsa",
		"ssh-rsa AAAAB3NzaC1yc2E= user@host",
		"-----BEGIN PUBLIC KEY-----\nMA==\n-----END PUBLIC KEY-----",
		vulnerableModuli[0],
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		res, err := Detect(in)
		if err == nil && res == nil {
			t.Fatalf("Detect(%q): nil error and nil result", in)
		}
	})
}
