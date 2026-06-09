package sshpub

import "testing"

// FuzzDecode drives arbitrary input + candidate through the parser to assert it
// never panics and never returns a nil error with a nil result.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		"# comment only",
		edLine,
		rsaLine,
		ecLine,
		dssLine,
		"@cert-authority *.example.com " + edLine,
		"|1|nfJ9/6uO8Esn+VDzdZGxA9W2J7M=|4eDWZz1YnmPX6P3HUWSoAtlg3hE= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPA32noYpHpH4lTWrZOPj75gEBOAIX3MBWXUoYbKDdMF",
		"ssh-rsa !!!notbase64 c",
	}
	for _, s := range seeds {
		f.Add(s, "server1.example.com")
	}
	f.Fuzz(func(t *testing.T, in, host string) {
		res, err := Decode(in, host)
		if err == nil && res == nil {
			t.Fatalf("Decode(%q,%q): nil error and nil result", in, host)
		}
	})
}
