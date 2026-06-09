package sshpub

import (
	"strings"
	"testing"
)

// The fingerprint / bits expectations below are pinned to `ssh-keygen -l` and
// `ssh-keygen -E md5 -l` output for freshly generated keys, and the hashed
// known_hosts vector to `ssh-keygen -H` (verified against `ssh-keygen -F`).

const (
	edLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPA32noYpHpH4lTWrZOPj75gEBOAIX3MBWXUoYbKDdMF alice@host"
	edSHA  = "SHA256:JuIMfQ//ieEGEi5gnc1RoiCKzDw4Lg0//enIme5ZhtA"
	edMD5  = "MD5:aa:59:fb:83:d3:fa:c2:db:0d:3e:17:11:35:1d:62:af"

	rsaLine = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjLFSM+KZ4pi0Lu46D95TapPuC2G428DICGDi0dpiORRMqQcnMeIJARaqhEEFXj6pBXOCbMoq1jaOG/3SG88ekCZZ/0x9qDbSwzSFnAPBmLjOr1t2PhcG+osmHNzLr+uyu/U3SE8C1c3eFcyzqhHf0PsA6woEsOt5BIVhs1IfqILDcfJmRD5CBrjWR0rO/WCX4WBrh2XwxldlA/SdMSZgeP3FkqLhT4sznhs7XCe0HtlyTFXSnffBTLzPworv1XRmuUla/qGVmxGwT7+uLEhkmtdYoZjOf2sfWnxa7szP5/4T17yz5lNZm6doOsOIqQCyz2AiLRWUpqDbscDVB406B bob@host"
	rsaSHA  = "SHA256:m1dkyZCNi5iuB9rSmVmXuQsmK/PGf3czZe2bGw547As"
	rsaMD5  = "MD5:26:fe:09:99:15:38:af:8f:b6:fc:54:9d:05:1d:c6:e6"

	ecLine = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEDuAxyRNn9L6KyR5zZyS1hnU1SDI52e9YCOopreVflxJA34SC+dpRMZWEpUAfCLMdGbVySZpFVxNtSv3OuM3nU= carol@host"
	ecSHA  = "SHA256:imj0h3l2RzQ1JT2+PnEhGhAkITT1QMotBeVI54qTRRU"
	ecMD5  = "MD5:50:be:44:1d:e2:00:41:cd:63:f5:4d:71:02:79:da:2c"

	dssLine = "ssh-dss AAAAB3NzaC1kc3MAAACBAOcpLIjsatI6B2yZc6dYVperl9A6wmZdbUmoeyO0ZqZje6IIqwhHDHJtcT9KA4aFajHjL7cY9db5lxy5rStPbLp7duyXmJ8h8BzyTjZ8+ahISVyAAjThX5cyqeyiEDOf/LFhJVtIz1/9z8L1fsmKca1T8XkbHEixU/zJ07J3BImtAAAAFQDwA8bThnznFFnZgtHXsL3CslIAOQAAAIEAze1onmEQ/PJlfSOZY7ZIyWqZZcLjcpFEvlzrW8sMQ2rxNpsK4Br1GG9frwmMgXoS8i2TOO9AszlXEo5qD2O2nzZHOC1UzGm7imvFLI9uz3oyQz0V9PRJ5mTMBAiwVUNtkKNmZWU7r9o6JaTn0IMtrprzL/KMxYlZpgJlXNbuBsgAAACBAMH3G1UOoCU+OzccMIAdssreY7F4soKvem3xwFpwy72ZnC5fs/kBC87BvGgpgMmt6af+sCdTe6F78Frf7vcoLnwPfF2WyavW005JGvX1Dol6O7WX++ygIa4gBqn9RjmNK7TOBhf1iTz6pYOryEFyfl67OMtct2QYjL7QlUeO6MGF dave@host"
	dssSHA  = "SHA256:Z2DmiDqniV2au40M0wAOOf7aCfbHv5rd7KmgcN+iop0"
)

func one(t *testing.T, line, candidate string) Key {
	t.Helper()
	res, err := Decode(line, candidate)
	if err != nil {
		t.Fatalf("Decode(%.20q): %v", line, err)
	}
	if len(res.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(res.Keys))
	}
	return res.Keys[0]
}

func TestFingerprints(t *testing.T) {
	cases := []struct {
		name             string
		line             string
		wantType         string
		wantLabel        string
		wantBits         int
		wantSHA, wantMD5 string
		wantComment      string
	}{
		{"ed25519", edLine, "ssh-ed25519", "ED25519", 256, edSHA, edMD5, "alice@host"},
		{"rsa", rsaLine, "ssh-rsa", "RSA", 2048, rsaSHA, rsaMD5, "bob@host"},
		{"ecdsa", ecLine, "ecdsa-sha2-nistp256", "ECDSA", 256, ecSHA, ecMD5, "carol@host"},
		{"dss", dssLine, "ssh-dss", "DSA", 1024, dssSHA, "", "dave@host"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := one(t, c.line, "")
			if k.Type != c.wantType {
				t.Errorf("type = %q, want %q", k.Type, c.wantType)
			}
			if k.Label != c.wantLabel {
				t.Errorf("label = %q, want %q", k.Label, c.wantLabel)
			}
			if k.Bits != c.wantBits {
				t.Errorf("bits = %d, want %d", k.Bits, c.wantBits)
			}
			if k.FingerprintSHA256 != c.wantSHA {
				t.Errorf("sha256 = %q, want %q", k.FingerprintSHA256, c.wantSHA)
			}
			if c.wantMD5 != "" && k.FingerprintMD5 != c.wantMD5 {
				t.Errorf("md5 = %q, want %q", k.FingerprintMD5, c.wantMD5)
			}
			if k.Comment != c.wantComment {
				t.Errorf("comment = %q, want %q", k.Comment, c.wantComment)
			}
		})
	}
}

// TestRSAModulusChainsToRoca confirms the RSA modulus is surfaced so the key
// can be screened by roca_detect.
func TestRSAModulusChainsToRoca(t *testing.T) {
	k := one(t, rsaLine, "")
	if k.RSAModulusHex == "" {
		t.Fatal("expected rsa modulus hex to be populated")
	}
	if !strings.Contains(k.Note, "roca_detect") {
		t.Errorf("note %q should mention roca_detect chaining", k.Note)
	}
}

// TestHashedKnownHost pins the |1|salt|hash deanonymisation to the ssh-keygen -H
// vector: server1.example.com matches, another host does not.
func TestHashedKnownHost(t *testing.T) {
	const line = "|1|nfJ9/6uO8Esn+VDzdZGxA9W2J7M=|4eDWZz1YnmPX6P3HUWSoAtlg3hE= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPA32noYpHpH4lTWrZOPj75gEBOAIX3MBWXUoYbKDdMF"

	k := one(t, line, "server1.example.com")
	if !k.HashedHost {
		t.Error("expected HashedHost true")
	}
	if k.HostMatch != "server1.example.com" {
		t.Errorf("HostMatch = %q, want server1.example.com", k.HostMatch)
	}

	k2 := one(t, line, "other.example.com")
	if k2.HostMatch != "" {
		t.Errorf("HostMatch = %q, want empty for non-matching host", k2.HostMatch)
	}
}

// TestPlainKnownHost covers a plaintext host list with a comma + a port-bracket
// form, matched by the candidate.
func TestPlainKnownHost(t *testing.T) {
	// known_hosts line: "hosts TYPE blob [comment]". edLine already supplies
	// "ssh-ed25519 <blob> alice@host"; the trailing comment is harmless.
	line := "server1.example.com,192.168.1.10 " + edLine
	k := one(t, line, "192.168.1.10")
	if k.Hosts == "" {
		t.Fatalf("expected hosts to be populated, got %+v", k)
	}
	if k.HostMatch != "192.168.1.10" {
		t.Errorf("HostMatch = %q, want 192.168.1.10", k.HostMatch)
	}
}

// TestAuthorizedKeysOptions parses a leading options field.
func TestAuthorizedKeysOptions(t *testing.T) {
	line := `command="/usr/bin/backup",no-pty ` + edLine
	k := one(t, line, "")
	if k.Options == "" {
		t.Errorf("expected options to be parsed, got %+v", k)
	}
	if k.Type != "ssh-ed25519" {
		t.Errorf("type = %q, want ssh-ed25519", k.Type)
	}
}

// TestMarker handles a @cert-authority known_hosts marker.
func TestMarker(t *testing.T) {
	line := "@cert-authority *.example.com " + edLine
	k := one(t, line, "")
	if k.Marker != "@cert-authority" {
		t.Errorf("marker = %q, want @cert-authority", k.Marker)
	}
	if k.Hosts != "*.example.com" {
		t.Errorf("hosts = %q, want *.example.com", k.Hosts)
	}
}

// TestMultiLineFile parses several lines and skips blanks + comments.
func TestMultiLineFile(t *testing.T) {
	file := "# a comment\n" + edLine + "\n\n" + rsaLine + "\n"
	res, err := Decode(file, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 2 {
		t.Fatalf("count = %d, want 2", res.Count)
	}
	if res.Keys[0].Type != "ssh-ed25519" || res.Keys[1].Type != "ssh-rsa" {
		t.Errorf("unexpected types: %q %q", res.Keys[0].Type, res.Keys[1].Type)
	}
}

func TestErrors(t *testing.T) {
	if _, err := Decode("", ""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := Decode("   \n# only a comment", ""); err == nil {
		t.Error("comment-only: want error")
	}
}

// TestGarbageLineIsReported confirms a malformed line is surfaced with a note
// rather than aborting a batch.
func TestGarbageLineIsReported(t *testing.T) {
	res, err := Decode("ssh-rsa not-valid-base64!!! x\n"+edLine, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 2 {
		t.Fatalf("count = %d, want 2", res.Count)
	}
	if !strings.HasPrefix(res.Keys[0].Note, "unparsed") {
		t.Errorf("first line should be unparsed, got %q", res.Keys[0].Note)
	}
	if res.Keys[1].Type != "ssh-ed25519" {
		t.Errorf("second line should still parse, got %q", res.Keys[1].Type)
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "example.com", false},
		{"host?", "host1", true},
		{"host?", "host12", false},
		{"exact", "exact", true},
		{"*", "anything", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pat, c.s); got != c.want {
			t.Errorf("globMatch(%q,%q) = %v, want %v", c.pat, c.s, got, c.want)
		}
	}
}
