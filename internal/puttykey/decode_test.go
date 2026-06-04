// SPDX-License-Identifier: AGPL-3.0-or-later

package puttykey

import "testing"

// The Public-Lines base64 in each vector below is the real SSH-wire public blob
// of an ssh-keygen-generated key, so the decoder's SHA256 fingerprint must equal
// `ssh-keygen -l` on the same key (the cross-oracle anchor):
//
//	ed25519 (alice@victim): SHA256:RYwu7r7v81keCa5t4NM5dGBCBmoH1M80rW8RJt3HlKY
//	rsa-2048 (svc@host):    SHA256:AWeSx77RBL5vG83pduVmy6GNYeQr2qZTvlOGE+S6UfU
//
// The header fields follow the PuTTY AppendixC .ppk format spec.

const ppk3EdUnenc = `PuTTY-User-Key-File-3: ssh-ed25519
Encryption: none
Comment: alice@victim
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAINg+vOr/NqTPMgFrhUe9KTF1U5NSahayaQ5l9bK0
dY8d
Private-Lines: 1
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Private-MAC: 8c9d1f6e7a2b3c4d5e6f70819293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5
`

const ppk3EdEnc = `PuTTY-User-Key-File-3: ssh-ed25519
Encryption: aes256-cbc
Comment: alice@victim
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAINg+vOr/NqTPMgFrhUe9KTF1U5NSahayaQ5l9bK0
dY8d
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 21
Argon2-Parallelism: 1
Argon2-Salt: 6f3b2a1c9d8e7f60514233445566778899aabbccddeeff00112233445566778a
Private-Lines: 1
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Private-MAC: aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee
`

// CRLF line endings + ssh-rsa, PPK version 2 (no Argon2 headers).
const ppk2RSAUnenc = "PuTTY-User-Key-File-2: ssh-rsa\r\n" +
	"Encryption: none\r\n" +
	"Comment: svc@host\r\n" +
	"Public-Lines: 6\r\n" +
	"AAAAB3NzaC1yc2EAAAADAQABAAABAQCttToxnKq+1YHCUPt69YFdm+AbZKhe5rl4\r\n" +
	"W9dVG6RV0fcCDVPwThA26b0pza8hUN/eFArSJuv0FvREPHGdutinRDWaQdVLNhvg\r\n" +
	"LT9GWr5uRDyLjtY/0sMRDHjGytgO8pL3vOCVTJ8A37XNE46bk1XtrKDdBgfqWHYP\r\n" +
	"s+A7JnLbz+fnYesnWiVcIzCj2y4tvZCPsXe2/VGWVyTpqTr6pRnr/HJM9Baf+2pB\r\n" +
	"PxluVmg1xje7TXK1kPqbvptBYpKCiJRlC0HsA4y56TWtmW3Ub88LUKprVTiQGhR/\r\n" +
	"U/lNAdU9PibDJh7VKBrImQLomdKZIkReIgWOLjtNjsdX8gcEkUEj\r\n" +
	"Private-Lines: 1\r\n" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" +
	"Private-MAC: 0123456789abcdef0123456789abcdef01234567\r\n"

const (
	edFP  = "SHA256:RYwu7r7v81keCa5t4NM5dGBCBmoH1M80rW8RJt3HlKY"
	rsaFP = "SHA256:AWeSx77RBL5vG83pduVmy6GNYeQr2qZTvlOGE+S6UfU"
)

func TestDecodeV3Unencrypted(t *testing.T) {
	r, err := Decode(ppk3EdUnenc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 3 {
		t.Errorf("version = %d, want 3", r.Version)
	}
	if r.Algorithm != "ssh-ed25519" || r.KeyType != "ssh-ed25519" {
		t.Errorf("algorithm=%q key_type=%q, want ssh-ed25519/ssh-ed25519", r.Algorithm, r.KeyType)
	}
	if r.Encrypted {
		t.Error("encrypted = true, want false")
	}
	if r.Encryption != "none" {
		t.Errorf("encryption = %q, want none", r.Encryption)
	}
	if r.Fingerprint != edFP {
		t.Errorf("fingerprint = %q, want %q", r.Fingerprint, edFP)
	}
	if r.Comment != "alice@victim" {
		t.Errorf("comment = %q, want alice@victim", r.Comment)
	}
}

func TestDecodeV3Encrypted(t *testing.T) {
	r, err := Decode(ppk3EdEnc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Encrypted {
		t.Error("encrypted = false, want true")
	}
	if r.Encryption != "aes256-cbc" {
		t.Errorf("encryption = %q, want aes256-cbc", r.Encryption)
	}
	if r.KeyDerivation != "Argon2id" {
		t.Errorf("key_derivation = %q, want Argon2id", r.KeyDerivation)
	}
	if r.Argon2Memory != 8192 || r.Argon2Passes != 21 || r.Argon2Parallelism != 1 {
		t.Errorf("argon2 mem/passes/par = %d/%d/%d, want 8192/21/1", r.Argon2Memory, r.Argon2Passes, r.Argon2Parallelism)
	}
	if r.Argon2SaltLen != 32 {
		t.Errorf("argon2_salt_len = %d, want 32", r.Argon2SaltLen)
	}
	// The fingerprint + comment are cleartext headers, readable despite encryption.
	if r.Fingerprint != edFP {
		t.Errorf("fingerprint = %q, want %q", r.Fingerprint, edFP)
	}
	if r.Comment != "alice@victim" {
		t.Errorf("comment = %q, want alice@victim (cleartext even when encrypted)", r.Comment)
	}
}

func TestDecodeV2RSACRLF(t *testing.T) {
	r, err := Decode(ppk2RSAUnenc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 {
		t.Errorf("version = %d, want 2", r.Version)
	}
	if r.KeyType != "ssh-rsa" {
		t.Errorf("key_type = %q, want ssh-rsa", r.KeyType)
	}
	if r.Fingerprint != rsaFP {
		t.Errorf("fingerprint = %q, want %q", r.Fingerprint, rsaFP)
	}
	if r.Comment != "svc@host" {
		t.Errorf("comment = %q, want svc@host", r.Comment)
	}
	if r.Encrypted {
		t.Error("encrypted = true, want false")
	}
}

func TestDecodeRejectsNonPPK(t *testing.T) {
	for _, in := range []string{
		"",
		"hello world",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----",
		"PuTTY-User-Key-File-9: ssh-rsa\nEncryption: none\n",     // bad version
		"PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n", // no Public-Lines
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) = nil error, want rejection", in)
		}
	}
}

// A declared Public-Lines count that overruns the file must be rejected, not panic.
func TestDecodeRejectsOverrun(t *testing.T) {
	in := "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPublic-Lines: 99\nAAAA\n"
	if _, err := Decode(in); err == nil {
		t.Error("Decode with overrunning Public-Lines = nil error, want rejection")
	}
}
