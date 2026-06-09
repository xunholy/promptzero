// SPDX-License-Identifier: AGPL-3.0-or-later

package ethkeystore_test

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/xunholy/promptzero/internal/ethkeystore"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

// canonicalPBKDF2 is the Web3 Secret Storage canonical PBKDF2 test vector:
// passphrase "testpassword" → private key
// 7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d.
const canonicalPBKDF2 = `{
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": {"iv": "6087dab2f9fdbbfaddc31a909735c1e6"},
    "ciphertext": "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
    "kdf": "pbkdf2",
    "kdfparams": {"c": 262144, "dklen": 32, "prf": "hmac-sha256", "salt": "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},
    "mac": "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
  },
  "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
  "version": 3
}`

// TestCanonicalPBKDF2Vector anchors the decryptor against the Web3 Secret
// Storage PBKDF2 vector — the external ground truth.
func TestCanonicalPBKDF2Vector(t *testing.T) {
	r, err := ethkeystore.Decrypt(canonicalPBKDF2, "testpassword")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !r.MACValid {
		t.Fatalf("mac_valid = false, want true")
	}
	const want = "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
	if r.PrivateKeyHex != want {
		t.Errorf("private_key = %s; want %s", r.PrivateKeyHex, want)
	}
	if r.KDF != "pbkdf2" || r.Version != 3 {
		t.Errorf("kdf/version = %s/%d; want pbkdf2/3", r.KDF, r.Version)
	}
}

// TestWrongPassphrase confirms a wrong passphrase fails the MAC and does NOT
// surface a (garbage) private key.
func TestWrongPassphrase(t *testing.T) {
	r, err := ethkeystore.Decrypt(canonicalPBKDF2, "wrongpassword")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if r.MACValid {
		t.Errorf("mac_valid = true, want false")
	}
	if r.PrivateKeyHex != "" {
		t.Errorf("private_key surfaced for wrong passphrase: %s", r.PrivateKeyHex)
	}
	if r.Note == "" {
		t.Errorf("expected a Note explaining the MAC failure")
	}
}

// buildScryptKeystore encrypts a known private key into a scrypt V3 keystore
// (small N for test speed), the inverse of Decrypt, so the scrypt path is
// proven end-to-end (the PBKDF2 vector already anchors the absolute crypto).
func buildScryptKeystore(t *testing.T, priv []byte, passphrase string) string {
	t.Helper()
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(0x10 + i)
	}
	const n, r, p = 4096, 8, 1
	dk, err := scrypt.Key([]byte(passphrase), salt, n, r, p, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(dk[:16])
	ct := make([]byte, len(priv))
	cipher.NewCTR(block, iv).XORKeyStream(ct, priv)
	h := sha3.NewLegacyKeccak256()
	h.Write(dk[16:32])
	h.Write(ct)
	mac := h.Sum(nil)
	return fmt.Sprintf(`{"version":3,"crypto":{"cipher":"aes-128-ctr",`+
		`"cipherparams":{"iv":"%s"},"ciphertext":"%s","kdf":"scrypt",`+
		`"kdfparams":{"dklen":32,"n":%d,"p":%d,"r":%d,"salt":"%s"},"mac":"%s"}}`,
		hex.EncodeToString(iv), hex.EncodeToString(ct), n, p, r,
		hex.EncodeToString(salt), hex.EncodeToString(mac))
}

// TestScryptRoundTrip proves the scrypt KDF path: encrypt a known key, decrypt
// it back.
func TestScryptRoundTrip(t *testing.T) {
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(0xa0 + i)
	}
	ks := buildScryptKeystore(t, priv, "hunter2")

	r, err := ethkeystore.Decrypt(ks, "hunter2")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !r.MACValid || r.KDF != "scrypt" {
		t.Fatalf("mac_valid=%v kdf=%s; want true/scrypt", r.MACValid, r.KDF)
	}
	if r.PrivateKeyHex != hex.EncodeToString(priv) {
		t.Errorf("private_key = %s; want %s", r.PrivateKeyHex, hex.EncodeToString(priv))
	}
	// Wrong passphrase on the scrypt file fails the MAC too.
	if bad, _ := ethkeystore.Decrypt(ks, "nope"); bad.MACValid {
		t.Errorf("scrypt wrong passphrase: mac_valid = true, want false")
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"invalid json":       "{not json",
		"no crypto section":  `{"version":3}`,
		"unsupported cipher": `{"version":3,"crypto":{"cipher":"aes-256-gcm","ciphertext":"00","cipherparams":{"iv":"00000000000000000000000000000000"},"kdf":"pbkdf2","kdfparams":{},"mac":"` + hex.EncodeToString(make([]byte, 32)) + `"}}`,
		"unsupported kdf":    `{"version":3,"crypto":{"cipher":"aes-128-ctr","ciphertext":"00","cipherparams":{"iv":"00000000000000000000000000000000"},"kdf":"argon2","kdfparams":{},"mac":"` + hex.EncodeToString(make([]byte, 32)) + `"}}`,
		"hostile scrypt N":   `{"version":3,"crypto":{"cipher":"aes-128-ctr","ciphertext":"00","cipherparams":{"iv":"00000000000000000000000000000000"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":2000000000,"p":1,"r":8,"salt":"00"},"mac":"` + hex.EncodeToString(make([]byte, 32)) + `"}}`,
	}
	for name, in := range cases {
		if _, err := ethkeystore.Decrypt(in, "x"); err == nil {
			t.Errorf("%s: Decrypt = nil error, want error", name)
		}
	}
}
