// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ethkeystore decrypts an Ethereum V3 keystore — the encrypted
// JSON wallet file Geth, MyEtherWallet, MetaMask exports, and most Ethereum
// tooling produce — recovering the 32-byte private key with the operator's
// passphrase. A captured keystore file is prime crypto-forensics / IR / pentest
// loot: it is an offline-crackable wrapper around an Ethereum private key, the
// ETH counterpart to a BIP-39 seed or a WIF key. Pure offline transform; no
// network or device.
//
// # Wrap-vs-native judgement
//
// Native orchestration over trusted primitives. The Web3 Secret Storage scheme
// is a public spec: a scrypt or PBKDF2-HMAC-SHA256 key derivation, an
// AES-128-CTR cipher, and a Keccak-256 MAC. The KDFs and Keccak come from
// golang.org/x/crypto (already a project dependency); AES/CTR are stdlib; the
// keystore JSON parse, the MAC check, and the field assembly are our own. No
// new runtime dependency, no shell-out. Address derivation (private key →
// public key → address) needs a secp256k1 implementation that is not a current
// dependency, so it is deliberately deferred — the recovered private key is the
// loot, and any wallet can import it.
//
// # Verifiable / no confidently-wrong output
//
// Anchored to the canonical Web3 Secret Storage PBKDF2 test vector (passphrase
// "testpassword" → private key
// 7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d). The MAC is
// the gate: Keccak-256(derivedKey[16:32] ‖ ciphertext) must equal the stored
// MAC. When it does not (wrong passphrase or a corrupt file) the private key is
// NOT surfaced — a confidently-wrong key is worse than none. A hostile scrypt N
// (128·N·r over 1 GiB) is rejected rather than allowed to exhaust memory; an
// unsupported cipher/KDF or malformed JSON is rejected.
package ethkeystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/wpa"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

// scryptMaxMem caps scrypt's working set (128·N·r bytes) at 1 GiB, matching the
// in-tree webpass convention — a hostile keystore with an absurd N is rejected.
const scryptMaxMem = 1 << 30

// pbkdf2MaxIter caps PBKDF2 iterations so a hostile keystore cannot hang the
// host (the standard count is 262144).
const pbkdf2MaxIter = 100_000_000

// Result is the decryption outcome.
type Result struct {
	Version       int    `json:"version"`
	Cipher        string `json:"cipher"`
	KDF           string `json:"kdf"`
	Address       string `json:"address,omitempty"` // the file's own "address" field, if present (not derived)
	MACValid      bool   `json:"mac_valid"`
	PrivateKeyHex string `json:"private_key_hex,omitempty"`
	Note          string `json:"note,omitempty"`
}

type cipherParams struct {
	IV string `json:"iv"`
}

type cryptoSection struct {
	Cipher       string          `json:"cipher"`
	CipherText   string          `json:"ciphertext"`
	CipherParams cipherParams    `json:"cipherparams"`
	KDF          string          `json:"kdf"`
	KDFParams    json.RawMessage `json:"kdfparams"`
	MAC          string          `json:"mac"`
}

type keystore struct {
	Address    string         `json:"address"`
	Crypto     *cryptoSection `json:"crypto"`
	CryptoCaps *cryptoSection `json:"Crypto"` // some legacy MEW files capitalise it
	Version    int            `json:"version"`
}

// Decrypt parses a V3 keystore JSON and recovers the private key with the
// passphrase. A malformed file or unsupported parameters return an error; a
// MAC mismatch (wrong passphrase / corrupt file) returns a Result with
// MACValid false and no private key.
func Decrypt(jsonStr, passphrase string) (*Result, error) {
	var ks keystore
	if err := json.Unmarshal([]byte(jsonStr), &ks); err != nil {
		return nil, fmt.Errorf("ethkeystore: invalid JSON: %w", err)
	}
	c := ks.Crypto
	if c == nil {
		c = ks.CryptoCaps
	}
	if c == nil || c.Cipher == "" {
		return nil, fmt.Errorf("ethkeystore: no crypto section — is this a V3 keystore?")
	}
	if strings.ToLower(c.Cipher) != "aes-128-ctr" {
		return nil, fmt.Errorf("ethkeystore: unsupported cipher %q (only aes-128-ctr)", c.Cipher)
	}

	ciphertext, err := hex.DecodeString(c.CipherText)
	if err != nil {
		return nil, fmt.Errorf("ethkeystore: ciphertext not hex: %w", err)
	}
	iv, err := hex.DecodeString(c.CipherParams.IV)
	if err != nil || len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("ethkeystore: invalid IV")
	}
	mac, err := hex.DecodeString(c.MAC)
	if err != nil || len(mac) != 32 {
		return nil, fmt.Errorf("ethkeystore: invalid MAC")
	}

	derived, err := deriveKey(c.KDF, c.KDFParams, passphrase)
	if err != nil {
		return nil, err
	}
	if len(derived) < 32 {
		return nil, fmt.Errorf("ethkeystore: derived key too short (dklen must be >= 32)")
	}

	res := &Result{Version: ks.Version, Cipher: c.Cipher, KDF: c.KDF, Address: ks.Address}

	// MAC = Keccak-256(derivedKey[16:32] || ciphertext).
	h := sha3.NewLegacyKeccak256()
	h.Write(derived[16:32])
	h.Write(ciphertext)
	res.MACValid = subtle.ConstantTimeCompare(h.Sum(nil), mac) == 1
	if !res.MACValid {
		res.Note = "MAC does not validate — wrong passphrase or corrupt keystore; the private key is NOT surfaced"
		return res, nil
	}

	// AES-128-CTR decrypt with derivedKey[0:16].
	block, err := aes.NewCipher(derived[:16])
	if err != nil {
		return nil, fmt.Errorf("ethkeystore: aes: %w", err)
	}
	pk := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(pk, ciphertext)
	res.PrivateKeyHex = hex.EncodeToString(pk)
	return res, nil
}

// deriveKey runs the keystore's KDF over the passphrase.
func deriveKey(kdf string, params json.RawMessage, passphrase string) ([]byte, error) {
	switch strings.ToLower(kdf) {
	case "scrypt":
		var p struct {
			DKLen int    `json:"dklen"`
			N     int    `json:"n"`
			P     int    `json:"p"`
			R     int    `json:"r"`
			Salt  string `json:"salt"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("ethkeystore: bad scrypt kdfparams: %w", err)
		}
		if p.N < 2 || p.R < 1 || p.P < 1 || p.DKLen < 32 {
			return nil, fmt.Errorf("ethkeystore: invalid scrypt parameters")
		}
		if int64(128)*int64(p.N)*int64(p.R) > scryptMaxMem {
			return nil, fmt.Errorf("ethkeystore: scrypt N=%d r=%d exceeds the memory cap (hostile keystore)", p.N, p.R)
		}
		salt, err := hex.DecodeString(p.Salt)
		if err != nil {
			return nil, fmt.Errorf("ethkeystore: scrypt salt not hex: %w", err)
		}
		return scrypt.Key([]byte(passphrase), salt, p.N, p.R, p.P, p.DKLen)
	case "pbkdf2":
		var p struct {
			C     int    `json:"c"`
			DKLen int    `json:"dklen"`
			PRF   string `json:"prf"`
			Salt  string `json:"salt"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("ethkeystore: bad pbkdf2 kdfparams: %w", err)
		}
		if p.PRF != "" && strings.ToLower(p.PRF) != "hmac-sha256" {
			return nil, fmt.Errorf("ethkeystore: unsupported pbkdf2 PRF %q (only hmac-sha256)", p.PRF)
		}
		if p.C < 1 || p.DKLen < 32 {
			return nil, fmt.Errorf("ethkeystore: invalid pbkdf2 parameters")
		}
		if p.C > pbkdf2MaxIter {
			return nil, fmt.Errorf("ethkeystore: pbkdf2 c=%d exceeds the iteration cap (hostile keystore)", p.C)
		}
		salt, err := hex.DecodeString(p.Salt)
		if err != nil {
			return nil, fmt.Errorf("ethkeystore: pbkdf2 salt not hex: %w", err)
		}
		return wpa.PBKDF2([]byte(passphrase), salt, p.C, p.DKLen, sha256.New), nil
	default:
		return nil, fmt.Errorf("ethkeystore: unsupported KDF %q (only scrypt, pbkdf2)", kdf)
	}
}
