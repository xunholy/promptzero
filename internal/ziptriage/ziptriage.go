// Package ziptriage decodes a ZIP archive's central directory into its
// encryption posture for password-cracking triage.
//
// Password-protected archives are among the most common high-value loot
// artifacts, and the operator's first question is "can I crack this, and with
// which hashcat mode?". The answer depends entirely on HOW the ZIP is
// encrypted: legacy **ZipCrypto** (PKWARE traditional) is weak and fast to
// attack (and has a known-plaintext break), whereas **WinZip AES** (AES-128/192/
// 256) is a slow PBKDF2-HMAC-SHA1 target. This decodes the central directory
// offline and reports which scheme is in use, the AES strength when applicable,
// and the matching hashcat mode (13600 for WinZip AES; the 17200-family for
// ZipCrypto).
//
// No confidently-wrong output: it reports the archive's encryption *structure*
// only — it does not crack, decrypt, or emit the zip2john hash string (that
// needs the encrypted record bytes and is out of scope); an archive with no
// encrypted entries is reported as such (not crackable — there is no password),
// and input that is not a ZIP is rejected.
//
// Wrap-vs-native: native — encoding/binary over the documented ZIP (APPNOTE.TXT)
// central-directory + the WinZip AES 0x9901 extra field; stdlib only, no new
// go.mod dependency. Anchored to real `zip -P` (ZipCrypto) and `7z` (AES)
// archives.
package ziptriage

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	sigLocalFile  = 0x04034b50
	sigCentralDir = 0x02014b50
	sigEOCD       = 0x06054b50
	aesExtraID    = 0x9901
)

// Entry is one central-directory record's triage-relevant fields.
type Entry struct {
	Name      string `json:"name"`
	Encrypted bool   `json:"encrypted"`
	Method    string `json:"method"`
}

// Result is the archive's encryption posture.
type Result struct {
	Format           string `json:"format"`
	TotalEntries     int    `json:"total_entries"`
	EncryptedEntries int    `json:"encrypted_entries"`
	// Encryption is "none", "ZipCrypto", or "WinZip-AES".
	Encryption         string `json:"encryption"`
	AESVersion         string `json:"aes_version,omitempty"`       // "AE-1" / "AE-2"
	AESStrengthBits    int    `json:"aes_strength_bits,omitempty"` // 128 / 192 / 256
	FirstEncryptedName string `json:"first_encrypted_name,omitempty"`

	HashcatMode     int    `json:"hashcat_mode"`
	HashcatModeNote string `json:"hashcat_mode_note,omitempty"`
	JohnTool        string `json:"john_tool"`
	Note            string `json:"note"`
}

// Decode parses a ZIP archive's central directory from its raw bytes.
func Decode(raw []byte) (*Result, error) {
	if len(raw) < 22 {
		return nil, errors.New("ziptriage: too short to be a ZIP")
	}
	if binary.LittleEndian.Uint32(raw[:4]) != sigLocalFile &&
		!containsSig(raw, sigEOCD) {
		return nil, errors.New("ziptriage: not a ZIP archive (no local-file or EOCD signature)")
	}
	eocd, err := findEOCD(raw)
	if err != nil {
		return nil, fmt.Errorf("ziptriage: %w", err)
	}
	count := int(binary.LittleEndian.Uint16(raw[eocd+10 : eocd+12]))
	cdOffset := int(binary.LittleEndian.Uint32(raw[eocd+16 : eocd+20]))
	if cdOffset < 0 || cdOffset > len(raw) {
		return nil, errors.New("ziptriage: central-directory offset out of range")
	}

	res := &Result{
		Format:     "ZIP",
		Encryption: "none",
		JohnTool:   "zip2john",
		Note: "Encryption posture only — the archive is not cracked or decrypted, and the zip2john hash is " +
			"not emitted. Crackability and speed depend on the scheme below.",
	}

	entries, aesVer, aesBits, firstEnc, anyAES, anyZipCrypto, anyDeflateEnc, allStoredEnc := walkCentralDir(raw, cdOffset, count, res)
	res.TotalEntries = entries
	classify(res, aesVer, aesBits, firstEnc, anyAES, anyZipCrypto, anyDeflateEnc, allStoredEnc)
	return res, nil
}

// walkCentralDir iterates up to count central-directory records starting at
// off, updating res.EncryptedEntries and returning aggregate flags.
func walkCentralDir(raw []byte, off, count int, res *Result) (
	total int, aesVer string, aesBits int, firstEnc string, anyAES, anyZipCrypto, anyDeflateEnc, allStoredEnc bool) {
	allStoredEnc = true
	pos := off
	for i := 0; i < count; i++ {
		if pos+46 > len(raw) || binary.LittleEndian.Uint32(raw[pos:pos+4]) != sigCentralDir {
			break
		}
		flags := binary.LittleEndian.Uint16(raw[pos+8 : pos+10])
		method := binary.LittleEndian.Uint16(raw[pos+10 : pos+12])
		fnLen := int(binary.LittleEndian.Uint16(raw[pos+28 : pos+30]))
		exLen := int(binary.LittleEndian.Uint16(raw[pos+30 : pos+32]))
		cmLen := int(binary.LittleEndian.Uint16(raw[pos+32 : pos+34]))
		nameEnd := pos + 46 + fnLen
		extraEnd := nameEnd + exLen
		if extraEnd > len(raw) {
			break
		}
		name := string(raw[pos+46 : nameEnd])
		extra := raw[nameEnd:extraEnd]
		total++

		e := Entry{Name: name, Encrypted: flags&0x0001 != 0}
		switch method {
		case 99:
			e.Method = "AES"
		case 0:
			e.Method = "stored"
		case 8:
			e.Method = "deflate"
		default:
			e.Method = fmt.Sprintf("method %d", method)
		}

		if e.Encrypted {
			res.EncryptedEntries++
			if firstEnc == "" {
				firstEnc = name
			}
			if method == 99 {
				anyAES = true
				if v, bits, ok := parseAESExtra(extra); ok {
					aesVer, aesBits = v, bits
				}
			} else {
				anyZipCrypto = true
				if method == 8 {
					anyDeflateEnc = true
					allStoredEnc = false
				} else if method != 0 {
					allStoredEnc = false
				}
			}
		}
		pos = extraEnd + cmLen
	}
	return total, aesVer, aesBits, firstEnc, anyAES, anyZipCrypto, anyDeflateEnc, allStoredEnc
}

// classify sets the encryption scheme + hashcat mode from the aggregate flags.
func classify(res *Result, aesVer string, aesBits int, firstEnc string,
	anyAES, anyZipCrypto, anyDeflateEnc, allStoredEnc bool) {
	res.FirstEncryptedName = firstEnc
	switch {
	case anyAES:
		res.Encryption = "WinZip-AES"
		res.AESVersion = aesVer
		res.AESStrengthBits = aesBits
		res.HashcatMode = 13600
		res.HashcatModeNote = "WinZip AES — hashcat -m 13600 (PBKDF2-HMAC-SHA1); slow to attack regardless of strength."
		if anyZipCrypto {
			res.Encryption = "mixed (WinZip-AES + ZipCrypto)"
		}
	case anyZipCrypto:
		res.Encryption = "ZipCrypto"
		if res.EncryptedEntries > 1 {
			res.HashcatMode = 17220
			res.HashcatModeNote = "PKWARE ZipCrypto, multiple encrypted files — hashcat -m 17220 (compressed) / -m 17225 (mixed). Weak cipher; a known-plaintext attack may apply."
		} else if anyDeflateEnc {
			res.HashcatMode = 17200
			res.HashcatModeNote = "PKWARE ZipCrypto (deflate-compressed) — hashcat -m 17200. Weak cipher; a known-plaintext attack may apply."
		} else if allStoredEnc {
			res.HashcatMode = 17210
			res.HashcatModeNote = "PKWARE ZipCrypto (uncompressed/stored) — hashcat -m 17210. Weak cipher; a known-plaintext attack may apply."
		} else {
			res.HashcatMode = 17200
			res.HashcatModeNote = "PKWARE ZipCrypto — hashcat -m 17200/17210 family. Weak cipher; a known-plaintext attack may apply."
		}
	default:
		res.Note = "No encrypted entries — the archive is not password-protected, so there is nothing to crack. " + res.Note
	}
}

// parseAESExtra finds the WinZip AES (0x9901) extra field and returns the AE
// version string and key strength in bits.
func parseAESExtra(extra []byte) (version string, bits int, ok bool) {
	for i := 0; i+4 <= len(extra); {
		id := binary.LittleEndian.Uint16(extra[i : i+2])
		size := int(binary.LittleEndian.Uint16(extra[i+2 : i+4]))
		body := i + 4
		if body+size > len(extra) {
			return "", 0, false
		}
		if id == aesExtraID && size >= 7 {
			// AE extra data: version(2) + vendor "AE"(2) + strength(1) + method(2).
			ver := binary.LittleEndian.Uint16(extra[body : body+2])
			strength := extra[body+4]
			switch strength {
			case 1:
				bits = 128
			case 2:
				bits = 192
			case 3:
				bits = 256
			}
			return fmt.Sprintf("AE-%d", ver), bits, true
		}
		i = body + size
	}
	return "", 0, false
}

// findEOCD locates the End Of Central Directory record by scanning backward for
// its signature (the EOCD may be followed by a variable-length comment).
func findEOCD(raw []byte) (int, error) {
	// Minimum EOCD is 22 bytes; the comment can be up to 65535.
	maxBack := len(raw) - 22
	limit := maxBack - 65535
	if limit < 0 {
		limit = 0
	}
	for i := maxBack; i >= limit; i-- {
		if binary.LittleEndian.Uint32(raw[i:i+4]) == sigEOCD {
			return i, nil
		}
	}
	return 0, errors.New("end-of-central-directory record not found")
}

// containsSig reports whether the 4-byte little-endian signature appears anywhere.
func containsSig(raw []byte, sig uint32) bool {
	for i := 0; i+4 <= len(raw); i++ {
		if binary.LittleEndian.Uint32(raw[i:i+4]) == sig {
			return true
		}
	}
	return false
}
