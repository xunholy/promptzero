// Package gpp decrypts Group Policy Preferences (GPP) cpassword values.
//
// Group Policy Preferences let a domain admin push local accounts, scheduled
// tasks, services, mapped drives, and data sources to every machine in an
// Active Directory domain. The password for those items is stored in an XML
// file under the domain SYSVOL share (Groups.xml, Services.xml,
// ScheduledTasks.xml, DataSources.xml, Drives.xml, Printers.xml) as a
// "cpassword" attribute — AES-256-CBC encrypted. The catch: Microsoft
// *published* the 32-byte AES key in the MS-GPPREF protocol spec
// (§2.2.1.1), so any domain user who can read SYSVOL can decrypt every
// cpassword offline. This is one of the highest-impact Active Directory
// findings (MS14-025 removed the ability to *create* new ones, but legacy
// SYSVOL files persist for years).
//
// This takes either a raw cpassword string or a pasted GPP XML snippet,
// extracts every cpassword (with the co-located account name when present),
// and decrypts it to the cleartext password. The AES key, the all-zero IV,
// the CBC mode, and the UTF-16LE plaintext encoding are all fixed by the spec
// — there is nothing to guess.
//
// No confidently-wrong output: the key / IV / algorithm are fixed; an empty
// cpassword (a cleared field) is reported as "no password set", and a
// wrong-length or bad-padding ciphertext is reported as an error on that entry,
// never a garbled guess. No network, no key material beyond the public one.
//
// Wrap-vs-native: native — Go stdlib crypto/aes + crypto/cipher + encoding/xml,
// no new go.mod dependency. Anchored to the well-known public cpassword vectors
// (see the test), cross-checked against openssl.
package gpp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf16"
)

// gppKey is the AES-256 key Microsoft published in MS-GPPREF §2.2.1.1. It is the
// same on every Windows install — that is the whole vulnerability.
var gppKey = []byte{ //nolint:gochecknoglobals
	0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
	0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
	0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
	0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
}

// Entry is one decrypted cpassword.
type Entry struct {
	Username  string `json:"username,omitempty"`
	Element   string `json:"element,omitempty"`
	Cpassword string `json:"cpassword"`
	Password  string `json:"password,omitempty"`
	Empty     bool   `json:"empty,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Result is the set of decrypted cpasswords.
type Result struct {
	Format  string  `json:"format"`
	Count   int     `json:"count"`
	Entries []Entry `json:"entries"`
	Note    string  `json:"note"`
}

var cpasswordAttr = regexp.MustCompile(`(?i)cpassword\s*=\s*"([^"]*)"`)

// Decode decrypts every cpassword in the input: a GPP XML snippet (any of the
// SYSVOL preference files) or a single raw cpassword string.
func Decode(data []byte) (*Result, error) {
	res := &Result{Format: "gpp"}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return nil, fmt.Errorf("gpp: empty input")
	}

	if strings.Contains(strings.ToLower(s), "cpassword") {
		res.Entries = extractFromXML(data)
		if len(res.Entries) == 0 {
			// Malformed XML but the attribute is present — fall back to regex.
			for _, m := range cpasswordAttr.FindAllStringSubmatch(s, -1) {
				res.Entries = append(res.Entries, decryptEntry(m[1], "", ""))
			}
		}
	} else {
		// Treat the whole input as a single raw cpassword.
		res.Entries = append(res.Entries, decryptEntry(s, "", ""))
	}

	res.Count = len(res.Entries)
	res.Note = summarize(res)
	return res, nil
}

// extractFromXML walks GPP XML and pulls each cpassword with the co-located
// account attribute (userName / accountName / newName / runAs / username).
func extractFromXML(data []byte) []Entry {
	var out []Entry
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err == io.EOF || err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		var cp, user string
		var hasCP bool
		for _, a := range se.Attr {
			switch strings.ToLower(a.Name.Local) {
			case "cpassword":
				cp, hasCP = a.Value, true
			case "username", "accountname", "newname", "runas":
				if user == "" {
					user = a.Value
				}
			}
		}
		if hasCP {
			out = append(out, decryptEntry(cp, user, se.Name.Local))
		}
	}
	return out
}

// decryptEntry decrypts one cpassword and packages the result.
func decryptEntry(cp, user, element string) Entry {
	e := Entry{Username: user, Element: element, Cpassword: cp}
	if strings.TrimSpace(cp) == "" {
		e.Empty = true
		return e
	}
	pw, err := decryptCpassword(cp)
	if err != nil {
		e.Error = err.Error()
		return e
	}
	e.Password = pw
	return e
}

// decryptCpassword performs the fixed AES-256-CBC / zero-IV / UTF-16LE decrypt.
func decryptCpassword(cp string) (string, error) {
	// GPP cpassword base64 is commonly stored without padding.
	b64 := strings.TrimSpace(cp)
	if m := len(b64) % 4; m != 0 {
		b64 += strings.Repeat("=", 4-m)
	}
	ct, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("not valid base64: %w", err)
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext length %d is not a multiple of the AES block size", len(ct))
	}
	block, err := aes.NewCipher(gppKey)
	if err != nil {
		return "", err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(pt, ct)
	pt, err = pkcs7Unpad(pt)
	if err != nil {
		return "", err
	}
	return utf16LE(pt), nil
}

// pkcs7Unpad strips and validates PKCS#7 padding.
func pkcs7Unpad(b []byte) ([]byte, error) {
	n := len(b)
	if n == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	pad := int(b[n-1])
	if pad < 1 || pad > aes.BlockSize || pad > n {
		return nil, fmt.Errorf("invalid PKCS#7 padding (likely a corrupt cpassword)")
	}
	for _, c := range b[n-pad:] {
		if int(c) != pad {
			return nil, fmt.Errorf("invalid PKCS#7 padding (likely a corrupt cpassword)")
		}
	}
	return b[:n-pad], nil
}

// utf16LE decodes little-endian UTF-16 bytes to a string, trimming a trailing
// NUL. An odd trailing byte is dropped.
func utf16LE(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

func summarize(res *Result) string {
	var recovered, empty, errs int
	for _, e := range res.Entries {
		switch {
		case e.Error != "":
			errs++
		case e.Empty:
			empty++
		default:
			recovered++
		}
	}
	if res.Count == 0 {
		return "No cpassword values found."
	}
	base := fmt.Sprintf("Decrypted %d cpassword(s) with the public MS-GPPREF AES key", recovered)
	if empty > 0 {
		base += fmt.Sprintf("; %d cleared (empty) field(s)", empty)
	}
	if errs > 0 {
		base += fmt.Sprintf("; %d undecryptable (corrupt) value(s)", errs)
	}
	if recovered > 0 {
		base += ". CRITICAL: these are cleartext credentials pushed via SYSVOL — rotate them and remove the GPP XML."
	}
	return base + "."
}
