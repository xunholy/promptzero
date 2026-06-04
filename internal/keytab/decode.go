// SPDX-License-Identifier: AGPL-3.0-or-later

// Package keytab parses an MIT Kerberos keytab file (the binary `.keytab`
// format, version 0x0502) into its entries — service / account principals,
// key-version numbers, encryption types, and the raw key bytes. A keytab
// recovered from a compromised host is high-value Active Directory loot: it
// holds the long-term Kerberos keys of the principals it serves, which an
// operator uses for offline ticket forging (silver tickets), pass-the-key /
// overpass-the-hash, and — for the RC4 (etype 23) entries — the account's NT
// hash directly. It is the file-format complement to kerberos_decode (which
// dissects the Kerberos wire protocol). Pure offline transform; no network or
// device.
//
// # Wrap-vs-native judgement
//
// Native. The keytab is a small, publicly documented big-endian binary format
// (MIT krb5 doc / source krb5_kt_*): a 2-byte version, then length-prefixed
// entries of counted-octet-string components + a keyblock. It is a length-
// prefixed walker; there is nothing to wrap, and pulling in a Kerberos library
// (gokrb5) — aimed at being a client — to read an untrusted file is unwarranted.
// Consistent with internal/kerberos and the other in-tree parsers.
//
// # Verifiable / no confidently-wrong output
//
// Anchored to the authoritative MIT `ktutil`: a keytab built per the 0x0502
// spec (principal HTTP/web.example.com@EXAMPLE.COM, kvno 5, etype 18 aes256,
// a 32-byte key) is confirmed by `ktutil rkt … / list -e -t` to list exactly
// those values, and the same bytes parse to the same principal / realm /
// components / name-type / kvno / enctype / key here. A truncated or malformed
// entry is rejected with an error, deleted/hole entries (negative size) are
// counted and skipped, and length fields are bounds-checked. The legacy 0x0501
// (host-byte-order, no name-type) variant is reported and rejected rather than
// guessed.
package keytab

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Result is the parsed keytab.
type Result struct {
	Version        string   `json:"version"`
	Entries        []*Entry `json:"entries"`
	DeletedEntries int      `json:"deleted_entries,omitempty"`
	TotalBytes     int      `json:"total_bytes"`
}

// Entry is one keytab key entry.
type Entry struct {
	Principal     string   `json:"principal"`
	Realm         string   `json:"realm"`
	Components    []string `json:"components"`
	NameType      int      `json:"name_type"`
	NameTypeName  string   `json:"name_type_name,omitempty"`
	TimestampUTC  string   `json:"timestamp_utc"`
	TimestampUnix int64    `json:"timestamp_unix"`
	KVNO          int      `json:"kvno"`
	EnctypeID     int      `json:"enctype_id"`
	EnctypeName   string   `json:"enctype_name,omitempty"`
	KeyLength     int      `json:"key_length"`
	KeyHex        string   `json:"key_hex"`
	Note          string   `json:"note,omitempty"`
}

// Decode parses the hex of a keytab file (separators / 0x prefix tolerated).
func Decode(hexBlob string) (*Result, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a keytab from raw bytes.
func DecodeBytes(b []byte) (*Result, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("keytab: too short for a version header")
	}
	ver := binary.BigEndian.Uint16(b[0:2])
	switch ver {
	case 0x0502:
		// standard, big-endian, with name_type — handled below.
	case 0x0501:
		return nil, fmt.Errorf("keytab: legacy 0x0501 (host-byte-order, no name-type) is not decoded here; convert with `ktutil` to the standard 0x0502 form")
	default:
		return nil, fmt.Errorf("keytab: unexpected version 0x%04x (want 0x0502)", ver)
	}

	r := &Result{Version: "0x0502", TotalBytes: len(b)}
	off := 2
	for off+4 <= len(b) {
		size := int32(binary.BigEndian.Uint32(b[off : off+4]))
		off += 4
		if size < 0 { // deleted / hole entry: skip |size| bytes
			// Promote to int64 so int32(MinInt32) negation can't overflow
			// back to a negative value.
			skip := -int64(size)
			if skip < 0 || off+int(skip) > len(b) {
				return nil, fmt.Errorf("keytab: deleted-entry size %d overruns buffer", skip)
			}
			off += int(skip)
			r.DeletedEntries++
			continue
		}
		if size == 0 || off+int(size) > len(b) {
			return nil, fmt.Errorf("keytab: entry size %d at offset %d out of range", size, off-4)
		}
		e, err := parseEntry(b[off : off+int(size)])
		if err != nil {
			return nil, err
		}
		r.Entries = append(r.Entries, e)
		off += int(size)
	}
	if len(r.Entries) == 0 && r.DeletedEntries == 0 {
		return nil, fmt.Errorf("keytab: no entries found")
	}
	return r, nil
}

// parseEntry parses one entry body (the bytes after its 4-byte size field).
func parseEntry(b []byte) (*Entry, error) {
	p := &cursor{b: b}
	numComp, err := p.u16()
	if err != nil {
		return nil, err
	}
	realm, err := p.cos()
	if err != nil {
		return nil, fmt.Errorf("keytab: realm: %w", err)
	}
	comps := make([]string, 0, numComp)
	for i := 0; i < int(numComp); i++ {
		c, err := p.cos()
		if err != nil {
			return nil, fmt.Errorf("keytab: component %d: %w", i, err)
		}
		comps = append(comps, string(c))
	}
	nameType, err := p.u32()
	if err != nil {
		return nil, err
	}
	ts, err := p.u32()
	if err != nil {
		return nil, err
	}
	kvno8, err := p.u8()
	if err != nil {
		return nil, err
	}
	etype, err := p.u16()
	if err != nil {
		return nil, err
	}
	key, err := p.cos()
	if err != nil {
		return nil, fmt.Errorf("keytab: key: %w", err)
	}
	kvno := int(kvno8)
	// An optional 32-bit kvno follows if the entry has 4 trailing bytes.
	if p.remaining() >= 4 {
		if v, err := p.u32(); err == nil && v != 0 {
			kvno = int(v)
		}
	}

	e := &Entry{
		Realm:         string(realm),
		Components:    comps,
		NameType:      int(nameType),
		NameTypeName:  nameTypeName(nameType),
		TimestampUnix: int64(ts),
		TimestampUTC:  time.Unix(int64(ts), 0).UTC().Format(time.RFC3339),
		KVNO:          kvno,
		EnctypeID:     int(etype),
		EnctypeName:   enctypeName(etype),
		KeyLength:     len(key),
		KeyHex:        hex.EncodeToString(key),
	}
	e.Principal = strings.Join(comps, "/") + "@" + string(realm)
	if etype == 23 { // arcfour-hmac
		e.Note = "RC4 (etype 23) key is the account's NT hash — usable for pass-the-hash / overpass-the-hash"
	}
	return e, nil
}

// cursor is a bounds-checked big-endian reader over an entry body.
type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) remaining() int { return len(c.b) - c.pos }

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || c.pos+n > len(c.b) {
		return nil, fmt.Errorf("keytab: truncated entry (need %d bytes at offset %d)", n, c.pos)
	}
	s := c.b[c.pos : c.pos+n]
	c.pos += n
	return s, nil
}

func (c *cursor) u8() (uint8, error) {
	s, err := c.take(1)
	if err != nil {
		return 0, err
	}
	return s[0], nil
}

func (c *cursor) u16() (uint16, error) {
	s, err := c.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(s), nil
}

func (c *cursor) u32() (uint32, error) {
	s, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(s), nil
}

// cos reads a counted_octet_string (uint16 length + bytes).
func (c *cursor) cos() ([]byte, error) {
	n, err := c.u16()
	if err != nil {
		return nil, err
	}
	return c.take(int(n))
}

func nameTypeName(t uint32) string {
	switch t {
	case 0:
		return "KRB5_NT_UNKNOWN"
	case 1:
		return "KRB5_NT_PRINCIPAL"
	case 2:
		return "KRB5_NT_SRV_INST"
	case 3:
		return "KRB5_NT_SRV_HST"
	case 4:
		return "KRB5_NT_SRV_XHST"
	case 5:
		return "KRB5_NT_UID"
	case 10:
		return "KRB5_NT_ENTERPRISE"
	}
	return ""
}

func enctypeName(e uint16) string {
	switch e {
	case 1:
		return "des-cbc-crc"
	case 2:
		return "des-cbc-md4"
	case 3:
		return "des-cbc-md5"
	case 16:
		return "des3-cbc-sha1"
	case 17:
		return "aes128-cts-hmac-sha1-96"
	case 18:
		return "aes256-cts-hmac-sha1-96"
	case 19:
		return "aes128-cts-hmac-sha256-128"
	case 20:
		return "aes256-cts-hmac-sha384-192"
	case 23:
		return "arcfour-hmac (RC4)"
	case 24:
		return "arcfour-hmac-exp"
	case 25:
		return "camellia128-cts-cmac"
	case 26:
		return "camellia256-cts-cmac"
	}
	return ""
}

// parseHex strips common separators / 0x prefix and decodes a hex string.
func parseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "",
		":", "", "-", "", "_", "", "0x", "", "0X", "").Replace(s)
	if s == "" {
		return nil, fmt.Errorf("keytab: empty input")
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("keytab: hex has odd length")
	}
	return hex.DecodeString(s)
}
