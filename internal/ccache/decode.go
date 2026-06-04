// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ccache parses an MIT Kerberos credential cache (the binary FILE: ccache
// format, version 0x0504) into its default principal and stored credentials —
// the client / server principals, ticket flags, validity times, session key,
// and the embedded ticket bytes. A ccache lifted from a host (the on-disk
// /tmp/krb5cc_* / KRB5CCNAME file, or a Rubeus / Mimikatz dump) is high-value
// Active Directory loot: it holds live Kerberos tickets usable for
// **pass-the-ticket**, and a TGT (service krbtgt/…) is the golden-ticket /
// delegation pivot. It is the credential-cache complement to keytab_decode
// (long-term keys) and kerberos_decode (the wire protocol). Pure offline
// transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. The ccache is a documented big-endian length-prefixed binary format
// (MIT krb5 ccache_file_format): a 2-byte version, a tagged header, a default
// principal, then variable-length credentials of uint32-counted principals +
// keyblock + times + flags + addresses + authdata + ticket. It is a
// length-prefixed walker; there is nothing to wrap, and pulling in a Kerberos
// library to read an untrusted file is unwarranted. Consistent with
// internal/keytab and internal/kerberos owning their parse in-tree.
//
// # Verifiable / no confidently-wrong output
//
// Anchored to the authoritative MIT `klist`: a ccache built per the 0x0504 spec
// (default principal alice@EXAMPLE.COM, a credential for krbtgt/EXAMPLE.COM with
// times + ticket_flags 0x40e00000) is confirmed by `klist -cf` to list exactly
// that principal, service, the three times, and `Flags: FRIA`
// (Forwardable/Renewable/Initial/preAuth) — and the same bytes parse to the same
// values here. Length fields are bounds-checked, hostile counts are capped, and
// a truncated/malformed credential is rejected. The legacy 0x0501–0x0503
// variants (different header / byte-order) are reported and rejected rather than
// guessed.
package ccache

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Result is the parsed credential cache.
type Result struct {
	Version          string        `json:"version"`
	DefaultPrincipal string        `json:"default_principal"`
	Credentials      []*Credential `json:"credentials"`
	TotalBytes       int           `json:"total_bytes"`
}

// Credential is one cached ticket + its metadata.
type Credential struct {
	Client      string `json:"client"`
	Server      string `json:"server"`
	KeyType     int    `json:"key_type"`
	KeyTypeName string `json:"key_type_name,omitempty"`
	KeyHex      string `json:"key_hex"`

	AuthTimeUTC  string `json:"auth_time_utc,omitempty"`
	StartTimeUTC string `json:"start_time_utc,omitempty"`
	EndTimeUTC   string `json:"end_time_utc,omitempty"`
	RenewTillUTC string `json:"renew_till_utc,omitempty"`

	TicketFlags     uint32   `json:"ticket_flags"`
	TicketFlagNames []string `json:"ticket_flag_names,omitempty"`
	IsSkey          bool     `json:"is_skey"`

	TicketLength       int    `json:"ticket_length"`
	TicketHex          string `json:"ticket_hex"`
	SecondTicketLength int    `json:"second_ticket_length,omitempty"`

	Note string `json:"note,omitempty"`
}

const maxCount = 1 << 16 // sanity cap on address/authdata counts

// Decode parses the hex of a ccache file (separators / 0x prefix tolerated).
func Decode(hexBlob string) (*Result, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a credential cache from raw bytes.
func DecodeBytes(b []byte) (*Result, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("ccache: too short for a version header")
	}
	ver := binary.BigEndian.Uint16(b[0:2])
	if ver != 0x0504 {
		return nil, fmt.Errorf("ccache: version 0x%04x not decoded here (only the modern 0x0504 FILE format; convert legacy caches with `klist`/`kcc`)", ver)
	}
	c := &cursor{b: b, pos: 2}

	// 0x0504 header: uint16 length + tagged fields (skipped wholesale).
	hlen, err := c.u16()
	if err != nil {
		return nil, err
	}
	if _, err := c.take(int(hlen)); err != nil {
		return nil, fmt.Errorf("ccache: header: %w", err)
	}

	dflt, err := c.principal()
	if err != nil {
		return nil, fmt.Errorf("ccache: default principal: %w", err)
	}
	r := &Result{Version: "0x0504", DefaultPrincipal: dflt, TotalBytes: len(b)}

	for c.remaining() > 0 {
		cred, err := c.credential()
		if err != nil {
			return nil, err
		}
		r.Credentials = append(r.Credentials, cred)
	}
	if len(r.Credentials) == 0 {
		return nil, fmt.Errorf("ccache: no credentials found")
	}
	return r, nil
}

// principal parses a ccache principal: name_type(u32) + num_components(u32) +
// realm(counted) + components(counted…), formatted as comp/comp@REALM.
func (c *cursor) principal() (string, error) {
	if _, err := c.u32(); err != nil { // name_type
		return "", err
	}
	nComp, err := c.u32()
	if err != nil {
		return "", err
	}
	if nComp > maxCount {
		return "", fmt.Errorf("ccache: implausible component count %d", nComp)
	}
	realm, err := c.counted()
	if err != nil {
		return "", err
	}
	comps := make([]string, 0, nComp)
	for i := uint32(0); i < nComp; i++ {
		comp, err := c.counted()
		if err != nil {
			return "", err
		}
		comps = append(comps, string(comp))
	}
	return strings.Join(comps, "/") + "@" + string(realm), nil
}

// credential parses one ccache credential structure.
func (c *cursor) credential() (*Credential, error) {
	client, err := c.principal()
	if err != nil {
		return nil, fmt.Errorf("ccache: credential client: %w", err)
	}
	server, err := c.principal()
	if err != nil {
		return nil, fmt.Errorf("ccache: credential server: %w", err)
	}
	// keyblock: keytype(u16) + etype(u16) + keylen(u16) + key.
	keyType, err := c.u16()
	if err != nil {
		return nil, err
	}
	if _, err := c.u16(); err != nil { // etype (unused in 0x0504; kept for layout)
		return nil, err
	}
	key, err := c.counted16()
	if err != nil {
		return nil, fmt.Errorf("ccache: keyblock: %w", err)
	}
	authT, _ := c.u32()
	startT, _ := c.u32()
	endT, _ := c.u32()
	renewT, err := c.u32()
	if err != nil {
		return nil, fmt.Errorf("ccache: times: %w", err)
	}
	isSkey, err := c.u8()
	if err != nil {
		return nil, err
	}
	flags, err := c.u32()
	if err != nil {
		return nil, err
	}
	if err := c.skipCountedList(); err != nil { // addresses
		return nil, fmt.Errorf("ccache: addresses: %w", err)
	}
	if err := c.skipCountedList(); err != nil { // authdata
		return nil, fmt.Errorf("ccache: authdata: %w", err)
	}
	ticket, err := c.counted()
	if err != nil {
		return nil, fmt.Errorf("ccache: ticket: %w", err)
	}
	secondTicket, err := c.counted()
	if err != nil {
		return nil, fmt.Errorf("ccache: second ticket: %w", err)
	}

	cred := &Credential{
		Client:             client,
		Server:             server,
		KeyType:            int(keyType),
		KeyTypeName:        enctypeName(keyType),
		KeyHex:             hex.EncodeToString(key),
		AuthTimeUTC:        utc(authT),
		StartTimeUTC:       utc(startT),
		EndTimeUTC:         utc(endT),
		RenewTillUTC:       utc(renewT),
		TicketFlags:        flags,
		TicketFlagNames:    flagNames(flags),
		IsSkey:             isSkey != 0,
		TicketLength:       len(ticket),
		TicketHex:          hex.EncodeToString(ticket),
		SecondTicketLength: len(secondTicket),
	}
	if strings.HasPrefix(server, "krbtgt/") {
		cred.Note = "TGT (krbtgt) — usable for pass-the-ticket; the golden-ticket / delegation pivot"
	} else {
		cred.Note = "service ticket — usable for pass-the-ticket against this service"
	}
	return cred, nil
}

// skipCountedList skips an addresses/authdata list: count(u32) then count ×
// (type(u16) + counted_data).
func (c *cursor) skipCountedList() error {
	n, err := c.u32()
	if err != nil {
		return err
	}
	if n > maxCount {
		return fmt.Errorf("implausible count %d", n)
	}
	for i := uint32(0); i < n; i++ {
		if _, err := c.u16(); err != nil { // type
			return err
		}
		if _, err := c.counted(); err != nil {
			return err
		}
	}
	return nil
}

func utc(t uint32) string {
	if t == 0 {
		return ""
	}
	return time.Unix(int64(t), 0).UTC().Format(time.RFC3339)
}

// flagNames decodes the krb5 ticket flags (RFC 4120 §5.3 bit numbering, MSB
// first) into the canonical MIT klist letter set's long names.
func flagNames(f uint32) []string {
	type fl struct {
		bit  uint32
		name string
	}
	table := []fl{
		{0x40000000, "forwardable"}, {0x20000000, "forwarded"},
		{0x10000000, "proxiable"}, {0x08000000, "proxy"},
		{0x04000000, "may-postdate"}, {0x02000000, "postdated"},
		{0x01000000, "invalid"}, {0x00800000, "renewable"},
		{0x00400000, "initial"}, {0x00200000, "pre-authent"},
		{0x00100000, "hw-authent"}, {0x00080000, "transit-policy-checked"},
		{0x00040000, "ok-as-delegate"}, {0x00020000, "anonymous"},
	}
	var out []string
	for _, e := range table {
		if f&e.bit != 0 {
			out = append(out, e.name)
		}
	}
	return out
}

func enctypeName(e uint16) string {
	switch e {
	case 1:
		return "des-cbc-crc"
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
	}
	return ""
}

// cursor is a bounds-checked big-endian reader.
type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) remaining() int { return len(c.b) - c.pos }

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || c.pos+n > len(c.b) {
		return nil, fmt.Errorf("ccache: truncated (need %d bytes at offset %d)", n, c.pos)
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

// counted reads a uint32-length-prefixed octet string.
func (c *cursor) counted() ([]byte, error) {
	n, err := c.u32()
	if err != nil {
		return nil, err
	}
	return c.take(int(n))
}

// counted16 reads a uint16-length-prefixed octet string (the keyblock key).
func (c *cursor) counted16() ([]byte, error) {
	n, err := c.u16()
	if err != nil {
		return nil, err
	}
	return c.take(int(n))
}

// parseHex strips common separators / 0x prefix and decodes a hex string.
func parseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "",
		":", "", "-", "", "_", "", "0x", "", "0X", "").Replace(s)
	if s == "" {
		return nil, fmt.Errorf("ccache: empty input")
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("ccache: hex has odd length")
	}
	return hex.DecodeString(s)
}
