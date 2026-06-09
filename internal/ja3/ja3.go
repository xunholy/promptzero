// Package ja3 computes the JA3 TLS-client fingerprint from a captured
// ClientHello — the fingerprint format used across IDS / threat-intel tooling
// (Suricata, Zeek, every major EDR) to identify a TLS client (and the malware
// family behind it) independent of IP or SNI.
//
// JA3 (Althouse et al., Salesforce) concatenates five ClientHello fields —
//
//	SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
//
// — values dash-joined, fields comma-joined, then takes the MD5. GREASE values
// (RFC 8701) are removed from the cipher, extension, and curve lists so a
// client that randomises GREASE still fingerprints to one hash. This package
// implements that algorithm over the raw ClientHello wire bytes.
//
// Wrap-vs-native: native — a bounds-checked walk of the TLS record /
// handshake / ClientHello structure (RFC 5246 §7.4.1.2) + stdlib crypto/md5.
// No new go.mod dependency. The field extraction and GREASE filtering are
// pinned against the Salesforce reference implementation (pyja3) on a real
// openssl ClientHello and a hand-built GREASE-bearing one, and the string→MD5
// step against the two worked examples in the JA3 spec.
//
// Scope: JA3 (client). JA3S (the server-side ServerHello variant) is detected
// and reported as not-yet-supported rather than mis-fingerprinted.
package ja3

import (
	"crypto/md5" //nolint:gosec // MD5 is the JA3 fingerprint digest, fixed by the spec.
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Result is the outcome of a Decode / FromClientHello call.
type Result struct {
	// JA3 is the fingerprint string (the pre-hash field concatenation).
	JA3 string `json:"ja3"`
	// JA3Digest is the MD5 of JA3, lowercase hex.
	JA3Digest string `json:"ja3_digest"`
	// TLSVersion is the ClientHello legacy_version as a decimal (e.g. 771 =
	// 0x0303).
	TLSVersion int `json:"tls_version"`
	// Ciphers is the offered cipher-suite list, GREASE removed.
	Ciphers []int `json:"ciphers"`
	// Extensions is the extension-type list in appearance order, GREASE removed.
	Extensions []int `json:"extensions"`
	// Curves is the supported_groups (ext 10) list, GREASE removed.
	Curves []int `json:"curves"`
	// PointFormats is the ec_point_formats (ext 11) list.
	PointFormats []int `json:"point_formats"`
	// SNI is the server_name (ext 0), informational — not part of the JA3.
	SNI string `json:"sni,omitempty"`
	// Note carries interpretation guidance.
	Note string `json:"note,omitempty"`
}

// Decode accepts a ClientHello as a hex string — either a full TLS record
// (starting 0x16) or a bare handshake message (starting 0x01) — and returns its
// JA3. Whitespace and colons in the hex are ignored.
func Decode(hexInput string) (*Result, error) {
	clean := strings.NewReplacer(" ", "", "\n", "", "\t", "", "\r", "", ":", "").Replace(hexInput)
	if clean == "" {
		return nil, errors.New("empty input")
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("input is not valid hex: %w", err)
	}
	return FromClientHello(raw)
}

// FromClientHello computes the JA3 from raw ClientHello bytes. The input may be
// a full TLS record (record-layer header stripped) or a bare handshake message.
func FromClientHello(b []byte) (*Result, error) {
	hs, err := unwrap(b)
	if err != nil {
		return nil, err
	}
	if len(hs) < 4 {
		return nil, errors.New("truncated handshake header")
	}
	switch hs[0] {
	case 0x01: // ClientHello
	case 0x02:
		return nil, errors.New("this is a ServerHello (handshake type 2); JA3S is not yet supported")
	default:
		return nil, fmt.Errorf("not a ClientHello (handshake type %d)", hs[0])
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	body := hs[4:]
	if hsLen > len(body) {
		return nil, fmt.Errorf("handshake length %d exceeds %d available bytes (fragmented capture?)", hsLen, len(body))
	}
	body = body[:hsLen]
	return parseBody(body)
}

// unwrap strips a TLS record-layer header (0x16 = handshake) if present,
// returning the handshake bytes; otherwise it returns the input unchanged.
func unwrap(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("no bytes")
	}
	if b[0] == 0x16 { // TLS record, content type = handshake
		if len(b) < 5 {
			return nil, errors.New("truncated TLS record header")
		}
		recLen := int(b[3])<<8 | int(b[4])
		rest := b[5:]
		if recLen <= len(rest) {
			rest = rest[:recLen]
		}
		return rest, nil
	}
	return b, nil
}

// parseBody walks the ClientHello body and assembles the JA3.
func parseBody(body []byte) (*Result, error) {
	c := &cursor{b: body}
	res := &Result{}

	ver, err := c.u16()
	if err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	res.TLSVersion = int(ver)

	if err := c.skip(32); err != nil { // random
		return nil, fmt.Errorf("random: %w", err)
	}
	if err := c.skipVec8(); err != nil { // session_id
		return nil, fmt.Errorf("session_id: %w", err)
	}

	cipherBytes, err := c.vec16()
	if err != nil {
		return nil, fmt.Errorf("cipher_suites: %w", err)
	}
	res.Ciphers = u16ListNoGREASE(cipherBytes)

	if err := c.skipVec8(); err != nil { // compression_methods
		return nil, fmt.Errorf("compression: %w", err)
	}

	// Extensions are optional (SSLv3-era hellos omit them entirely).
	if c.remaining() > 0 {
		extBlock, err := c.vec16()
		if err != nil {
			return nil, fmt.Errorf("extensions: %w", err)
		}
		if err := parseExtensions(extBlock, res); err != nil {
			return nil, err
		}
	}

	res.JA3 = buildString(res)
	sum := md5.Sum([]byte(res.JA3)) //nolint:gosec // JA3 digest.
	res.JA3Digest = hex.EncodeToString(sum[:])
	res.Note = "JA3 client fingerprint. GREASE values (RFC 8701) are removed from " +
		"ciphers/extensions/curves; the digest identifies the TLS client stack, not the host."
	return res, nil
}

// parseExtensions walks the extension TLV block, recording extension types
// (GREASE removed) and the supported_groups / ec_point_formats / server_name
// contents.
func parseExtensions(block []byte, res *Result) error {
	ec := &cursor{b: block}
	for ec.remaining() > 0 {
		extType, err := ec.u16()
		if err != nil {
			return fmt.Errorf("extension type: %w", err)
		}
		data, err := ec.vec16()
		if err != nil {
			return fmt.Errorf("extension %d body: %w", extType, err)
		}
		if !isGREASE(extType) {
			res.Extensions = append(res.Extensions, int(extType))
		}
		switch extType {
		case 0x000a: // supported_groups: uint16 list, length-prefixed
			if inner, err := vec16Of(data); err == nil {
				res.Curves = u16ListNoGREASE(inner)
			}
		case 0x000b: // ec_point_formats: uint8 list, length-prefixed
			if inner, err := vec8Of(data); err == nil {
				res.PointFormats = u8List(inner)
			}
		case 0x0000: // server_name
			res.SNI = parseSNI(data)
		}
	}
	return nil
}

// buildString assembles the JA3 field concatenation.
func buildString(res *Result) string {
	return strings.Join([]string{
		strconv.Itoa(res.TLSVersion),
		joinInts(res.Ciphers),
		joinInts(res.Extensions),
		joinInts(res.Curves),
		joinInts(res.PointFormats),
	}, ",")
}

// isGREASE reports whether v is one of the 16 RFC 8701 GREASE values
// (0x0a0a, 0x1a1a, … 0xfafa): the two bytes are equal and the low nibble of
// each is 0xa.
func isGREASE(v uint16) bool {
	hi, lo := byte(v>>8), byte(v)
	return hi == lo && hi&0x0f == 0x0a
}

// u16ListNoGREASE reads a flat list of uint16 values, dropping GREASE. A
// trailing odd byte is ignored.
func u16ListNoGREASE(b []byte) []int {
	out := []int{}
	for i := 0; i+1 < len(b); i += 2 {
		v := uint16(b[i])<<8 | uint16(b[i+1])
		if !isGREASE(v) {
			out = append(out, int(v))
		}
	}
	return out
}

// u8List reads a flat list of uint8 values.
func u8List(b []byte) []int {
	out := make([]int, len(b))
	for i, x := range b {
		out[i] = int(x)
	}
	return out
}

// parseSNI extracts the first host_name from a server_name extension body.
func parseSNI(data []byte) string {
	inner, err := vec16Of(data) // ServerNameList
	if err != nil || len(inner) < 3 {
		return ""
	}
	// inner: name_type(1) + HostName(vec16).
	if inner[0] != 0 {
		return ""
	}
	name, err := vec16Of(inner[1:])
	if err != nil {
		return ""
	}
	return string(name)
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, "-")
}

// cursor is a bounds-checked byte reader over a TLS structure.
type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) remaining() int { return len(c.b) - c.pos }

func (c *cursor) skip(n int) error {
	if c.pos+n > len(c.b) {
		return errors.New("out of bounds")
	}
	c.pos += n
	return nil
}

func (c *cursor) u16() (uint16, error) {
	if c.pos+2 > len(c.b) {
		return 0, errors.New("out of bounds")
	}
	v := uint16(c.b[c.pos])<<8 | uint16(c.b[c.pos+1])
	c.pos += 2
	return v, nil
}

// vec16 reads a uint16-length-prefixed byte slice.
func (c *cursor) vec16() ([]byte, error) {
	n, err := c.u16()
	if err != nil {
		return nil, err
	}
	if c.pos+int(n) > len(c.b) {
		return nil, errors.New("length exceeds buffer")
	}
	v := c.b[c.pos : c.pos+int(n)]
	c.pos += int(n)
	return v, nil
}

// skipVec8 skips a uint8-length-prefixed field.
func (c *cursor) skipVec8() error {
	if c.pos >= len(c.b) {
		return errors.New("out of bounds")
	}
	n := int(c.b[c.pos])
	c.pos++
	return c.skip(n)
}

// vec16Of reads a uint16-length-prefixed slice from the front of b.
func vec16Of(b []byte) ([]byte, error) {
	if len(b) < 2 {
		return nil, errors.New("too short")
	}
	n := int(b[0])<<8 | int(b[1])
	if 2+n > len(b) {
		return nil, errors.New("length exceeds buffer")
	}
	return b[2 : 2+n], nil
}

// vec8Of reads a uint8-length-prefixed slice from the front of b.
func vec8Of(b []byte) ([]byte, error) {
	if len(b) < 1 {
		return nil, errors.New("too short")
	}
	n := int(b[0])
	if 1+n > len(b) {
		return nil, errors.New("length exceeds buffer")
	}
	return b[1 : 1+n], nil
}
