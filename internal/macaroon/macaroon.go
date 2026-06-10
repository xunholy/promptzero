// Package macaroon decodes macaroon authorization credentials from their
// libmacaroons binary serialization (v1 packet format and v2 binary format).
//
// It is a read-only parser: it recovers the location, identifier, caveats, and
// signature so a caller can inspect a captured macaroon — for example a leaked
// PyPI API token (see internal/pypitoken) — without the issuing HMAC secret. It
// deliberately does NOT verify the macaroon's signature chain: that requires the
// root key, which loot never carries, and a decoder that claimed verification
// from the token alone would be confidently wrong.
//
// Wrap-vs-native: native — both layouts are a short run of length-prefixed
// fields, decoded with the stdlib (encoding/binary varint) and no new go.mod
// dep. The format is rescrv/libmacaroons doc/format.txt; the parser is anchored
// to the cross-implementation vectors in pymacaroons'
// tests/functional_tests/serialization_tests.py (see macaroon_test.go).
package macaroon

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// v2 field-type tags, per rescrv/libmacaroons doc/format.txt.
const (
	v2FieldEOS        = 0
	v2FieldLocation   = 1
	v2FieldIdentifier = 2
	v2FieldVID        = 4
	v2FieldSignature  = 6
)

// Caveat is one macaroon caveat. A first-party caveat (VID empty) carries only
// an ID — for PyPI that ID is a JSON-encoded restriction. A third-party caveat
// additionally carries a Location and a verification key ID (VID).
type Caveat struct {
	Location string
	ID       []byte
	VID      []byte
}

// FirstParty reports whether c is a first-party caveat (no verification key ID).
func (c Caveat) FirstParty() bool { return len(c.VID) == 0 }

// Macaroon is a decoded macaroon. Signature is the raw HMAC bytes; the parser
// does not verify it (the root key is not present in a captured token).
type Macaroon struct {
	Version    int
	Location   string
	Identifier []byte
	Caveats    []Caveat
	Signature  []byte
}

// Decode parses a macaroon from its raw (already base64-decoded) binary form,
// auto-detecting v1 vs v2 the same way libmacaroons does: a leading byte of
// 0x02 is the v2 binary format; a leading ASCII hex digit is the v1 packet
// format. Use DecodeBase64 for the base64-wrapped form tokens ship in.
func Decode(raw []byte) (*Macaroon, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty macaroon")
	}
	switch {
	case raw[0] == 2:
		return decodeV2(raw)
	case isASCIIHex(raw[0]):
		return decodeV1(raw)
	default:
		return nil, fmt.Errorf("unrecognised macaroon format (leading byte 0x%02x)", raw[0])
	}
}

// isASCIIHex reports whether b is an ASCII hex digit, the v1 length-prefix
// alphabet ('0'-'9', 'a'-'f', 'A'-'F').
func isASCIIHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// decodeV1 parses the v1 packet format: a flat sequence of packets, each a
// 4-char ASCII-hex length prefix (counting the prefix itself and the trailing
// newline) followed by "key value\n". Keys: location, identifier, cid, vid, cl,
// signature.
func decodeV1(raw []byte) (*Macaroon, error) {
	m := &Macaroon{Version: 1}
	for i := 0; i < len(raw); {
		if i+4 > len(raw) {
			return nil, errors.New("v1: truncated packet length prefix")
		}
		n, err := parseHex4(raw[i : i+4])
		if err != nil {
			return nil, fmt.Errorf("v1: %w", err)
		}
		// The minimum legal packet is "0006 \n" (prefix + space + newline);
		// anything shorter than the 4-byte prefix can never terminate, so
		// guard against a zero/short length to keep the loop finite.
		if n < 4 || i+n > len(raw) {
			return nil, fmt.Errorf("v1: packet length %d out of range at offset %d", n, i)
		}
		body := raw[i+4 : i+n]
		key, val, err := depacketizeV1(body)
		if err != nil {
			return nil, err
		}
		if err := m.applyV1(key, val); err != nil {
			return nil, err
		}
		i += n
	}
	return m, nil
}

// depacketizeV1 splits a v1 packet body ("key value\n") into its key and value,
// stripping the trailing newline from the value.
func depacketizeV1(body []byte) (key, val []byte, err error) {
	sp := -1
	for i, b := range body {
		if b == ' ' {
			sp = i
			break
		}
	}
	if sp < 0 {
		return nil, nil, errors.New("v1: packet missing key/value separator")
	}
	key = body[:sp]
	val = body[sp+1:]
	if len(val) == 0 || val[len(val)-1] != '\n' {
		return nil, nil, errors.New("v1: packet value missing trailing newline")
	}
	return key, val[:len(val)-1], nil
}

// applyV1 stores one decoded v1 packet on the macaroon. A cid opens a new
// caveat; vid and cl attach to the most recently opened caveat.
func (m *Macaroon) applyV1(key, val []byte) error {
	switch string(key) {
	case "location":
		m.Location = string(val)
	case "identifier":
		m.Identifier = append([]byte(nil), val...)
	case "cid":
		m.Caveats = append(m.Caveats, Caveat{ID: append([]byte(nil), val...)})
	case "vid":
		if len(m.Caveats) == 0 {
			return errors.New("v1: vid before any caveat")
		}
		m.Caveats[len(m.Caveats)-1].VID = append([]byte(nil), val...)
	case "cl":
		if len(m.Caveats) == 0 {
			return errors.New("v1: cl before any caveat")
		}
		m.Caveats[len(m.Caveats)-1].Location = string(val)
	case "signature":
		m.Signature = append([]byte(nil), val...)
	default:
		return fmt.Errorf("v1: unknown packet key %q", key)
	}
	return nil
}

// parseHex4 decodes a 4-byte ASCII-hex length prefix.
func parseHex4(b []byte) (int, error) {
	n := 0
	for _, c := range b {
		d, err := hexVal(c)
		if err != nil {
			return 0, err
		}
		n = n<<4 | d
	}
	return n, nil
}

// hexVal returns the numeric value of an ASCII hex digit.
func hexVal(c byte) (int, error) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), nil
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, nil
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex digit 0x%02x", c)
	}
}

// decodeV2 parses the v2 binary format:
//
//	VERSION(0x02) [LOCATION] IDENTIFIER EOS  (caveat)* EOS  SIGNATURE
//
// where each field is `field-type:varuint  length:varuint  data` and EOS is a
// single zero byte ending a section. Each caveat is its own section of
// `[LOCATION] IDENTIFIER [VID]`.
func decodeV2(raw []byte) (*Macaroon, error) {
	r := &reader{buf: raw[1:]} // skip the version byte
	m := &Macaroon{Version: 2}

	header, err := r.section()
	if err != nil {
		return nil, fmt.Errorf("v2: header: %w", err)
	}
	if len(header) > 0 && header[0].typ == v2FieldLocation {
		m.Location = string(header[0].data)
		header = header[1:]
	}
	if len(header) != 1 || header[0].typ != v2FieldIdentifier {
		return nil, errors.New("v2: invalid macaroon header")
	}
	m.Identifier = header[0].data

	for {
		sect, err := r.section()
		if err != nil {
			return nil, fmt.Errorf("v2: caveats: %w", err)
		}
		if len(sect) == 0 {
			break // the empty section terminates the caveat list
		}
		cav, err := caveatFromSection(sect)
		if err != nil {
			return nil, fmt.Errorf("v2: %w", err)
		}
		m.Caveats = append(m.Caveats, cav)
	}

	sig, err := r.packet()
	if err != nil {
		return nil, fmt.Errorf("v2: signature: %w", err)
	}
	if sig.typ != v2FieldSignature {
		return nil, fmt.Errorf("v2: expected signature field, got type %d", sig.typ)
	}
	m.Signature = sig.data
	return m, nil
}

// caveatFromSection builds a Caveat from a parsed v2 section
// ([LOCATION] IDENTIFIER [VID]).
func caveatFromSection(sect []packet) (Caveat, error) {
	var cav Caveat
	if len(sect) > 0 && sect[0].typ == v2FieldLocation {
		cav.Location = string(sect[0].data)
		sect = sect[1:]
	}
	if len(sect) == 0 || sect[0].typ != v2FieldIdentifier {
		return Caveat{}, errors.New("caveat missing identifier")
	}
	cav.ID = sect[0].data
	sect = sect[1:]
	if len(sect) == 0 {
		if cav.Location != "" {
			return Caveat{}, errors.New("location not allowed in first-party caveat")
		}
		return cav, nil
	}
	if len(sect) != 1 || sect[0].typ != v2FieldVID {
		return Caveat{}, errors.New("unexpected field in caveat")
	}
	cav.VID = sect[0].data
	return cav, nil
}

// packet is one decoded v2 field.
type packet struct {
	typ  int
	data []byte
}

// reader walks a v2 byte buffer.
type reader struct {
	buf []byte
}

// section reads packets until an EOS byte, returning the packets before it.
func (r *reader) section() ([]packet, error) {
	var out []packet
	prevType := -1
	for {
		if len(r.buf) == 0 {
			return nil, errors.New("section extends past end of buffer")
		}
		p, err := r.packet()
		if err != nil {
			return nil, err
		}
		if p.typ == v2FieldEOS {
			return out, nil
		}
		if p.typ <= prevType {
			return nil, errors.New("fields out of order")
		}
		out = append(out, p)
		prevType = p.typ
	}
}

// packet reads a single v2 packet: field-type varuint, then (unless EOS) a
// length varuint and that many payload bytes.
func (r *reader) packet() (packet, error) {
	ft, n := binary.Uvarint(r.buf)
	if n <= 0 {
		return packet{}, errors.New("malformed field-type varint")
	}
	r.buf = r.buf[n:]
	if ft == v2FieldEOS {
		return packet{typ: v2FieldEOS}, nil
	}
	plen, n := binary.Uvarint(r.buf)
	if n <= 0 {
		return packet{}, errors.New("malformed field-length varint")
	}
	r.buf = r.buf[n:]
	if plen > uint64(len(r.buf)) {
		return packet{}, errors.New("field data extends past end of buffer")
	}
	data := r.buf[:plen]
	r.buf = r.buf[plen:]
	return packet{typ: int(ft), data: data}, nil
}
