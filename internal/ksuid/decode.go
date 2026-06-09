// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ksuid decodes a KSUID (K-Sortable Unique IDentifier — the
// segmentio/ksuid format) into its embedded creation timestamp and random
// payload. A KSUID is a 27-character base62 string encoding 20 bytes: a 4-byte
// big-endian timestamp (seconds since a custom 2014 epoch) followed by 16 bytes
// of randomness. Like a UUIDv1/v7, a MongoDB ObjectId, a ULID, or a Snowflake,
// a KSUID is NOT opaque — its leading bytes leak the creation time of whatever
// it identifies (tokens, request IDs, database keys, URLs, logs), and its
// lexicographic sortability aids record enumeration. Widely used by Go backends
// (Segment and others). Pure offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. Decoding a KSUID is a base62 → 160-bit conversion (math/big) then a
// 4-byte big-endian read + an epoch add — a few lines of arithmetic, nothing to
// wrap. Consistent with the in-tree identifier decoders (internal/uuidinfo,
// internal/objectid, internal/ulid, internal/snowflake), which this completes.
//
// # Verifiable / no confidently-wrong output
//
// Unlike a Snowflake, a KSUID is unambiguous — there is one published format and
// one epoch — so the decode is a single asserted answer, not a candidate set.
// The layout, the base62 alphabet, and the epoch are taken from the
// segmentio/ksuid reference, and the decode is anchored to that project's own
// documented example: 0ujtsYcgvSTl8PAuAdqWYSMnLOv → raw
// 0669F7EFB5A1CD34B5F99D1154FB6853345C9735, timestamp field 0x0669F7EF
// (107608047) + epoch → 2017-10-10T04:00:47Z, payload
// B5A1CD34B5F99D1154FB6853345C9735. Input must be exactly 27 base62 characters
// whose 160-bit value fits in 20 bytes; a wrong length, an out-of-alphabet
// character, or a value exceeding the KSUID range is rejected rather than
// mis-decoded.
package ksuid

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	// ksuidEpoch is the KSUID epoch in Unix seconds (2014-05-13T16:53:20Z).
	// segmentio/ksuid offsets the 32-bit timestamp from here so the usable
	// range extends to ~2150 instead of 2106.
	ksuidEpoch int64 = 1400000000
	// encodedLen is the fixed KSUID string length; rawLen / payloadLen are the
	// decoded byte and random-tail lengths.
	encodedLen = 27
	rawLen     = 20
	payloadLen = 16
)

// base62Alphabet is the KSUID base62 digit set (segmentio/ksuid): decimal
// digits, then uppercase, then lowercase — a character's value is its index.
const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// base62Index maps each byte to its base62 value, or -1 when it is not a
// base62 digit. Built once at package init.
var base62Index = func() [256]int {
	var idx [256]int
	for i := range idx {
		idx[i] = -1
	}
	for i := 0; i < len(base62Alphabet); i++ {
		idx[base62Alphabet[i]] = i
	}
	return idx
}()

// Result is the decoded view of a KSUID.
type Result struct {
	// Ksuid is the input string (trimmed).
	Ksuid string `json:"ksuid"`
	// RawHex is the 20-byte decoded value, uppercase hex, no separators.
	RawHex string `json:"raw_hex"`
	// Timestamp is the raw 32-bit timestamp field (seconds since the KSUID
	// epoch, before the epoch is added).
	Timestamp uint32 `json:"timestamp"`
	// UnixSeconds is Timestamp + the KSUID epoch (seconds since 1970).
	UnixSeconds int64 `json:"unix_seconds"`
	// TimestampUTC is the creation time in RFC 3339 UTC — the recon value.
	TimestampUTC string `json:"timestamp_utc"`
	// PayloadHex is the 16-byte random payload, uppercase hex.
	PayloadHex string `json:"payload_hex"`
}

// Decode parses a 27-character base62 KSUID string into its timestamp and
// payload. A wrong length, an out-of-alphabet character, or a 160-bit value
// that overflows 20 bytes is rejected.
func Decode(s string) (*Result, error) {
	id := strings.TrimSpace(s)
	if len(id) != encodedLen {
		return nil, fmt.Errorf("ksuid: %q is %d characters, want %d", s, len(id), encodedLen)
	}

	// Parse the string as a base62 number (most-significant digit first).
	v := new(big.Int)
	sixtyTwo := big.NewInt(62)
	for i := 0; i < len(id); i++ {
		d := base62Index[id[i]]
		if d < 0 {
			return nil, fmt.Errorf("ksuid: invalid base62 character %q at position %d", string(id[i]), i)
		}
		v.Mul(v, sixtyTwo)
		v.Add(v, big.NewInt(int64(d)))
	}

	raw := v.Bytes() // big-endian, minimal length
	if len(raw) > rawLen {
		return nil, fmt.Errorf("ksuid: %q decodes to %d bytes, exceeds the 160-bit KSUID range", s, len(raw))
	}
	// Left-pad to the fixed 20-byte width.
	buf := make([]byte, rawLen)
	copy(buf[rawLen-len(raw):], raw)

	ts := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
	unix := int64(ts) + ksuidEpoch
	return &Result{
		Ksuid:        id,
		RawHex:       strings.ToUpper(hex.EncodeToString(buf)),
		Timestamp:    ts,
		UnixSeconds:  unix,
		TimestampUTC: time.Unix(unix, 0).UTC().Format(time.RFC3339),
		PayloadHex:   strings.ToUpper(hex.EncodeToString(buf[rawLen-payloadLen:])),
	}, nil
}
