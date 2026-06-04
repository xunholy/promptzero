// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ulid decodes a ULID (Universally Unique Lexicographically Sortable
// Identifier) into its embedded creation timestamp and randomness. A ULID is a
// 26-character Crockford-base32 string encoding 128 bits — a 48-bit
// millisecond Unix timestamp followed by 80 bits of randomness — and is widely
// used by modern backends as a sortable, UUID-sized identifier (the spec's
// answer to UUIDv4, and a peer of UUIDv7). Like a UUIDv1/v7 or a MongoDB
// ObjectId, a ULID is NOT opaque: it leaks the **creation time** of whatever it
// identifies, and its lexicographic sortability aids record enumeration. This
// completes the identifier-timestamp triad with internal/uuidinfo and
// internal/objectid. Pure offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. A ULID is Crockford base32 over a fixed 128-bit layout: decode the 26
// characters to 16 bytes, then the first 6 bytes are the big-endian millisecond
// timestamp and the last 10 are the randomness. It is a base-32 decode + a
// uint48 read — there is nothing to wrap, and no ULID type exists in the Go
// stdlib. Consistent with the other in-tree identifier decoders.
//
// # Verifiable / no confidently-wrong output
//
// Anchored to the reference python-ulid library AND hand-verified: the canonical
// ULID 01ARZ3NDEKTSV4RRFFQ69G5FAV decodes to 1469922850259 ms
// (2016-07-30T23:54:10.259Z) — confirmed both by the library and by manually
// Crockford-decoding its first ten characters. The all-zero ULID decodes to the
// Unix epoch. Input is rejected unless it is exactly 26 Crockford-base32
// characters whose first character is 0-7 (a larger first character would
// overflow 128 bits — the spec's max ULID is 7ZZ…).
package ulid

import (
	"fmt"
	"math/big"
	"strings"
	"time"
)

// crockford is the Crockford base-32 alphabet used by ULID (no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Result is the decoded view of a ULID.
type Result struct {
	ULID          string `json:"ulid"` // canonical uppercase
	TimestampUTC  string `json:"timestamp_utc"`
	UnixMillis    int64  `json:"unix_millis"`
	RandomnessHex string `json:"randomness_hex"` // 80-bit / 10-byte tail
	Note          string `json:"note,omitempty"`
}

// decodeTable maps a Crockford character (upper-cased) to its 5-bit value, or
// -1 if it is not in the alphabet.
var decodeTable = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(crockford); i++ {
		t[crockford[i]] = int8(i)
	}
	return t
}()

// Decode parses a 26-character ULID into its millisecond timestamp and
// 80-bit randomness.
func Decode(in string) (*Result, error) {
	s := strings.ToUpper(strings.TrimSpace(in))
	if len(s) != 26 {
		return nil, fmt.Errorf("ulid: not a ULID (need 26 Crockford-base32 chars, got %d)", len(s))
	}
	// Accumulate the 130-bit value (26×5) into a big.Int; the first character
	// must be 0-7 so the result fits 128 bits.
	if decodeTable[s[0]] < 0 || decodeTable[s[0]] > 7 {
		return nil, fmt.Errorf("ulid: first character %q is invalid (must be 0-7; a larger value overflows 128 bits)", string(s[0]))
	}
	v := new(big.Int)
	for i := 0; i < len(s); i++ {
		d := decodeTable[s[i]]
		if d < 0 {
			return nil, fmt.Errorf("ulid: character %q is not in the Crockford base-32 alphabet (no I/L/O/U)", string(s[i]))
		}
		v.Lsh(v, 5)
		v.Or(v, big.NewInt(int64(d)))
	}
	var b [16]byte
	v.FillBytes(b[:]) // big-endian, left-zero-padded to 16 bytes

	ms := int64(b[0])<<40 | int64(b[1])<<32 | int64(b[2])<<24 | int64(b[3])<<16 | int64(b[4])<<8 | int64(b[5])
	return &Result{
		ULID:          s,
		UnixMillis:    ms,
		TimestampUTC:  time.UnixMilli(ms).UTC().Format(time.RFC3339Nano),
		RandomnessHex: fmt.Sprintf("%x", b[6:16]),
		Note: "ULID: the leading 48 bits are the millisecond creation timestamp (recoverable, and the " +
			"basis of ULID's lexicographic sortability — useful for record time-ordering / enumeration); the " +
			"trailing 80 bits are randomness.",
	}, nil
}
