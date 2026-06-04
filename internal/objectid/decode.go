// SPDX-License-Identifier: AGPL-3.0-or-later

// Package objectid decodes a MongoDB ObjectId into its embedded fields — most
// usefully its **creation timestamp**. A 12-byte ObjectId is the default _id of
// every MongoDB document, and it is not opaque: its first four bytes are the
// Unix-second creation time. ObjectIds leak into URLs, REST API parameters,
// logs, and exported documents, so a captured ObjectId reveals when its record
// was created (and, via the trailing counter, supports record-enumeration /
// timing inference). This is the MongoDB analogue of uuid_decode's
// timestamp/info extraction, and the completion of the ObjectId rendering in
// mongodb_decode / bson_decode (which surface it only as raw hex). Pure offline
// transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. An ObjectId is 12 bytes with a fixed layout (BSON spec): a 4-byte
// big-endian Unix-second timestamp, a 5-byte per-process random value, and a
// 3-byte big-endian counter. Decoding is hex parsing + a uint32 read — there is
// nothing to wrap. Consistent with the other in-tree identifier decoders
// (internal/uuidinfo).
//
// # Verifiable / no confidently-wrong output
//
// The timestamp — the one recoverable, security-relevant field — is anchored to
// the reference pymongo `ObjectId.generation_time`: 507f1f77bcf86cd799439011 →
// 2012-10-17T21:13:27Z, 65a1b2c3d4e5f60718293a4b → 2024-01-12T21:44:35Z. The
// random and counter fields are surfaced raw (hex / integer); the legacy
// pre-3.4 machine-id/process-id split of those bytes is deprecated and
// deliberately NOT asserted (it would be a confidently-wrong interpretation on a
// modern ObjectId). A string that is not exactly 24 hex digits is rejected.
package objectid

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Result is the decoded view of a MongoDB ObjectId.
type Result struct {
	ObjectID     string `json:"objectid"` // canonical lowercase 24-hex
	TimestampUTC string `json:"timestamp_utc"`
	UnixSeconds  int64  `json:"unix_seconds"`
	RandomHex    string `json:"random_hex"` // bytes 4-8 (5-byte per-process value)
	Counter      int    `json:"counter"`    // bytes 9-11 (3-byte big-endian)
	Note         string `json:"note,omitempty"`
}

// Decode parses a 24-hex-character MongoDB ObjectId (optionally wrapped in
// ObjectId("…") / quotes) into its timestamp, random, and counter fields.
func Decode(in string) (*Result, error) {
	h := normalize(in)
	if len(h) != 24 {
		return nil, fmt.Errorf("objectid: not an ObjectId (need 24 hex digits, got %d)", len(h))
	}
	b := make([]byte, 12)
	for i := 0; i < 12; i++ {
		v, ok := hexByte(h[2*i], h[2*i+1])
		if !ok {
			return nil, fmt.Errorf("objectid: invalid hex in ObjectId")
		}
		b[i] = v
	}
	secs := int64(binary.BigEndian.Uint32(b[0:4]))
	counter := int(b[9])<<16 | int(b[10])<<8 | int(b[11])
	return &Result{
		ObjectID:     h,
		TimestampUTC: time.Unix(secs, 0).UTC().Format(time.RFC3339),
		UnixSeconds:  secs,
		RandomHex:    fmt.Sprintf("%x", b[4:9]),
		Counter:      counter,
		Note: "MongoDB ObjectId: bytes 0-3 = creation timestamp (the recoverable field), bytes 4-8 = a " +
			"5-byte per-process random value, bytes 9-11 = a 3-byte incrementing counter (current BSON spec). " +
			"The legacy pre-3.4 machine-id/process-id split of bytes 4-8 is deprecated and not asserted here.",
	}, nil
}

// normalize strips an optional ObjectId("…") wrapper, quotes, and whitespace,
// and lowercases, returning the bare hex.
func normalize(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "objectid(")
	s = strings.TrimSuffix(s, ")")
	s = strings.Trim(s, `"'`)
	return s
}

func hexByte(hi, lo byte) (byte, bool) {
	h, ok1 := hexNibble(hi)
	l, ok2 := hexNibble(lo)
	return h<<4 | l, ok1 && ok2
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	default:
		return 0, false
	}
}
