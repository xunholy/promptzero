// SPDX-License-Identifier: AGPL-3.0-or-later

// Package uuidinfo decodes a UUID/GUID into its structure and — crucially for
// recon — any information it leaks. A version-1 (or version-6) UUID embeds the
// **generating host's MAC address** and the **creation timestamp**; a version-7
// UUID embeds a millisecond creation timestamp. These appear in tokens, API
// responses, email Message-IDs, filenames, database keys, and session
// identifiers, so a UUID captured in any of those deanonymizes the host that
// minted it (the classic "UUIDv1 leaks the MAC + time" finding) and time-orders
// records for enumeration. Pure offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. A UUID is 16 bytes with a fixed RFC 9562 (formerly RFC 4122) bit
// layout: a 4-bit version nibble, a 2-3 bit variant, and per-version timestamp /
// node / clock-sequence fields. Decoding is hex parsing + bit/field extraction +
// a gregorian↔unix epoch shift — there is nothing to wrap, and the Go stdlib has
// no UUID type. Distinct from internal/btuuid, which looks up Bluetooth GATT
// service UUIDs (a different, assigned-numbers concern). Consistent with the
// other in-tree identifier/loot decoders.
//
// # Verifiable / no confidently-wrong output
//
// Anchored to Python's reference `uuid` module: the v1 example decodes to its
// exact version / variant / node / clock-sequence and UTC timestamp
// (2006-06-10T10:48:31.013993Z, node 00:11:24:44:be:1e), v3/v4/v5/v7 to their
// versions, and the v7 48-bit millisecond timestamp to its exact UTC instant.
// v6 (which the reference module does not timestamp-decode) is cross-checked
// against v1 by field-reordering the same known instant. Versions that embed no
// recoverable data (v3/v5 name hashes, v4 random) say so rather than inventing a
// timestamp; the MAC-leak assessment is gated on the IEEE multicast bit, so a
// randomized node is never reported as a hardware address. A non-UUID string is
// rejected.
package uuidinfo

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// gregorianEpoch100ns is the count of 100-nanosecond intervals between the UUID
// epoch (1582-10-15 00:00:00 UTC) and the Unix epoch (1970-01-01).
const gregorianEpoch100ns = 0x01b21dd213814000

// Result is the decoded view of a UUID.
type Result struct {
	UUID        string `json:"uuid"`    // canonical 8-4-4-4-12 lowercase
	Version     int    `json:"version"` // 1..8; 0 = nil/max/unversioned
	VersionName string `json:"version_name"`
	Variant     string `json:"variant"`

	TimestampUTC string `json:"timestamp_utc,omitempty"` // v1 / v6 / v7
	UnixMillis   int64  `json:"unix_millis,omitempty"`
	Node         string `json:"node,omitempty"` // v1 / v6 — colon MAC form
	NodeIsMAC    bool   `json:"node_is_mac,omitempty"`
	ClockSeq     int    `json:"clock_seq,omitempty"` // v1 / v6

	Note string `json:"note,omitempty"`
}

// Decode parses a UUID in any common textual form (8-4-4-4-12 dashed, 32 bare
// hex, urn:uuid: prefixed, or {brace}-wrapped) and reports its structure.
func Decode(in string) (*Result, error) {
	h := normalize(in)
	if len(h) != 32 {
		return nil, fmt.Errorf("uuidinfo: not a UUID (need 32 hex digits, got %d)", len(h))
	}
	b := make([]byte, 16)
	for i := 0; i < 16; i++ {
		v, ok := hexByte(h[2*i], h[2*i+1])
		if !ok {
			return nil, fmt.Errorf("uuidinfo: invalid hex in UUID")
		}
		b[i] = v
	}
	r := &Result{UUID: canonical(h)}

	// Nil / max special cases (RFC 9562 §5.9, §5.10).
	if allEqual(b, 0x00) {
		r.VersionName, r.Variant, r.Note = "nil UUID", "n/a", "the all-zero UUID — carries no information"
		return r, nil
	}
	if allEqual(b, 0xff) {
		r.VersionName, r.Variant, r.Note = "max UUID", "n/a", "the all-ones UUID — carries no information"
		return r, nil
	}

	r.Version = int(b[6] >> 4)
	r.Variant = variant(b[8])

	switch r.Version {
	case 1:
		r.VersionName = "time-based (v1)"
		decodeV1(r, b)
	case 2:
		r.VersionName = "DCE security (v2)"
		r.Note = "DCE-security UUID — embeds a POSIX UID/GID and a partial timestamp; rarely used and not fully decoded here."
	case 3:
		r.VersionName = "name-based MD5 (v3)"
		r.Note = "MD5 hash of a namespace + name — carries no recoverable timestamp or node."
	case 4:
		r.VersionName = "random (v4)"
		r.Note = "random — carries no recoverable timestamp or node."
	case 5:
		r.VersionName = "name-based SHA-1 (v5)"
		r.Note = "SHA-1 hash of a namespace + name — carries no recoverable timestamp or node."
	case 6:
		r.VersionName = "time-ordered (v6)"
		decodeV6(r, b)
	case 7:
		r.VersionName = "unix-time-ordered (v7)"
		decodeV7(r, b)
	case 8:
		r.VersionName = "custom (v8)"
		r.Note = "vendor/custom layout — no standard fields to decode."
	default:
		r.VersionName = fmt.Sprintf("unknown (v%d)", r.Version)
	}
	return r, nil
}

// decodeV1 extracts the 60-bit gregorian timestamp, the node, and the clock
// sequence from a version-1 UUID.
func decodeV1(r *Result, b []byte) {
	timeLow := uint64(binary.BigEndian.Uint32(b[0:4]))
	timeMid := uint64(binary.BigEndian.Uint16(b[4:6]))
	timeHi := uint64(binary.BigEndian.Uint16(b[6:8]) & 0x0fff)
	ticks := timeHi<<48 | timeMid<<32 | timeLow
	setGregorianTime(r, ticks)
	setNode(r, b)
	r.ClockSeq = int(uint16(b[8]&0x3f)<<8 | uint16(b[9]))
}

// decodeV6 extracts the 60-bit timestamp from a version-6 UUID, whose fields are
// the v1 fields re-ordered most-significant-first for sortability (RFC 9562 §5.6).
func decodeV6(r *Result, b []byte) {
	timeHigh := uint64(binary.BigEndian.Uint32(b[0:4]))
	timeMid := uint64(binary.BigEndian.Uint16(b[4:6]))
	timeLow := uint64(binary.BigEndian.Uint16(b[6:8]) & 0x0fff)
	ticks := timeHigh<<28 | timeMid<<12 | timeLow
	setGregorianTime(r, ticks)
	setNode(r, b)
	r.ClockSeq = int(uint16(b[8]&0x3f)<<8 | uint16(b[9]))
}

// decodeV7 extracts the 48-bit unix-millisecond timestamp (RFC 9562 §5.7).
func decodeV7(r *Result, b []byte) {
	ms := int64(b[0])<<40 | int64(b[1])<<32 | int64(b[2])<<24 | int64(b[3])<<16 | int64(b[4])<<8 | int64(b[5])
	r.UnixMillis = ms
	r.TimestampUTC = time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
}

// setGregorianTime converts a 60-bit count of 100-ns intervals since the UUID
// epoch into a UTC timestamp and the unix-millisecond value.
func setGregorianTime(r *Result, ticks uint64) {
	unix100ns := int64(ticks) - gregorianEpoch100ns
	secs := unix100ns / 1e7
	nanos := (unix100ns % 1e7) * 100
	t := time.Unix(secs, nanos).UTC()
	r.TimestampUTC = t.Format(time.RFC3339Nano)
	r.UnixMillis = unix100ns / 1e4
}

// setNode reads the 48-bit node field and assesses whether it is a real
// hardware MAC (IEEE multicast bit clear) — the information leak — or a
// randomized node (multicast bit set, per RFC recommendation).
func setNode(r *Result, b []byte) {
	node := b[10:16]
	r.Node = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", node[0], node[1], node[2], node[3], node[4], node[5])
	if node[0]&0x01 == 0 {
		r.NodeIsMAC = true
		r.Note = "node has the IEEE multicast bit clear — it is almost certainly the generating host's real hardware MAC address (UUIDv1/v6 leaks the host MAC + creation time)."
	} else {
		r.NodeIsMAC = false
		r.Note = "node has the multicast bit set — a randomized node per the RFC recommendation, not a hardware MAC (no MAC leak)."
	}
}

func variant(b8 byte) string {
	switch {
	case b8&0x80 == 0x00:
		return "NCS (legacy Apollo)"
	case b8&0xc0 == 0x80:
		return "RFC 4122 / RFC 9562"
	case b8&0xe0 == 0xc0:
		return "Microsoft (legacy GUID)"
	default:
		return "reserved (future)"
	}
}

// normalize strips urn:uuid: prefixes, braces, dashes, and whitespace, and
// lowercases, returning the bare hex.
func normalize(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "urn:uuid:")
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	s = strings.ReplaceAll(s, "-", "")
	return s
}

func canonical(h string) string {
	if len(h) != 32 {
		return h
	}
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
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

func allEqual(b []byte, v byte) bool {
	for _, x := range b {
		if x != v {
			return false
		}
	}
	return true
}
