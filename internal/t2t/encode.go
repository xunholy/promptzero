// SPDX-License-Identifier: AGPL-3.0-or-later

package t2t

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// DefaultInternal is the page-2 "internal" byte NXP Ultralight/NTAG tags
// ship with (0x48); it has no functional meaning to a reader.
const DefaultInternal = 0x48

// EncodeRequest describes the Type 2 Tag header pages to build.
type EncodeRequest struct {
	// UID is the 7-byte device UID as hex (required). The two BCC check
	// bytes are computed from it.
	UID string
	// Internal is the page-2 internal byte (defaults to 0x48).
	Internal byte
	// Lock0, Lock1 are the page-2 static lock bytes (default 0x00 = unlocked).
	Lock0, Lock1 byte
	// CC is the 4-byte Capability Container (page 3) as hex. Defaults to
	// "E1101200" (NDEF-formatted, v1.0, 144-byte, free access) — override to
	// replicate a specific tag's CC.
	CC string
}

// EncodeHeader builds the first four pages (16 bytes) of an NFC Forum Type 2
// Tag — the inverse of Decode's header parse. It computes the two UID BCC
// check bytes (BCC0 = 0x88 XOR UID0..2, BCC1 = UID3..6), lays out the UID,
// internal byte, static lock bytes, and Capability Container, and returns
// the 16-byte header. This is the clone-prep step for writing a chosen UID
// to a UID-rewritable ("magic") NTAG / Ultralight: the BCCs are filled in so
// the tag passes a reader's UID-integrity check. Generation only — it
// touches no card.
//
// # Wrap-vs-native judgement
//
// Native, and the exact inverse of Decode: it reuses the same BCC formula,
// so the two are guaranteed consistent. Pure byte assembly over the public
// NFC Forum Type 2 layout, no crypto, no hardware. Correctness is verifiable
// two ways: round-trip against Decode (BCCs validate) and the hand-computed
// BCC vector (UID 04 11 22 33 44 55 66 -> BCC0 0xBF, BCC1 0x44).
func EncodeHeader(r EncodeRequest) ([]byte, error) {
	uid, err := parseFixedHex(r.UID, 7, "uid")
	if err != nil {
		return nil, err
	}
	cc := []byte{0xE1, 0x10, 0x12, 0x00}
	if strings.TrimSpace(r.CC) != "" {
		cc, err = parseFixedHex(r.CC, 4, "cc")
		if err != nil {
			return nil, err
		}
	}
	internal := r.Internal
	if internal == 0 {
		internal = DefaultInternal
	}

	out := make([]byte, 16)
	// Page 0: UID0 UID1 UID2 BCC0
	out[0], out[1], out[2] = uid[0], uid[1], uid[2]
	out[3] = byte(CascadeTag) ^ uid[0] ^ uid[1] ^ uid[2]
	// Page 1: UID3 UID4 UID5 UID6
	out[4], out[5], out[6], out[7] = uid[3], uid[4], uid[5], uid[6]
	// Page 2: BCC1 Internal Lock0 Lock1
	out[8] = uid[3] ^ uid[4] ^ uid[5] ^ uid[6]
	out[9] = internal
	out[10], out[11] = r.Lock0, r.Lock1
	// Page 3: Capability Container
	copy(out[12:16], cc)
	return out, nil
}

// parseFixedHex decodes a hex string (separators / 0x tolerated) and
// requires exactly n bytes.
func parseFixedHex(s string, n int, field string) ([]byte, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(strings.TrimSpace(s))
	if strings.HasPrefix(strings.ToLower(clean), "0x") {
		clean = clean[2:]
	}
	if clean == "" {
		return nil, fmt.Errorf("t2t: %s is required (%d bytes hex)", field, n)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("t2t: %s is not valid hex: %w", field, err)
	}
	if len(b) != n {
		return nil, fmt.Errorf("t2t: %s must be exactly %d bytes; got %d", field, n, len(b))
	}
	return b, nil
}
