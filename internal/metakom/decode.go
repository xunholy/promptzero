// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metakom decodes a Metakom iButton key — the 4-byte (32-bit) contact
// key format used by Metakom intercom systems (common across the former-CIS /
// Eastern-European residential market). It is one of the two non-Dallas iButton
// formats the project's internal/ibutton decoder explicitly deferred (the other
// is Cyfral); this is the dedicated decoder for the Metakom width.
//
// Input is the *decoded* 4-byte key — the bytes a Flipper Zero iButton read
// emits (the "ID: AB CD EF 12" value), MSB-first. The on-wire framing (the sync
// bit, the 0b010 start/stop words, the bit-period timing) is the reader's
// concern and out of scope here, so the decode is deterministic.
//
// # Wrap-vs-native judgement
//
//	Native. The decode is a 4-byte read plus a per-byte even-parity check; a
//	popcount and a comparison, stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The key width (4 bytes), the MSB-first byte order and the validity rule —
//	every data byte must have an EVEN number of 1 bits — are taken from the
//	Flipper Zero firmware (lib/ibutton/protocols/misc/protocol_metakom.c
//	metakom_parity_check, which rejects a key whose any byte fails the even-
//	parity test). The rule is hand-checkable by counting bits, so no external
//	vector is needed. Metakom carries no stronger structural marker, so the
//	per-byte even parity is the only integrity gate (a comparatively weak ~1-in-
//	16 gate); a key that fails it is reported as parity-invalid rather than
//	asserted as a genuine Metakom key, and the raw bytes are always surfaced.
package metakom

import (
	"encoding/hex"
	"fmt"
	"math/bits"
	"strings"
)

// Result is a decoded Metakom iButton key.
type Result struct {
	Format      string `json:"format"`
	ID          string `json:"id"`           // "AB CD EF 12"
	IDHex       string `json:"id_hex"`       // "ABCDEF12"
	ParityValid bool   `json:"parity_valid"` // all four bytes have even parity
	ByteParity  []bool `json:"byte_parity"`  // per-byte even-parity result

	Notes []string `json:"notes,omitempty"`
}

// Decode parses a 4-byte Metakom key from hex (whitespace / ':' / '-' / '_'
// separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) != 4 {
		return nil, fmt.Errorf("metakom: need exactly 4 bytes (32-bit Metakom key), got %d", len(b))
	}

	parity := make([]bool, 4)
	allEven := true
	for i, x := range b {
		even := bits.OnesCount8(x)%2 == 0
		parity[i] = even
		if !even {
			allEven = false
		}
	}

	upper := strings.ToUpper(hex.EncodeToString(b))
	r := &Result{
		Format:      "Metakom",
		IDHex:       upper,
		ID:          fmt.Sprintf("%s %s %s %s", upper[0:2], upper[2:4], upper[4:6], upper[6:8]),
		ParityValid: allEven,
		ByteParity:  parity,
	}
	if !allEven {
		r.Notes = append(r.Notes, "one or more bytes fail the even-parity check — not a valid Metakom key (corrupt read or a different protocol); raw bytes surfaced")
	}
	r.Notes = append(r.Notes,
		"Metakom iButton key — the integrity gate is per-byte even parity (each byte has an even number of 1 bits); there is no stronger structural marker, so a coincidental ~1-in-16 pass is possible",
		"the on-wire sync / 0b010 start-stop framing is the reader's concern and out of scope; this decodes the 4-byte key")
	return r, nil
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("metakom: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("metakom: input is not valid hex: %w", err)
	}
	return b, nil
}
