package iclass

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
)

// Capture holds one iCLASS reader-authentication exchange.
// Wire format (proxmark3 binary, 24 bytes): CSN(8) || CC(8) || NR(4) || MAC(4).
type Capture struct {
	CSN [8]byte
	CC  [8]byte // EPURSE (card challenge)
	NR  [4]byte // reader nonce
	MAC [4]byte // reader MAC over CC||NR
}

// CaptureSize is the on-disk size of one Capture record.
const CaptureSize = 24

// ParseCapturesFromFile reads a binary capture file and returns all records.
func ParseCapturesFromFile(path string) ([]Capture, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()
	return ParseCaptures(f)
}

// ParseCaptures reads Capture records from an io.Reader until EOF.
func ParseCaptures(r io.Reader) ([]Capture, error) {
	var caps []Capture
	buf := make([]byte, CaptureSize)
	for {
		_, err := io.ReadFull(r, buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read capture: %w", err)
		}
		var c Capture
		copy(c.CSN[:], buf[0:8])
		copy(c.CC[:], buf[8:16])
		copy(c.NR[:], buf[16:20])
		copy(c.MAC[:], buf[20:24])
		caps = append(caps, c)
	}
	return caps, nil
}

// ParseCapturesHex parses a sequence of captures from a hex string (pm3 text
// format or raw hex). Each capture is exactly 48 hex chars (24 bytes).
func ParseCapturesHex(hexData string) ([]Capture, error) {
	hexData = strings.ReplaceAll(hexData, " ", "")
	hexData = strings.ReplaceAll(hexData, "\n", "")
	hexData = strings.ReplaceAll(hexData, "\r", "")

	raw, err := hex.DecodeString(hexData)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}

	if len(raw)%CaptureSize != 0 {
		return nil, fmt.Errorf("capture data length %d is not a multiple of %d", len(raw), CaptureSize)
	}

	caps := make([]Capture, len(raw)/CaptureSize)
	for i := range caps {
		b := raw[i*CaptureSize : (i+1)*CaptureSize]
		copy(caps[i].CSN[:], b[0:8])
		copy(caps[i].CC[:], b[8:16])
		copy(caps[i].NR[:], b[16:20])
		copy(caps[i].MAC[:], b[20:24])
	}
	return caps, nil
}

// WriteCaptures writes all captures to w in binary format.
func WriteCaptures(w io.Writer, caps []Capture) error {
	buf := make([]byte, CaptureSize)
	for i, c := range caps {
		copy(buf[0:8], c.CSN[:])
		copy(buf[8:16], c.CC[:])
		copy(buf[16:20], c.NR[:])
		copy(buf[20:24], c.MAC[:])
		if _, err := w.Write(buf); err != nil {
			return fmt.Errorf("write capture %d: %w", i, err)
		}
	}
	return nil
}

// GenerateCaptures synthesises N authentication captures for the given
// Kcus. CSNs are chosen so that their Hash1 indices cover positions 0..15.
// CC is fixed at zero (as in the standard simulation). NR is random.
//
// Returns an error if sufficient coverage cannot be achieved.
func GenerateCaptures(kcus [8]byte, n int, rng *rand.Rand) ([]Capture, error) { //nolint:gocognit
	if n < 1 {
		return nil, fmt.Errorf("n must be >= 1")
	}

	// Build keytable from Kcus
	kt, err := Hash2(kcus)
	if err != nil {
		return nil, fmt.Errorf("hash2: %w", err)
	}

	// Find CSNs that together cover keytable positions 0..15.
	csns, err := findCoveringCSNs(16, n, rng)
	if err != nil {
		return nil, fmt.Errorf("CSN selection: %w", err)
	}

	// For each CSN, build the capture.
	caps := make([]Capture, n)
	for i, csn := range csns {
		var cc [8]byte // EPURSE = all zeros

		var nr [4]byte
		binary.BigEndian.PutUint32(nr[:], rng.Uint32())

		// Assemble key_sel from keytable using hash1 indices
		h1 := Hash1(csn)
		var keySel [8]byte
		for j := 0; j < 8; j++ {
			keySel[j] = kt[h1[j]]
		}

		// Convert key_sel from iClass format to standard DES format
		keySelStd := PermuteKeyRev(keySel)

		// Derive per-card key: div_key = hash0(DES_enc(keySelStd, csn))
		divKey, err := DiversifyKey(csn, keySelStd)
		if err != nil {
			return nil, fmt.Errorf("diversify key for CSN %d: %w", i, err)
		}

		// Build cc_nr = CC(8) || NR(4)
		var ccNR [12]byte
		copy(ccNR[:8], cc[:])
		copy(ccNR[8:], nr[:])

		mac := DoReaderMAC(ccNR, divKey)

		caps[i] = Capture{CSN: csn, CC: cc, NR: nr, MAC: mac}
	}
	return caps, nil
}

// findCoveringCSNs finds CSNs that together cover keytable positions 0..targetCoverage-1
// in their Hash1 outputs, using a simulation of the brute-force ordering to ensure
// each selected CSN is actually attackable (≤ 3 distinct unknown positions at the
// time of processing).
func findCoveringCSNs(targetCoverage, maxN int, rng *rand.Rand) ([][8]byte, error) { //nolint:gocognit
	// Simulate the attack process: track which positions are "virtually cracked".
	// A cracked[i] = true means position i is known (as if cracked by a previous capture).
	cracked := make([]bool, 128)

	var csns [][8]byte
	coveredLow := uint32(0) // bitmask of positions 0..15 covered

	// Try up to 2_000_000 random CSNs in a greedy search.
	// For each candidate, check if it's attackable (≤ 3 distinct unknowns) and adds coverage.
	for attempt := 0; attempt < 2000000 && countBits(coveredLow) < targetCoverage; attempt++ {
		var csn [8]byte
		//nolint:gosec // deterministic rand seeded by caller; not security-sensitive
		binary.BigEndian.PutUint64(csn[:], rng.Uint64())
		csn[4] = 0xf7
		csn[5] = 0xff
		csn[6] = 0x12
		csn[7] = 0xe0

		h1 := Hash1(csn)

		// Count distinct unknown positions and new positions in [0..targetCoverage).
		seen := map[uint8]bool{}
		var unknowns []uint8
		for _, idx := range h1 {
			if !cracked[idx] && !seen[idx] {
				seen[idx] = true
				unknowns = append(unknowns, idx)
			}
		}

		// Too many unknowns to brute-force — skip.
		if len(unknowns) > 3 {
			continue
		}

		// Check if any unknown is in [0..targetCoverage) and not yet covered.
		newCoverage := false
		for _, u := range unknowns {
			if int(u) < targetCoverage && (coveredLow>>(uint(u)))&1 == 0 {
				newCoverage = true
				break
			}
		}
		if !newCoverage {
			continue
		}

		// Accept this CSN: virtually crack its unknowns.
		for _, u := range unknowns {
			cracked[u] = true
			if int(u) < targetCoverage {
				coveredLow |= 1 << uint(u)
			}
		}
		csns = append(csns, csn)
	}

	if countBits(coveredLow) < targetCoverage {
		return nil, fmt.Errorf("could not find attackable CSNs covering positions 0..%d (covered %d/16 after %d CSNs)",
			targetCoverage-1, countBits(coveredLow), len(csns))
	}

	// Pad to maxN by cycling through the coverage CSNs if needed.
	// v0.5.1 followup: cycle index was buggy; unreachable in v0.5 because
	// the caller's CSN-coverage search returns an error before this loop.
	for i := 0; len(csns) < maxN; i++ {
		csns = append(csns, csns[i%len(csns)])
	}

	return csns[:maxN], nil
}

// countBits counts the number of 1-bits in a uint32.
func countBits(x uint32) int {
	n := 0
	for x != 0 {
		n++
		x &= x - 1
	}
	return n
}
