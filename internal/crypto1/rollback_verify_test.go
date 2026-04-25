package crypto1

import "testing"

// TestRollbackCorrectness verifies that rollback32 and invertLFSRStep
// are exact inverses of the forward LFSR operations.
func TestRollbackCorrectness(t *testing.T) {
	const key = uint64(0xa0a1a2a3a4a5)
	const uid = uint32(0xcafebabe)
	const nt = uint32(0x01020304)
	const nr = uint32(0x12345678)

	c := New()
	c.Init(key)
	stateAfterInit := c.state

	c.CryptFeedback(uid ^ nt)
	stateAfterNT := c.state

	c.EncCrypt(nr, 0)
	stateAfterNR := c.state

	// rollback32(nR phase) must recover stateAfterNT.
	if got := rollback32(stateAfterNR, nr); got != stateAfterNT {
		t.Errorf("rollback32(nR): got 0x%012X want 0x%012X", got, stateAfterNT)
	}

	// rollback32(nT phase) must recover stateAfterInit (= key).
	if got := rollback32(stateAfterNT, uid^nt); got != stateAfterInit {
		t.Errorf("rollback32(nT): got 0x%012X want 0x%012X", got, stateAfterInit)
	}

	// invertLFSRStep must perfectly invert a single clockLFSR step.
	for _, extBit := range []uint64{0, 1} {
		orig := stateAfterInit
		c2 := New()
		c2.state = orig
		c2.clockLFSR(extBit)
		fwd := c2.state
		bck := invertLFSRStep(fwd, extBit)
		if bck != orig {
			t.Errorf("invertLFSRStep(extBit=%d): got 0x%012X want 0x%012X",
				extBit, bck, orig)
		}
	}
}

// TestAuthAndKsFromState verifies that ksFromState returns the same
// 32-bit keystream as the Crypt(0) call following the auth sequence.
func TestAuthAndKsFromState(t *testing.T) {
	const key = uint64(0xa0a1a2a3a4a5)
	const uid = uint32(0xcafebabe)
	const nt = uint32(0x01020304)
	const nr = uint32(0x12345678)

	c := New()
	c.Init(key)
	c.CryptFeedback(uid ^ nt)
	c.EncCrypt(nr, 0)
	stateAfterNR := c.state
	ks2Expected := c.Crypt(0)

	if ks2Got := ksFromState(stateAfterNR); ks2Got != ks2Expected {
		t.Errorf("ksFromState: got 0x%08X want 0x%08X", ks2Got, ks2Expected)
	}

	// AuthEncrypt must produce arEnc = prng(nt, 64) XOR ks2.
	_, arEnc := AuthEncrypt(key, uid, AuthCapture{NT: nt, NR: nr})
	if want := Prng(nt, 64) ^ ks2Expected; arEnc != want {
		t.Errorf("AuthEncrypt arEnc: got 0x%08X want 0x%08X", arEnc, want)
	}

	// Full rollback chain must recover the original key.
	sAfterNT := rollback32(stateAfterNR, nr)
	if keyGot := rollback32(sAfterNT, uid^nt); keyGot != key {
		t.Errorf("full rollback: got 0x%012X want 0x%012X", keyGot, key)
	}
}
