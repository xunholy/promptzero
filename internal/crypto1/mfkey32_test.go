package crypto1

import (
	"context"
	"testing"
)

// mfkey32RecoverVector groups the inputs and expected output for one
// closed-loop Recover test.  All keys have hi32 = 0 (bits 47..16 = 0)
// so RecoverWithRange(…, 0, 1) finds them in a 2^16 search (~70 ms).
type mfkey32RecoverVector struct {
	name       string
	key        uint64
	uid        uint32
	cap0, cap1 AuthCapture
}

// mfkey32Vectors contains three closed-loop test vectors.
// Keys are restricted to the range 0x0000..0xFFFF (16-bit) so that the
// search space is 2^16 and each test completes in under 100 ms.
var mfkey32Vectors = []mfkey32RecoverVector{
	{
		// Vector 1: arbitrary 16-bit key, common uid and nonces.
		name: "key=0x1234",
		key:  0x1234,
		uid:  0xcafebabe,
		cap0: AuthCapture{NT: 0x01020304, NR: 0xdeadbeef},
		cap1: AuthCapture{NT: 0xe93e12e4, NR: 0x11223344},
	},
	{
		// Vector 2: all-zeros key (corner case — LFSR stays all-zero).
		name: "zero key",
		key:  0x0000,
		uid:  0xAABBCCDD,
		cap0: AuthCapture{NT: 0xDEADBEEF, NR: 0x00000001},
		cap1: AuthCapture{NT: 0xCAFEBABE, NR: 0x00000002},
	},
	{
		// Vector 3: 16-bit key derived from "PZ" ASCII (0x50=P, 0x5A=Z).
		name: "PZ key=0x505A",
		key:  0x505A,
		uid:  0x12345678,
		cap0: AuthCapture{NT: 0xABCDEF01, NR: 0x98765432},
		cap1: AuthCapture{NT: 0x11111111, NR: 0xFEDCBA98},
	},
}

// TestMfkey32ClosedLoop runs Recover against three closed-loop vectors.
// For each: encrypt with key K to produce {aR} values, then assert that
// RecoverWithRange returns K.
func TestMfkey32ClosedLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("TestMfkey32ClosedLoop (~70 ms per vector): skipped in -short mode")
	}

	for _, v := range mfkey32Vectors {
		v := v
		t.Run(v.name, func(t *testing.T) {
			_, ar0 := AuthEncrypt(v.key, v.uid, v.cap0)
			_, ar1 := AuthEncrypt(v.key, v.uid, v.cap1)

			got, err := RecoverWithRange(
				context.Background(),
				v.uid,
				v.cap0.NT, v.cap0.NR, ar0,
				v.cap1.NT, v.cap1.NR, ar1,
				0, 1, // search hi32 = 0 only (2^16 key space)
			)
			if err != nil {
				t.Fatalf("Recover failed: %v", err)
			}
			if got != v.key {
				t.Errorf("Recover = 0x%012X; want 0x%012X", got, v.key)
			}
		})
	}
}

// TestRecoverWithRangeContextCancellation verifies that RecoverWithRange
// returns a context error promptly when the context is cancelled before
// the search range is exhausted (regression test for the goroutine-leak fix).
func TestRecoverWithRangeContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	const uid = uint32(0xcafebabe)
	cap0 := AuthCapture{NT: 0x01020304, NR: 0xdeadbeef}
	cap1 := AuthCapture{NT: 0xe93e12e4, NR: 0x11223344}
	_, ar0 := AuthEncrypt(0x1234, uid, cap0)
	_, ar1 := AuthEncrypt(0x1234, uid, cap1)

	// Use a large hi-range so the search would never finish without context.
	_, err := RecoverWithRange(ctx, uid, cap0.NT, cap0.NR, ar0, cap1.NT, cap1.NR, ar1, 0, 1<<32)
	if err == nil {
		t.Fatal("RecoverWithRange: expected error on cancelled context, got nil")
	}
	if !isCtxError(err) {
		t.Errorf("RecoverWithRange: want context error, got %v", err)
	}
}

func isCtxError(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}

// TestMfkey32AuthEncryptRoundTrip verifies that AuthEncrypt produces
// values consistent with the auth sequence:
//
//   - nrEnc re-computed from the cipher matches AuthEncrypt's nrEnc.
//   - arEnc = prng(NT, 64) XOR ks2.
func TestMfkey32AuthEncryptRoundTrip(t *testing.T) {
	const key = uint64(0xA0A1A2A3A4A5)
	const uid = uint32(0xcafebabe)
	cap := AuthCapture{NT: 0x01020304, NR: 0xdeadbeef}

	nrEnc, arEnc := AuthEncrypt(key, uid, cap)

	// Re-run the cipher and verify nrEnc.
	c := New()
	c.Init(key)
	c.CryptFeedback(uid ^ cap.NT)
	nrEncRecheck := c.EncCrypt(cap.NR, 0)
	if nrEnc != nrEncRecheck {
		t.Errorf("nrEnc = 0x%08X; re-check = 0x%08X", nrEnc, nrEncRecheck)
	}

	// Verify arEnc = prng(NT, 64) XOR ks2.
	ks2 := c.Crypt(0)
	if want := Prng(cap.NT, 64) ^ ks2; arEnc != want {
		t.Errorf("arEnc = 0x%08X; want 0x%08X (prng XOR ks2)", arEnc, want)
	}
}

// TestMfkey32RollbackInverse verifies that rollback32 and invertLFSRStep
// are exact inverses of the forward LFSR steps, using a full auth chain.
func TestMfkey32RollbackInverse(t *testing.T) {
	const key = uint64(0xa0a1a2a3a4a5)
	const uid = uint32(0xcafebabe)
	const nt = uint32(0x01020304)
	const nr = uint32(0xdeadbeef)

	c := New()
	c.Init(key)
	stateAfterInit := c.state

	c.CryptFeedback(uid ^ nt)
	stateAfterNT := c.state

	c.EncCrypt(nr, 0)
	stateAfterNR := c.state

	if s := rollback32(stateAfterNR, nr); s != stateAfterNT {
		t.Errorf("rollback32(nR): got 0x%012X want 0x%012X", s, stateAfterNT)
	}
	if s := rollback32(stateAfterNT, uid^nt); s != stateAfterInit {
		t.Errorf("rollback32(nT): got 0x%012X want 0x%012X", s, stateAfterInit)
	}

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
