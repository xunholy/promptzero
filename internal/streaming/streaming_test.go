package streaming

import (
	"sync"
	"testing"
)

func TestNewSink_DefaultsBuffer(t *testing.T) {
	s := NewSink("tool", 0)
	if cap(s.frames) != DefaultBufferSize {
		t.Errorf("default buffer = %d, want %d", cap(s.frames), DefaultBufferSize)
	}
	if s := NewSink("tool", -5); cap(s.frames) != DefaultBufferSize {
		t.Errorf("negative buffer not normalised: %d", cap(s.frames))
	}
	if s := NewSink("tool", 8); cap(s.frames) != 8 {
		t.Errorf("explicit buffer dropped: %d", cap(s.frames))
	}
}

func TestSend_RoundTripFrame(t *testing.T) {
	s := NewSink("scan_ap", 4)
	if !s.Send([]byte("ap-1")) {
		t.Fatal("Send returned false on a healthy sink")
	}
	frame := <-s.Frames()
	if frame.Tool != "scan_ap" {
		t.Errorf("Tool = %q, want scan_ap", frame.Tool)
	}
	if frame.Seq != 1 {
		t.Errorf("Seq = %d, want 1", frame.Seq)
	}
	if string(frame.Bytes) != "ap-1" {
		t.Errorf("Bytes = %q, want ap-1", frame.Bytes)
	}
	if frame.Time.IsZero() {
		t.Errorf("Time not stamped: %+v", frame)
	}
}

func TestSend_CopiesCallerBuffer(t *testing.T) {
	// A streaming tool typically reuses a parse buffer between
	// frames. The sink MUST snapshot the bytes so a later
	// caller-side mutation doesn't corrupt frames the consumer
	// hasn't read yet.
	s := NewSink("t", 4)
	buf := []byte("first")
	s.Send(buf)
	for i := range buf {
		buf[i] = 'X'
	}
	frame := <-s.Frames()
	if string(frame.Bytes) != "first" {
		t.Errorf("Bytes mutated by caller: %q, want %q", frame.Bytes, "first")
	}
}

func TestSend_SequenceMonotonic(t *testing.T) {
	s := NewSink("t", 4)
	s.Send([]byte("a"))
	s.Send([]byte("b"))
	s.Send([]byte("c"))
	for i, want := range []uint64{1, 2, 3} {
		f := <-s.Frames()
		if f.Seq != want {
			t.Errorf("frame %d Seq = %d, want %d", i, f.Seq, want)
		}
	}
}

func TestSend_DropsOnFullBuffer(t *testing.T) {
	s := NewSink("t", 2)
	if !s.Send([]byte("a")) {
		t.Fatal("send 1 failed")
	}
	if !s.Send([]byte("b")) {
		t.Fatal("send 2 failed")
	}
	// Third send should drop without blocking.
	if s.Send([]byte("c")) {
		t.Errorf("third send returned true on full buffer")
	}
	if got := s.Drops(); got != 1 {
		t.Errorf("Drops = %d, want 1", got)
	}
}

func TestSend_AfterCloseReturnsFalse(t *testing.T) {
	s := NewSink("t", 4)
	s.Close()
	if s.Send([]byte("late")) {
		t.Errorf("Send after Close returned true")
	}
}

func TestClose_IsIdempotent(t *testing.T) {
	s := NewSink("t", 4)
	s.Close()
	s.Close() // second close must not panic
	s.Close()
}

func TestClose_TerminatesRangeLoop(t *testing.T) {
	s := NewSink("t", 4)
	s.Send([]byte("a"))
	s.Send([]byte("b"))
	s.Close()
	var got []string
	for f := range s.Frames() {
		got = append(got, string(f.Bytes))
	}
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("range result = %v, want [a b]", got)
	}
}

func TestNilSink_AllOpsAreNoOps(t *testing.T) {
	var s *Sink
	if s.Send([]byte("x")) {
		t.Errorf("nil Send returned true")
	}
	if s.Drops() != 0 {
		t.Errorf("nil Drops != 0")
	}
	if s.Sequence() != 0 {
		t.Errorf("nil Sequence != 0")
	}
	if s.Frames() != nil {
		t.Errorf("nil Frames != nil")
	}
	s.Close() // must not panic
}

func TestSend_ConcurrentProducers(t *testing.T) {
	// Two goroutines sharing one sink — verify Seq stays monotonic
	// + total count matches the sum, and no race detector trip.
	s := NewSink("t", 1024)
	var wg sync.WaitGroup
	wg.Add(2)
	const each = 500
	go func() {
		defer wg.Done()
		for i := 0; i < each; i++ {
			s.Send([]byte("a"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < each; i++ {
			s.Send([]byte("b"))
		}
	}()
	wg.Wait()
	s.Close()
	// Concurrent Add(1) + buffered-channel send means receive order
	// is NOT seq-monotonic — two goroutines can each take a Seq
	// before either has a chance to push to the channel. The
	// invariant we DO care about: every Seq is unique and falls in
	// [1, 2*each], and seen + Drops == 2*each.
	seenSeqs := make(map[uint64]struct{})
	for f := range s.Frames() {
		if _, dup := seenSeqs[f.Seq]; dup {
			t.Errorf("duplicate seq: %d", f.Seq)
		}
		if f.Seq < 1 || f.Seq > uint64(2*each) {
			t.Errorf("seq out of range: %d", f.Seq)
		}
		seenSeqs[f.Seq] = struct{}{}
	}
	if uint64(len(seenSeqs))+s.Drops() != uint64(2*each) {
		t.Errorf("seen=%d + drops=%d != %d", len(seenSeqs), s.Drops(), 2*each)
	}
}

func TestSequence_TracksHighestSeq(t *testing.T) {
	s := NewSink("t", 8)
	for i := 0; i < 5; i++ {
		s.Send([]byte("x"))
	}
	if got := s.Sequence(); got != 5 {
		t.Errorf("Sequence = %d, want 5", got)
	}
}
