package flipper

import (
	"strings"
	"testing"
)

// SubGHzTxKey + SubGHzTxKeyDevice validate frequency, te, and repeat
// before transport. Prior to the fix, all three fields were forwarded
// verbatim to `subghz tx`. Out-of-band freq produced an opaque
// "Frequency not allowed!" banner several seconds later; te=0 sent a
// broken signal; repeat<=0 silently produced no transmission.

func TestSubGHzFreqAllowed_Bands(t *testing.T) {
	allowed := []uint32{
		300_000_000, 315_000_000, 348_000_000,
		387_000_000, 433_920_000, 464_000_000,
		779_000_000, 868_350_000, 915_000_000, 928_000_000,
	}
	for _, f := range allowed {
		if !subGHzFreqAllowed(f) {
			t.Errorf("subGHzFreqAllowed(%d) = false; want true (in allowed band)", f)
		}
	}

	disallowed := []uint32{
		0, 1, 100_000_000, 299_999_999, 348_000_001,
		386_999_999, 464_000_001, 778_999_999, 928_000_001,
		1_000_000_000, 2_400_000_000,
	}
	for _, f := range disallowed {
		if subGHzFreqAllowed(f) {
			t.Errorf("subGHzFreqAllowed(%d) = true; want false (outside allowed bands)", f)
		}
	}
}

func TestSubGHzTxKey_RejectsOutOfBandFrequency(t *testing.T) {
	f := &Flipper{}
	cases := []uint32{0, 100_000_000, 500_000_000, 2_400_000_000}
	for _, freq := range cases {
		_, err := f.SubGHzTxKey("AABBCC", freq, 200, 3)
		if err == nil {
			t.Errorf("expected error for freq=%d; got nil", freq)
			continue
		}
		if !strings.Contains(err.Error(), "frequency") {
			t.Errorf("freq=%d err = %v; want frequency validation error", freq, err)
		}
	}
}

func TestSubGHzTxKey_RejectsZeroTimingElement(t *testing.T) {
	f := &Flipper{}
	_, err := f.SubGHzTxKey("AABBCC", 433_920_000, 0, 3)
	if err == nil {
		t.Fatal("expected error for te=0; got nil")
	}
	if !strings.Contains(err.Error(), "te") {
		t.Errorf("err = %v; want te validation error", err)
	}
}

func TestSubGHzTxKey_RejectsNonPositiveRepeat(t *testing.T) {
	f := &Flipper{}
	for _, repeat := range []int{0, -1, -100} {
		_, err := f.SubGHzTxKey("AABBCC", 433_920_000, 200, repeat)
		if err == nil {
			t.Errorf("expected error for repeat=%d; got nil", repeat)
			continue
		}
		if !strings.Contains(err.Error(), "repeat") {
			t.Errorf("repeat=%d err = %v; want repeat validation error", repeat, err)
		}
	}
}

func TestSubGHzTxKeyDevice_RejectsOutOfBandFrequency(t *testing.T) {
	f := &Flipper{}
	_, err := f.SubGHzTxKeyDevice("AABBCC", 100_000_000, 200, 3, 0)
	if err == nil {
		t.Fatal("expected error for out-of-band freq; got nil")
	}
	if !strings.Contains(err.Error(), "frequency") {
		t.Errorf("err = %v; want frequency validation error", err)
	}
}

func TestSubGHzTxKeyDevice_RejectsZeroTimingElement(t *testing.T) {
	f := &Flipper{}
	_, err := f.SubGHzTxKeyDevice("AABBCC", 433_920_000, 0, 3, 1)
	if err == nil {
		t.Fatal("expected error for te=0; got nil")
	}
	if !strings.Contains(err.Error(), "te") {
		t.Errorf("err = %v; want te validation error", err)
	}
}
