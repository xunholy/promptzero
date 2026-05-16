package flipper

import (
	"strings"
	"testing"
)

// SetLED and LED validate channel + value before transport. Pre-fix
// both forwarded arbitrary strings/ints to `led`. Unknown channels
// silently no-op'd; out-of-range values either clamped or surfaced
// as an opaque firmware banner.

func TestValidateLEDArgs_AcceptsAllChannels(t *testing.T) {
	for _, ch := range []string{"r", "g", "b", "bl"} {
		for _, v := range []int{0, 1, 128, 255} {
			if err := validateLEDArgs(ch, v); err != nil {
				t.Errorf("validateLEDArgs(%q, %d) = %v; want nil", ch, v, err)
			}
		}
	}
}

func TestLED_RejectsUnknownChannel(t *testing.T) {
	f := &Flipper{}
	for _, ch := range []string{"R", "BL", "white", "rgb", "", "red"} {
		_, err := f.LED(ch, 128)
		if err == nil {
			t.Errorf("expected error for channel=%q; got nil", ch)
			continue
		}
		if !strings.Contains(err.Error(), "channel") {
			t.Errorf("channel=%q err = %v; want channel validation error", ch, err)
		}
	}
}

func TestLED_RejectsOutOfRangeValue(t *testing.T) {
	f := &Flipper{}
	for _, v := range []int{-1, -100, 256, 1000} {
		_, err := f.LED("r", v)
		if err == nil {
			t.Errorf("expected error for value=%d; got nil", v)
			continue
		}
		if !strings.Contains(err.Error(), "value") {
			t.Errorf("value=%d err = %v; want value validation error", v, err)
		}
	}
}

func TestSetLED_RejectsUnknownChannel(t *testing.T) {
	f := &Flipper{}
	err := f.SetLED("RED", 128)
	if err == nil {
		t.Fatal("expected error for SetLED with bad channel; got nil")
	}
	if !strings.Contains(err.Error(), "channel") {
		t.Errorf("err = %v; want channel validation error", err)
	}
}

func TestSetLED_RejectsOutOfRangeValue(t *testing.T) {
	f := &Flipper{}
	err := f.SetLED("r", 999)
	if err == nil {
		t.Fatal("expected error for SetLED with bad value; got nil")
	}
	if !strings.Contains(err.Error(), "value") {
		t.Errorf("err = %v; want value validation error", err)
	}
}
