// SPDX-License-Identifier: AGPL-3.0-or-later

package debruijn

import (
	"strings"
	"testing"
)

// TestSequence_Length: B(2,n) has length exactly 2^n.
func TestSequence_Length(t *testing.T) {
	for n := 1; n <= 12; n++ {
		seq, err := Sequence(n)
		if err != nil {
			t.Fatalf("Sequence(%d): %v", n, err)
		}
		if len(seq) != 1<<uint(n) {
			t.Errorf("Sequence(%d) length = %d, want %d", n, len(seq), 1<<uint(n))
		}
	}
}

// TestDeBruijnProperty is the self-verifying anchor: every length-n window of
// the linear sequence must be present and unique, covering all 2^n codes.
func TestDeBruijnProperty(t *testing.T) {
	for n := 1; n <= 14; n++ {
		lin, err := Linear(n)
		if err != nil {
			t.Fatalf("Linear(%d): %v", n, err)
		}
		if len(lin) != (1<<uint(n))+n-1 {
			t.Fatalf("Linear(%d) length = %d, want %d", n, len(lin), (1<<uint(n))+n-1)
		}
		seen := make(map[string]bool, 1<<uint(n))
		for i := 0; i+n <= len(lin); i++ {
			var sb strings.Builder
			for j := 0; j < n; j++ {
				sb.WriteByte('0' + lin[i+j])
			}
			w := sb.String()
			if seen[w] {
				t.Fatalf("n=%d: window %q repeats — not a de Bruijn sequence", n, w)
			}
			seen[w] = true
		}
		if len(seen) != 1<<uint(n) {
			t.Errorf("n=%d: covered %d windows, want %d", n, len(seen), 1<<uint(n))
		}
	}
}

// TestSequence_OnlyBinary: every element is 0 or 1.
func TestSequence_OnlyBinary(t *testing.T) {
	seq, err := Sequence(8)
	if err != nil {
		t.Fatalf("Sequence: %v", err)
	}
	for i, b := range seq {
		if b != 0 && b != 1 {
			t.Fatalf("element %d = %d, want 0/1", i, b)
		}
	}
}

// TestSequence_N1 is the minimal hand-checkable case: B(2,1) = "01".
func TestSequence_N1(t *testing.T) {
	seq, err := Sequence(1)
	if err != nil {
		t.Fatalf("Sequence(1): %v", err)
	}
	if len(seq) != 2 || seq[0] != 0 || seq[1] != 1 {
		t.Errorf("B(2,1) = %v, want [0 1]", seq)
	}
}

func TestSequence_Errors(t *testing.T) {
	if _, err := Sequence(0); err == nil {
		t.Error("expected error for n=0")
	}
	if _, err := Sequence(MaxBits + 1); err == nil {
		t.Error("expected error for n > MaxBits")
	}
}
