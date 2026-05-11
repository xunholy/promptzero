// Package diff renders a `git diff --no-prefix`-style unified-diff string
// from two text inputs. The implementation is a line-level Myers
// algorithm with a hard output cap so a pathological input cannot blow
// the confirmation prompt to megabytes.
//
// The package has no external dependencies and is safe to call with
// arbitrary byte sequences (CR, NUL, mixed-encoding bytes are passed
// through verbatim — line splitting is on `\n` only, the same as `git
// diff` for a binary-ish file).
package diff

import (
	"fmt"
	"strings"
)

// Hard caps on rendered output. The confirmation prompt and web modal
// have to absorb this string verbatim; an unbounded diff (a freshly
// generated 10 MB payload, or a clobber of a binary blob) would lock
// up either UI. The truncation marker tells the operator to inspect
// the file via storage_read if the cap matters.
const (
	maxLines = 500
	maxBytes = 64 * 1024
)

// Unified returns a unified-diff block describing the change from
// oldContent to newContent for a file conventionally named name.
//
//	Identical inputs → empty string.
//	Empty oldContent → header + every line of newContent prefixed with "+".
//	Empty newContent → header + every line of oldContent prefixed with "-".
//
// Output is capped at the package-level maxLines / maxBytes; when the
// cap fires, a single "[... N lines truncated ...]" marker is emitted
// at the truncation point and the rest of the diff is dropped.
func Unified(name, oldContent, newContent string) string {
	if oldContent == newContent {
		return ""
	}

	oldLines := splitLines(oldContent)
	newLines := splitLines(newContent)

	ops := myers(oldLines, newLines)

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n", name)
	fmt.Fprintf(&b, "+++ %s\n", name)

	// Walk the edit script and group consecutive non-equal ops into
	// hunks with three lines of leading/trailing context. We don't try
	// to merge adjacent hunks (the operator-facing renderer handles
	// readability via line-level coloring); a simple per-change hunk
	// is plenty for a confirmation preview.
	const ctx = 3
	hunks := buildHunks(ops, ctx)

	emittedLines := 2 // the two header lines above
	emittedBytes := b.Len()
	capped := false

	flush := func(s string) bool {
		if emittedLines >= maxLines || emittedBytes+len(s) > maxBytes {
			capped = true
			return false
		}
		b.WriteString(s)
		emittedLines++
		emittedBytes += len(s)
		return true
	}

	// Snapshot the hunk loop indices when we bail so we can count
	// the lines we never got to emit and surface that in the
	// truncation marker. Previously the counter incremented exactly
	// once on the first rejected line and we then broke out of both
	// loops — the marker always read "1 lines truncated" no matter
	// how much content actually fell off, which made the message
	// useless for sizing-up "is this a small or massive diff" at a
	// glance.
	stopHunk, stopOp := -1, -1

	for hi, h := range hunks {
		header := fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", h.oldStart, h.oldLen, h.newStart, h.newLen)
		if !flush(header) {
			stopHunk, stopOp = hi, 0
			break
		}
		stopped := false
		for oi, op := range h.ops {
			var prefix byte
			switch op.kind {
			case opEqual:
				prefix = ' '
			case opDelete:
				prefix = '-'
			case opInsert:
				prefix = '+'
			}
			line := string(prefix) + op.text + "\n"
			if !flush(line) {
				stopHunk, stopOp = hi, oi
				stopped = true
				break
			}
		}
		if stopped {
			break
		}
	}

	if capped {
		// Count every op + hunk header that we never reached. Each
		// remaining op contributes one line; each remaining hunk
		// (beyond the one we stopped inside) contributes a header
		// line too. Off-by-one safety: stopOp is the index of the
		// rejected line, so ops at >= stopOp are unflushed.
		remaining := 0
		if stopHunk >= 0 {
			// Lines left in the hunk we bailed from.
			if stopHunk < len(hunks) {
				remaining += len(hunks[stopHunk].ops) - stopOp
			}
			// Lines (header + every op) for every hunk after that.
			for i := stopHunk + 1; i < len(hunks); i++ {
				remaining += 1 + len(hunks[i].ops)
			}
		}
		fmt.Fprintf(&b, "[... %d lines truncated ...]\n", remaining)
	}

	return b.String()
}

// splitLines splits s on '\n' without retaining the newline. An empty
// input yields an empty slice (not a slice with one empty string) so
// "no content" is distinguishable from "one blank line".
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	// Strip a single trailing newline so a file ending in "\n" doesn't
	// add a phantom empty line at the end of the diff.
	trimmed := strings.TrimSuffix(s, "\n")
	if trimmed == "" {
		return []string{""}
	}
	return strings.Split(trimmed, "\n")
}

type opKind int

const (
	opEqual opKind = iota
	opDelete
	opInsert
)

type editOp struct {
	kind opKind
	text string
	// 1-based line numbers in the original sequences; only valid for
	// equal+delete (oldLine) and equal+insert (newLine).
	oldLine int
	newLine int
}

// myers runs the classical Myers diff on lines and returns a flat edit
// script. The implementation is the basic O(ND) variant — adequate for
// confirmation previews where N is bounded by maxLines anyway.
func myers(a, b []string) []editOp {
	n, m := len(a), len(b)
	maxD := n + m

	if maxD == 0 {
		return nil
	}

	// Trace per-D snapshot of the v vector so we can backtrack once we
	// reach the end. Stored as []map[int]int because the v indexing is
	// in [-maxD, maxD] and a slice with a +maxD shift would work too —
	// the map is simpler and the constant overhead is negligible at our
	// scale.
	trace := make([]map[int]int, 0, maxD+1)
	v := map[int]int{1: 0}

	found := false
	for d := 0; d <= maxD; d++ {
		snap := make(map[int]int, len(v))
		for k, x := range v {
			snap[k] = x
		}
		trace = append(trace, snap)

		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[k-1] < v[k+1]) {
				x = v[k+1]
			} else {
				x = v[k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[k] = x
			if x >= n && y >= m {
				found = true
				break
			}
		}
		if found {
			break
		}
	}

	// Backtrack from (n,m) using the stored snapshots.
	var ops []editOp
	x, y := n, m
	for d := len(trace) - 1; d >= 0 && (x > 0 || y > 0); d-- {
		vd := trace[d]
		k := x - y
		var prevK int
		if k == -d || (k != d && vd[k-1] < vd[k+1]) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevX := vd[prevK]
		prevY := prevX - prevK

		for x > prevX && y > prevY {
			ops = append(ops, editOp{kind: opEqual, text: a[x-1], oldLine: x, newLine: y})
			x--
			y--
		}
		if d == 0 {
			break
		}
		if x == prevX {
			ops = append(ops, editOp{kind: opInsert, text: b[y-1], newLine: y})
		} else {
			ops = append(ops, editOp{kind: opDelete, text: a[x-1], oldLine: x})
		}
		x = prevX
		y = prevY
	}

	// Reverse: backtrack produced ops in tail-first order.
	for i, j := 0, len(ops)-1; i < j; i, j = i+1, j-1 {
		ops[i], ops[j] = ops[j], ops[i]
	}
	// Re-stamp line numbers — backtrack assigned them off the trailing
	// position. For renderer correctness we need monotonically rising
	// numbers along the edit script.
	oldLine, newLine := 1, 1
	for i := range ops {
		switch ops[i].kind {
		case opEqual:
			ops[i].oldLine = oldLine
			ops[i].newLine = newLine
			oldLine++
			newLine++
		case opDelete:
			ops[i].oldLine = oldLine
			oldLine++
		case opInsert:
			ops[i].newLine = newLine
			newLine++
		}
	}
	return ops
}

type hunk struct {
	oldStart, oldLen int
	newStart, newLen int
	ops              []editOp
}

// buildHunks groups the edit script into hunks with up to ctx lines of
// surrounding equal-context. Equal runs longer than 2*ctx are split so
// adjacent hunks don't fuse into one giant block. Hunk header line
// numbers are 1-based and use 0 for an empty side, matching git's
// convention for whole-file additions/deletions.
func buildHunks(ops []editOp, ctx int) []hunk {
	if len(ops) == 0 {
		return nil
	}

	// Mark indices of changed ops, then expand around each run with
	// the context window.
	type rng struct{ lo, hi int }
	var ranges []rng
	i := 0
	for i < len(ops) {
		if ops[i].kind == opEqual {
			i++
			continue
		}
		j := i
		for j < len(ops) && ops[j].kind != opEqual {
			j++
		}
		// Grow [i,j) by ctx on each side, but stop on hitting the
		// previous range's hi so hunks don't overlap.
		lo := i - ctx
		if lo < 0 {
			lo = 0
		}
		hi := j + ctx
		if hi > len(ops) {
			hi = len(ops)
		}
		if len(ranges) > 0 && lo <= ranges[len(ranges)-1].hi {
			ranges[len(ranges)-1].hi = hi
		} else {
			ranges = append(ranges, rng{lo, hi})
		}
		i = j
	}

	out := make([]hunk, 0, len(ranges))
	for _, r := range ranges {
		var h hunk
		h.ops = ops[r.lo:r.hi]
		// Compute the displayed start lines + counts.
		oldStart, newStart := 0, 0
		oldLen, newLen := 0, 0
		for _, op := range h.ops {
			switch op.kind {
			case opEqual:
				if oldStart == 0 {
					oldStart = op.oldLine
				}
				if newStart == 0 {
					newStart = op.newLine
				}
				oldLen++
				newLen++
			case opDelete:
				if oldStart == 0 {
					oldStart = op.oldLine
				}
				oldLen++
			case opInsert:
				if newStart == 0 {
					newStart = op.newLine
				}
				newLen++
			}
		}
		// git uses start 0 when the side is empty (whole-file create
		// or delete); otherwise the first line number. Our oldStart
		// stays zero only when the hunk has no old-side lines.
		h.oldStart = oldStart
		h.oldLen = oldLen
		h.newStart = newStart
		h.newLen = newLen
		out = append(out, h)
	}
	return out
}
