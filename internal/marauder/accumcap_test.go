// SPDX-License-Identifier: AGPL-3.0-or-later

package marauder

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestExecCtx_TruncatesOnAccumOverflow proves a runaway/hostile board that
// floods bytes without ever sending the prompt is bounded: the read returns
// the partial output with ErrResponseTruncated instead of growing the
// accumulator without limit.
func TestExecCtx_TruncatesOnAccumOverflow(t *testing.T) {
	fp := newFakePort()
	fp.respond("scanap", strings.Repeat("A", 5000)) // no newline, no prompt
	fp.suppressPrompt("scanap")                     // never emit the '> ' prompt

	m := newMarauderWithPort(fp)
	m.SetMaxAccumBytes(256) // small cap so the test stays fast

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := m.ExecCtx(ctx, "scanap", 3*time.Second)
	if !errors.Is(err, ErrResponseTruncated) {
		t.Fatalf("err = %v, want ErrResponseTruncated", err)
	}
	if out == "" {
		t.Error("expected partial output alongside the truncation error")
	}
	// The cap (256) bounds the read; the returned partial is the parsed view
	// of the accumulator, so it must be far smaller than the 5000-byte flood.
	if len(out) > 4000 {
		t.Errorf("partial output not bounded by the cap: %d bytes", len(out))
	}
}

// TestAccumCapResolver pins the default-vs-override resolution.
func TestAccumCapResolver(t *testing.T) {
	m := newMarauderWithPort(newFakePort())
	if got := m.accumCap(); got != defaultMaxAccumBytes {
		t.Errorf("default accumCap = %d, want %d", got, defaultMaxAccumBytes)
	}
	m.SetMaxAccumBytes(4096)
	if got := m.accumCap(); got != 4096 {
		t.Errorf("override accumCap = %d, want 4096", got)
	}
	m.SetMaxAccumBytes(0) // reset to default
	if got := m.accumCap(); got != defaultMaxAccumBytes {
		t.Errorf("reset accumCap = %d, want %d", got, defaultMaxAccumBytes)
	}
}
