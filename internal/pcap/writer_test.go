// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Michael Fornaro

package pcap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// ---- helpers ----------------------------------------------------------------

func mustNewWriter(t *testing.T, buf *bytes.Buffer, lt LinkType) *Writer {
	t.Helper()
	w, err := NewWriter(buf, lt)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	return w
}

// ---- round-trip: write N packets, read them back --------------------------

func TestRoundTrip100Packets(t *testing.T) {
	const n = 100
	rng := rand.New(rand.NewSource(42))

	type pkt struct {
		ts   time.Time
		data []byte
	}
	sent := make([]pkt, n)

	var buf bytes.Buffer
	w := mustNewWriter(t, &buf, LinkTypeIEEE802_11)

	base := time.Unix(1_700_000_000, 0).UTC()
	for i := range sent {
		size := rng.Intn(1400) + 24
		data := make([]byte, size)
		rng.Read(data)
		ts := base.Add(time.Duration(i) * time.Second)
		sent[i] = pkt{ts: ts, data: data}
		if err := w.WritePacket(ts, data); err != nil {
			t.Fatalf("WritePacket[%d]: %v", i, err)
		}
	}

	if w.PacketsWritten() != n {
		t.Errorf("PacketsWritten = %d, want %d", w.PacketsWritten(), n)
	}

	r, err := NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if r.LinkType() != LinkTypeIEEE802_11 {
		t.Errorf("LinkType = %d, want %d", r.LinkType(), LinkTypeIEEE802_11)
	}

	for i := 0; i < n; i++ {
		gotTs, gotData, err := r.Next()
		if err != nil {
			t.Fatalf("Next[%d]: %v", i, err)
		}

		// Timestamps are stored at microsecond precision.
		wantTs := sent[i].ts.Truncate(time.Microsecond)
		if !gotTs.Equal(wantTs) {
			t.Errorf("packet %d: ts = %v, want %v", i, gotTs, wantTs)
		}
		if !bytes.Equal(gotData, sent[i].data) {
			t.Errorf("packet %d: data mismatch (len got=%d want=%d)", i, len(gotData), len(sent[i].data))
		}
	}

	// Must be at EOF now.
	_, _, err = r.Next()
	if err != io.EOF {
		t.Errorf("expected io.EOF after last packet, got %v", err)
	}
}

// ---- global header field verification -------------------------------------

func TestGlobalHeaderFields(t *testing.T) {
	var buf bytes.Buffer
	mustNewWriter(t, &buf, LinkTypeIEEE802_11Radiotap)

	b := buf.Bytes()
	if len(b) < globalHeaderLen {
		t.Fatalf("buffer too short: %d bytes", len(b))
	}
	le := binary.LittleEndian

	if magic := le.Uint32(b[0:]); magic != pcapMagicMicrosecond {
		t.Errorf("magic = 0x%08x, want 0x%08x", magic, pcapMagicMicrosecond)
	}
	if vmaj := le.Uint16(b[4:]); vmaj != 2 {
		t.Errorf("version_major = %d, want 2", vmaj)
	}
	if vmin := le.Uint16(b[6:]); vmin != 4 {
		t.Errorf("version_minor = %d, want 4", vmin)
	}
	if zone := int32(le.Uint32(b[8:])); zone != 0 {
		t.Errorf("thiszone = %d, want 0", zone)
	}
	if sigfigs := le.Uint32(b[12:]); sigfigs != 0 {
		t.Errorf("sigfigs = %d, want 0", sigfigs)
	}
	if snap := le.Uint32(b[16:]); snap != pcapSnaplen {
		t.Errorf("snaplen = %d, want %d", snap, pcapSnaplen)
	}
	if lt := le.Uint32(b[20:]); lt != uint32(LinkTypeIEEE802_11Radiotap) {
		t.Errorf("network = %d, want %d", lt, LinkTypeIEEE802_11Radiotap)
	}
}

// ---- BytesWritten accounting ----------------------------------------------

func TestBytesWritten(t *testing.T) {
	var buf bytes.Buffer
	w := mustNewWriter(t, &buf, LinkTypeEthernet)

	if w.BytesWritten() != globalHeaderLen {
		t.Errorf("after NewWriter: BytesWritten = %d, want %d", w.BytesWritten(), globalHeaderLen)
	}

	frame := make([]byte, 60)
	if err := w.WritePacket(time.Now(), frame); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	want := int64(globalHeaderLen + perPacketHeaderLen + len(frame))
	if w.BytesWritten() != want {
		t.Errorf("BytesWritten = %d, want %d", w.BytesWritten(), want)
	}
	if int64(buf.Len()) != want {
		t.Errorf("buf.Len = %d, want %d", buf.Len(), want)
	}
}

// ---- hex fixture: 1-packet pcap with known content ------------------------
//
// A single pcap is constructed manually and compared against what Writer
// produces.  Timestamp: Unix 0x63B0_CD00 = 1672531200 (2023-01-01 00:00:00 UTC),
// sub-second = 0, frame = []byte{0xDE, 0xAD, 0xBE, 0xEF}.

func TestHexFixture(t *testing.T) {
	ts := time.Unix(0x63B0CD00, 0).UTC()
	frame := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	// Build expected bytes manually.
	var want bytes.Buffer
	le := binary.LittleEndian
	put32 := func(v uint32) {
		var b [4]byte
		le.PutUint32(b[:], v)
		want.Write(b[:])
	}
	put16 := func(v uint16) {
		var b [2]byte
		le.PutUint16(b[:], v)
		want.Write(b[:])
	}
	// Global header
	put32(0xa1b2c3d4)
	put16(2)
	put16(4)
	put32(0) // thiszone
	put32(0) // sigfigs
	put32(65535)
	put32(uint32(LinkTypeEthernet))
	// Packet record header
	put32(uint32(ts.Unix()))
	put32(0) // ts_usec = 0
	put32(uint32(len(frame)))
	put32(uint32(len(frame)))
	want.Write(frame)

	// Now produce the same via Writer.
	var got bytes.Buffer
	w := mustNewWriter(t, &got, LinkTypeEthernet)
	if err := w.WritePacket(ts, frame); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	if !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Errorf("hex mismatch\n got: %s\nwant: %s",
			strings.ToUpper(hex.EncodeToString(got.Bytes())),
			strings.ToUpper(hex.EncodeToString(want.Bytes())))
	}
}

// ---- error paths ----------------------------------------------------------

func TestWritePacketNilData(t *testing.T) {
	var buf bytes.Buffer
	w := mustNewWriter(t, &buf, LinkTypeIEEE802_11)
	if err := w.WritePacket(time.Now(), nil); err == nil {
		t.Error("expected error for nil data, got nil")
	}
	// PacketsWritten must not increment.
	if w.PacketsWritten() != 0 {
		t.Errorf("PacketsWritten = %d after nil write, want 0", w.PacketsWritten())
	}
}

func TestWritePacketEmptyData(t *testing.T) {
	var buf bytes.Buffer
	w := mustNewWriter(t, &buf, LinkTypeIEEE802_11)
	// empty (non-nil) slice is valid.
	if err := w.WritePacket(time.Now(), []byte{}); err != nil {
		t.Errorf("unexpected error for empty slice: %v", err)
	}
	if w.PacketsWritten() != 1 {
		t.Errorf("PacketsWritten = %d, want 1", w.PacketsWritten())
	}
}

// TestWriterNoPoison verifies that a write failure doesn't permanently
// prevent subsequent WritePacket attempts. We simulate a failing writer,
// then replace it with a good one.
func TestWriterNoPoison(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, LinkTypeIEEE802_11)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// First write succeeds.
	if err := w.WritePacket(time.Now(), []byte{0x01}); err != nil {
		t.Fatalf("first WritePacket: %v", err)
	}

	// Point the writer at an always-failing io.Writer.
	w.w = errorWriter{}
	if err := w.WritePacket(time.Now(), []byte{0x02}); err == nil {
		t.Error("expected error from failing writer, got nil")
	}

	// Restore a good writer; subsequent calls must proceed.
	var buf2 bytes.Buffer
	w.w = &buf2
	if err := w.WritePacket(time.Now(), []byte{0x03}); err != nil {
		t.Errorf("write after recovery: %v", err)
	}
	if w.PacketsWritten() != 2 {
		t.Errorf("PacketsWritten = %d, want 2 (packets 1 and 3)", w.PacketsWritten())
	}
}

// errorWriter always returns an error.
type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

// ---- snaplen cap ----------------------------------------------------------

func TestSnaplengthCap(t *testing.T) {
	oversized := make([]byte, int(pcapSnaplen)+100)
	for i := range oversized {
		oversized[i] = byte(i)
	}

	var buf bytes.Buffer
	w := mustNewWriter(t, &buf, LinkTypeIEEE802_11)
	if err := w.WritePacket(time.Now(), oversized); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	r, err := NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	_, data, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if uint32(len(data)) != pcapSnaplen {
		t.Errorf("incl_len = %d, want snaplen %d", len(data), pcapSnaplen)
	}
	if !bytes.Equal(data, oversized[:pcapSnaplen]) {
		t.Error("snaplen-capped data mismatch")
	}
}

// ---- Reader: bad magic ----------------------------------------------------

func TestReaderBadMagic(t *testing.T) {
	garbage := make([]byte, globalHeaderLen)
	binary.LittleEndian.PutUint32(garbage[0:], 0xDEADBEEF)
	_, err := NewReader(bytes.NewReader(garbage))
	if err == nil {
		t.Error("expected error for bad magic, got nil")
	}
}

// ---- Reader: truncated packet data ----------------------------------------

func TestReaderTruncatedPacket(t *testing.T) {
	var buf bytes.Buffer
	w := mustNewWriter(t, &buf, LinkTypeIEEE802_11)

	// Manually corrupt: write a record header claiming 100 bytes but
	// append only 10.
	le := binary.LittleEndian
	var rec [perPacketHeaderLen]byte
	le.PutUint32(rec[0:], uint32(time.Now().Unix()))
	le.PutUint32(rec[8:], 100) // incl_len
	le.PutUint32(rec[12:], 100)
	buf.Write(rec[:])
	buf.Write(make([]byte, 10)) // only 10 bytes

	_ = w // silence unused

	r, err := NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	_, _, err = r.Next()
	if err == nil {
		t.Error("expected error for truncated packet data, got nil")
	}
}

// TestNext_OversizedInclLenNoOOM guards a memory-amplification bug: a
// record header declaring inclLen up to 4 GiB used to drive
// make([]byte, inclLen) into an out-of-memory kill before io.ReadFull
// could fail. Next must reject any inclLen above the clamped snaplen
// (here the 16 MiB absolute backstop) with errPacketTrunc and never
// allocate the oversized buffer. Found via fuzzing.
func TestNext_OversizedInclLenNoOOM(t *testing.T) {
	le := binary.LittleEndian
	// Valid 24-byte global header with snaplen=0 (→ clamped to the
	// 16 MiB backstop).
	hdr := make([]byte, 24)
	le.PutUint32(hdr[0:], 0xa1b2c3d4)
	le.PutUint16(hdr[4:], 2)  // version major
	le.PutUint16(hdr[6:], 4)  // version minor
	le.PutUint32(hdr[16:], 0) // snaplen = 0
	le.PutUint32(hdr[20:], 1) // linktype = Ethernet

	// One record header with inclLen = 0xFFFFFFFF (4 GiB) and no body.
	rec := make([]byte, 16)
	le.PutUint32(rec[8:], 0xFFFFFFFF)  // incl_len
	le.PutUint32(rec[12:], 0xFFFFFFFF) // orig_len

	r, err := NewReader(bytes.NewReader(append(hdr, rec...)))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	_, _, err = r.Next()
	if err == nil {
		t.Fatal("expected error for oversized inclLen, got nil")
	}
	// Must be the truncation error, not an OOM/panic.
	if !errors.Is(err, errPacketTrunc) {
		t.Errorf("got %v; want errPacketTrunc", err)
	}
}
