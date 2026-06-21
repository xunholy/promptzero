package bplist

import (
	"encoding/binary"
	"testing"
)

// TestDecode_HugeElementCountIsRejected guards an unbounded-allocation DoS: a
// crafted bplist whose array/string object declares an extended element count
// near int64-max makes the n*objectRefSize span computation in refs (or n*2 in
// the UTF-16 path) overflow uint64, wrapping the range check small so it passes,
// then make([]uint64, n) / make([]uint16, n) allocates the original huge n — an
// uncaught makeslice panic / OOM on an untrusted .plist (Decode has no recover).
//
// The fix bounds the element count to the file size in sizedCount (no object can
// have more elements than there are bytes on disk). This test crafts the
// minimal valid skeleton — header + one array object with a 2^63-1 extended
// count + a one-entry offset table + a trailer with objectRefSize=2 — and
// asserts Decode returns an error instead of panicking.
func TestDecode_HugeElementCountIsRejected(t *testing.T) {
	var b []byte
	b = append(b, "bplist00"...) // 0..7
	// object 0 at offset 8: array (0xA) with extended count (lo 0xF).
	b = append(b, 0xAF)                                           // 8: array marker
	b = append(b, 0x13)                                           // 9: int marker, 1<<3 = 8-byte count
	b = append(b, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) // 10..17: count = 2^63-1
	b = append(b, 0x08)                                           // 18: offset table — object 0 at offset 8

	tr := make([]byte, 32)
	tr[6] = 0x01                              // offsetIntSize
	tr[7] = 0x02                              // objectRefSize (makes n*refSize overflow)
	binary.BigEndian.PutUint64(tr[8:16], 1)   // numObjects
	binary.BigEndian.PutUint64(tr[16:24], 0)  // topObject
	binary.BigEndian.PutUint64(tr[24:32], 18) // offsetTableOffset
	b = append(b, tr...)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Decode panicked on a crafted huge element count (unbounded-allocation DoS): %v", r)
		}
	}()
	if _, err := Decode(b); err == nil {
		t.Fatal("expected an error for an implausible element count exceeding the file size, got nil")
	}
}
