package rpc

import (
	"fmt"
	"io"

	pb "github.com/xunholy/promptzero/internal/flipper/rpc/pb"
	"google.golang.org/protobuf/encoding/protowire"
	proto "google.golang.org/protobuf/proto"
)

// maxFrameBytes caps the length prefix readFramed will allocate for. The
// transport is a raw serial port with no framing delimiter beyond the length
// prefix itself, so a desynced stream, line noise, or a hostile/buggy peer can
// present a garbage varint — up to 2^64-1. Without a cap `make([]byte, msgLen)`
// would then attempt a multi-gigabyte allocation and OOM the process. A Flipper
// RPC Main message is tiny (the firmware chunks large transfers and runs in a
// few hundred KB of RAM), so 16 MiB is orders of magnitude of headroom over any
// legitimate frame while bounding a hostile allocation.
const maxFrameBytes = 16 << 20

// writeFramed marshals m, length-prefixes it with a protowire varint, and
// writes the result to w.
func writeFramed(w io.Writer, m *pb.Main) error {
	body, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("rpc: marshal: %w", err)
	}
	prefix := protowire.AppendVarint(nil, uint64(len(body)))
	if _, err := w.Write(prefix); err != nil {
		return fmt.Errorf("rpc: write varint prefix: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("rpc: write body: %w", err)
	}
	return nil
}

// readFramed reads one varint-length-prefixed protobuf Main message from r.
//
// The varint is consumed byte-by-byte so we never over-read. This matters
// because the underlying transport is a raw serial port and there is no
// framing delimiter other than the length prefix itself.
func readFramed(r io.Reader) (*pb.Main, error) {
	msgLen, err := readVarint(r)
	if err != nil {
		return nil, fmt.Errorf("rpc: read length prefix: %w", err)
	}
	if msgLen > maxFrameBytes {
		return nil, fmt.Errorf("rpc: frame length %d exceeds max %d (stream desync or hostile peer)", msgLen, maxFrameBytes)
	}
	body := make([]byte, msgLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("rpc: read body (%d bytes): %w", msgLen, err)
	}
	var m pb.Main
	if err := proto.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("rpc: unmarshal: %w", err)
	}
	return &m, nil
}

// readVarint reads a protowire varint one byte at a time from r.
func readVarint(r io.Reader) (uint64, error) {
	var (
		x   uint64
		buf [1]byte
	)
	for s := uint(0); s < 64; s += 7 {
		_, err := r.Read(buf[:])
		if err != nil {
			return 0, err
		}
		b := buf[0]
		x |= uint64(b&0x7f) << s
		if b < 0x80 {
			return x, nil
		}
	}
	return 0, fmt.Errorf("rpc: varint overflow")
}
