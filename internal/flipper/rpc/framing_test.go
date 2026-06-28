package rpc

import (
	"bytes"
	"io"
	"testing"

	pb "github.com/xunholy/promptzero/internal/flipper/rpc/pb"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestFramingRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		msg  *pb.Main
	}{
		{
			name: "ping request",
			msg: &pb.Main{
				CommandId: 1,
				Content:   &pb.Main_SystemPingRequest{SystemPingRequest: &pb.PingRequest{}},
			},
		},
		{
			name: "ping response with data",
			msg: &pb.Main{
				CommandId: 2,
				Content: &pb.Main_SystemPingResponse{
					SystemPingResponse: &pb.PingResponse{Data: []byte("pong payload")},
				},
			},
		},
		{
			name: "start screen stream request",
			msg: &pb.Main{
				CommandId: 42,
				Content: &pb.Main_GuiStartScreenStreamRequest{
					GuiStartScreenStreamRequest: &pb.StartScreenStreamRequest{},
				},
			},
		},
		{
			name: "screen frame (large payload)",
			msg: &pb.Main{
				CommandId: 100,
				Content: &pb.Main_GuiScreenFrame{
					GuiScreenFrame: &pb.ScreenFrame{
						Data:        make([]byte, 1024),
						Orientation: pb.ScreenOrientation_HORIZONTAL,
					},
				},
			},
		},
		{
			name: "stop session",
			msg: &pb.Main{
				CommandId: 999,
				Content:   &pb.Main_StopSession{StopSession: &pb.StopSession{}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeFramed(&buf, tc.msg); err != nil {
				t.Fatalf("writeFramed: %v", err)
			}
			got, err := readFramed(&buf)
			if err != nil {
				t.Fatalf("readFramed: %v", err)
			}
			if got.CommandId != tc.msg.CommandId {
				t.Errorf("CommandId: got %d, want %d", got.CommandId, tc.msg.CommandId)
			}
			// Verify the content type is preserved.
			if got.Content == nil && tc.msg.Content != nil {
				t.Error("content lost after round-trip")
			}
		})
	}
}

// TestFramingVarintEdgeCases encodes messages whose serialised sizes produce
// multi-byte varints (> 127 bytes) to exercise the byte-by-byte varint reader.
func TestFramingVarintEdgeCases(t *testing.T) {
	// 256-byte payload produces a 3-byte varint prefix.
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}
	msg := &pb.Main{
		CommandId: 7,
		Content: &pb.Main_GuiScreenFrame{
			GuiScreenFrame: &pb.ScreenFrame{Data: payload[:128]},
		},
	}
	var buf bytes.Buffer
	if err := writeFramed(&buf, msg); err != nil {
		t.Fatalf("writeFramed: %v", err)
	}
	got, err := readFramed(&buf)
	if err != nil {
		t.Fatalf("readFramed: %v", err)
	}
	if got.CommandId != 7 {
		t.Errorf("CommandId: got %d, want 7", got.CommandId)
	}
}

// timeoutReader replays a script of read results. A "" element models an idle
// read-timeout — the transports return (0, nil) there, NOT an error or EOF —
// so it must leave buf untouched and report n=0.
type timeoutReader struct {
	steps []string // each: a chunk of bytes to deliver, or "" for a (0,nil) timeout
	i     int
}

func (tr *timeoutReader) Read(p []byte) (int, error) {
	if tr.i >= len(tr.steps) {
		return 0, io.EOF
	}
	s := tr.steps[tr.i]
	if s == "" { // idle timeout: no bytes, no error
		tr.i++
		return 0, nil
	}
	n := copy(p, s)
	if n < len(s) {
		tr.steps[tr.i] = s[n:] // partial consume, stay on this step
	} else {
		tr.i++
	}
	return n, nil
}

// TestReadVarintToleratesIdleTimeouts is the regression guard for the framing
// desync bug: readVarint must not consume a stale byte when the transport
// returns (0, nil) on an idle read-timeout. The headline case is a timeout
// landing BETWEEN the two bytes of varint(300) = {0xAC, 0x02}: the buggy reader
// re-consumed the stale 0xAC and returned 38444, permanently desyncing the RPC
// stream.
func TestReadVarintToleratesIdleTimeouts(t *testing.T) {
	t.Run("timeout mid-varint does not corrupt length", func(t *testing.T) {
		// varint(300) split by an idle timeout between its two bytes.
		r := &timeoutReader{steps: []string{"\xac", "", "", "\x02"}}
		got, err := readVarint(r)
		if err != nil {
			t.Fatalf("readVarint: %v", err)
		}
		if got != 300 {
			t.Fatalf("got %d, want 300 (stale-byte re-consume regression)", got)
		}
	})

	t.Run("timeout before any byte yields empty frame, not corruption", func(t *testing.T) {
		// (0,nil) with no data is the no-frame-yet poll signal: length 0.
		r := &timeoutReader{steps: []string{"", ""}}
		got, err := readVarint(r)
		if err != nil {
			t.Fatalf("readVarint: %v", err)
		}
		if got != 0 {
			t.Fatalf("got %d, want 0 (no-data poll path)", got)
		}
	})

	t.Run("full frame round-trips through idle timeouts", func(t *testing.T) {
		// A 256-byte payload (3-byte varint prefix) interleaved with timeouts
		// at the prefix boundary must still decode intact.
		msg := &pb.Main{
			CommandId: 11,
			Content:   &pb.Main_GuiScreenFrame{GuiScreenFrame: &pb.ScreenFrame{Data: make([]byte, 200)}},
		}
		var buf bytes.Buffer
		if err := writeFramed(&buf, msg); err != nil {
			t.Fatalf("writeFramed: %v", err)
		}
		raw := buf.Bytes()
		// Deliver: first prefix byte, a timeout, the rest of the frame.
		r := &timeoutReader{steps: []string{string(raw[:1]), "", string(raw[1:])}}
		got, err := readFramed(r)
		if err != nil {
			t.Fatalf("readFramed: %v", err)
		}
		if got.CommandId != 11 {
			t.Errorf("CommandId: got %d, want 11", got.CommandId)
		}
	})
}

// TestFramingOversizedLengthRejected guards the unbounded-allocation hazard: a
// garbage length prefix (stream desync / hostile peer) must be rejected, not
// fed straight into make([]byte, msgLen) and OOM the process.
func TestFramingOversizedLengthRejected(t *testing.T) {
	// A varint declaring a 4 GiB frame, with no body following.
	prefix := protowire.AppendVarint(nil, 4<<30)
	if _, err := readFramed(bytes.NewReader(prefix)); err == nil {
		t.Fatal("expected oversized frame length to be rejected, got nil error")
	}

	// A frame exactly at the cap boundary + 1 is rejected before allocation.
	overByOne := protowire.AppendVarint(nil, uint64(maxFrameBytes)+1)
	if _, err := readFramed(bytes.NewReader(overByOne)); err == nil {
		t.Fatal("expected length just over maxFrameBytes to be rejected")
	}

	// A legitimately-sized frame still round-trips (cap does not over-reject).
	var buf bytes.Buffer
	msg := &pb.Main{CommandId: 9, Content: &pb.Main_SystemPingRequest{SystemPingRequest: &pb.PingRequest{}}}
	if err := writeFramed(&buf, msg); err != nil {
		t.Fatalf("writeFramed: %v", err)
	}
	if _, err := readFramed(&buf); err != nil {
		t.Fatalf("legit frame rejected: %v", err)
	}
}
