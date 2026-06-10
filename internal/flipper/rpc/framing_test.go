package rpc

import (
	"bytes"
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
