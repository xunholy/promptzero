package rpc

import (
	"time"

	pb "github.com/xunholy/promptzero/internal/flipper/rpc/pb"
)

// Orientation mirrors the firmware's ScreenOrientation enum.
type Orientation int

const (
	OrientationDefault        Orientation = iota // maps to HORIZONTAL (firmware default)
	OrientationVertical                          // 90°
	OrientationHorizontal                        // explicit horizontal
	OrientationVerticalFlip                      // 270°
	OrientationHorizontalFlip                    // 180°
)

// ScreenFrame is a single Flipper display snapshot delivered by StartScreenStream.
// Pixels contains 1024 bytes in column-page packed format (firmware-native):
//
//	byte index = (y/8)*128 + x
//	bit index  = y % 8   (LSB = top of page)
//
// Width and Height are always 128×64.
type ScreenFrame struct {
	Width, Height int
	Orientation   Orientation
	Pixels        []byte
	ReceivedAt    time.Time
}

// Pixel reports whether the pixel at (x, y) is lit.
// x ∈ [0, 127], y ∈ [0, 63].
func (f ScreenFrame) Pixel(x, y int) bool {
	if x < 0 || x >= 128 || y < 0 || y >= 64 {
		return false
	}
	return (f.Pixels[(y/8)*128+x]>>(uint(y)%8))&1 == 1
}

// decodeFrame converts a protobuf ScreenFrame into our typed ScreenFrame.
func decodeFrame(p *pb.ScreenFrame) ScreenFrame {
	pixels := make([]byte, 1024)
	if len(p.Data) == 1024 {
		copy(pixels, p.Data)
	}
	return ScreenFrame{
		Width:       128,
		Height:      64,
		Orientation: orientationFromPB(p.Orientation),
		Pixels:      pixels,
		ReceivedAt:  time.Now(),
	}
}

func orientationFromPB(o pb.ScreenOrientation) Orientation {
	switch o {
	case pb.ScreenOrientation_VERTICAL:
		return OrientationVertical
	case pb.ScreenOrientation_HORIZONTAL:
		return OrientationHorizontal
	case pb.ScreenOrientation_VERTICAL_FLIP:
		return OrientationVerticalFlip
	case pb.ScreenOrientation_HORIZONTAL_FLIP:
		return OrientationHorizontalFlip
	default:
		return OrientationDefault
	}
}
