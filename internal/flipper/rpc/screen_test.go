package rpc

import (
	"testing"

	pb "github.com/xunholy/promptzero/internal/flipper/rpc/pb"
)

// buildPixels builds a 1024-byte buffer and sets the pixel at (x, y).
func buildPixels(x, y int) []byte {
	buf := make([]byte, 1024)
	buf[(y/8)*128+x] |= 1 << (uint(y) % 8)
	return buf
}

func TestPixelSingleBit(t *testing.T) {
	cases := []struct{ x, y int }{
		{0, 0},    // top-left, page 0 bit 0
		{127, 0},  // top-right, page 0 bit 0
		{0, 63},   // bottom-left, page 7 bit 7
		{127, 63}, // bottom-right
		{64, 32},  // middle
		{0, 7},    // last bit of first page column 0
		{0, 8},    // first bit of second page column 0 (page boundary)
	}
	for _, tc := range cases {
		pixels := buildPixels(tc.x, tc.y)
		f := ScreenFrame{Width: 128, Height: 64, Pixels: pixels}
		if !f.Pixel(tc.x, tc.y) {
			t.Errorf("Pixel(%d,%d) = false, want true", tc.x, tc.y)
		}
		// Neighbouring pixels must be off.
		if tc.x+1 < 128 && f.Pixel(tc.x+1, tc.y) {
			t.Errorf("Pixel(%d,%d) collateral damage: right neighbour lit", tc.x, tc.y)
		}
		if tc.y+1 < 64 && f.Pixel(tc.x, tc.y+1) {
			t.Errorf("Pixel(%d,%d) collateral damage: below neighbour lit", tc.x, tc.y)
		}
	}
}

func TestPixelOOB(t *testing.T) {
	f := ScreenFrame{Width: 128, Height: 64, Pixels: make([]byte, 1024)}
	oob := [][2]int{{-1, 0}, {0, -1}, {128, 0}, {0, 64}, {200, 100}}
	for _, p := range oob {
		if f.Pixel(p[0], p[1]) {
			t.Errorf("Pixel(%d,%d) = true for OOB coordinate", p[0], p[1])
		}
	}
}

func TestPixelAllSet(t *testing.T) {
	pixels := make([]byte, 1024)
	for i := range pixels {
		pixels[i] = 0xFF
	}
	f := ScreenFrame{Width: 128, Height: 64, Pixels: pixels}
	for y := 0; y < 64; y++ {
		for x := 0; x < 128; x++ {
			if !f.Pixel(x, y) {
				t.Fatalf("Pixel(%d,%d) = false with all-set buffer", x, y)
			}
		}
	}
}

func TestPixelAllClear(t *testing.T) {
	f := ScreenFrame{Width: 128, Height: 64, Pixels: make([]byte, 1024)}
	for y := 0; y < 64; y++ {
		for x := 0; x < 128; x++ {
			if f.Pixel(x, y) {
				t.Fatalf("Pixel(%d,%d) = true with all-clear buffer", x, y)
			}
		}
	}
}

func TestDecodeFrame(t *testing.T) {
	pixels := make([]byte, 1024)
	pixels[0] = 0xAB
	pbf := &pb.ScreenFrame{
		Data:        pixels,
		Orientation: pb.ScreenOrientation_VERTICAL,
	}
	f := decodeFrame(pbf)
	if f.Width != 128 || f.Height != 64 {
		t.Errorf("dimensions: got %dx%d, want 128x64", f.Width, f.Height)
	}
	if f.Orientation != OrientationVertical {
		t.Errorf("orientation: got %v, want OrientationVertical", f.Orientation)
	}
	if f.Pixels[0] != 0xAB {
		t.Errorf("pixels[0]: got %#x, want 0xAB", f.Pixels[0])
	}
}

func TestDecodeFrameShortData(t *testing.T) {
	// Firmware anomaly: fewer than 1024 bytes. Should not panic; pixels zeroed.
	pbf := &pb.ScreenFrame{Data: []byte{0xFF, 0xFF}}
	f := decodeFrame(pbf)
	if len(f.Pixels) != 1024 {
		t.Errorf("pixels len: got %d, want 1024", len(f.Pixels))
	}
	// Data too short — pixels must be all zero (safe default).
	for i, b := range f.Pixels {
		if b != 0 {
			t.Fatalf("pixels[%d] = %#x, want 0 for short input", i, b)
		}
	}
}
