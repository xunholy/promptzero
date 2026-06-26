// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthn

import "testing"

func TestCborItemLen(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want int
		err  bool
	}{
		{"small uint", []byte{0x05}, 1, false},
		{"uint8 arg", []byte{0x18, 0x2a}, 2, false},
		{"byte string", []byte{0x43, 1, 2, 3}, 4, false},               // bytes(3)
		{"empty map", []byte{0xA0}, 1, false},                          // map(0)
		{"map 1 pair", []byte{0xA1, 0x01, 0x02}, 3, false},             // {1:2}
		{"nested map", []byte{0xA1, 0x01, 0xA1, 0x02, 0x03}, 5, false}, // {1:{2:3}}
		{"array", []byte{0x83, 0x01, 0x02, 0x03}, 4, false},            // [1,2,3]
		{"truncated string", []byte{0x43, 1, 2}, 0, true},              // bytes(3) but only 2
		{"truncated map", []byte{0xA1, 0x01}, 0, true},                 // pair missing value
		{"indefinite array", []byte{0x9f, 0x01, 0xff}, 0, true},
		{"empty", []byte{}, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := cborItemLen(c.in)
			if c.err {
				if err == nil {
					t.Errorf("want error, got len=%d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("len = %d, want %d", got, c.want)
			}
		})
	}
}
