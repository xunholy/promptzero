package ja3

import "testing"

// FuzzDecode drives arbitrary hex through the parser to assert it never panics
// and never returns a nil error with a nil result.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"", "01", "16030100", realHello, greaseHello, "02000003030011"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		res, err := Decode(in)
		if err == nil && res == nil {
			t.Fatalf("Decode(%q): nil error and nil result", in)
		}
	})
}

// FuzzFromClientHello drives arbitrary bytes through the wire parser.
func FuzzFromClientHello(f *testing.F) {
	for _, s := range []string{realHello, greaseHello} {
		raw := make([]byte, 0)
		for i := 0; i+1 < len(s); i += 2 {
			var b byte
			for _, c := range s[i : i+2] {
				b <<= 4
				switch {
				case c >= '0' && c <= '9':
					b |= byte(c - '0')
				case c >= 'a' && c <= 'f':
					b |= byte(c-'a') + 10
				}
			}
			raw = append(raw, b)
		}
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		res, err := FromClientHello(in)
		if err == nil && res == nil {
			t.Fatalf("FromClientHello: nil error and nil result")
		}
	})
}
