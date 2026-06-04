// SPDX-License-Identifier: AGPL-3.0-or-later

package httpmsg

import "testing"

// JA4H anchors — byte-for-byte against FoxIO snapshot outputs, with the exact
// HTTP requests extracted from FoxIO's own test pcaps.
func TestJA4H(t *testing.T) {
	cases := []struct {
		name string
		req  string
		want string
	}{
		{
			// pcap/http-empty-useragent.pcap: GET / HTTP/1.0 with one (empty) User-Agent.
			name: "empty-useragent",
			req:  "GET / HTTP/1.0\r\nUser-Agent:\r\n\r\n",
			want: "ge10nn010000_b8bcd45ac095_000000000000_000000000000",
		},
		{
			// pcap/http1-with-cookies.pcapng: curl GET with Referer + 2 cookies + Accept-Language.
			name: "cookies",
			req: "GET / HTTP/1.1\r\nHost: localhost:8000\r\nUser-Agent: curl/8.1.2\r\n" +
				"Accept: */*\r\nReferer: https://fake.example\r\n" +
				"Cookie: yummy_cookie=choco; tasty_cookie=strawberry\r\n" +
				"Accept-Language: da, en-GB;q=0.8, en;q=0.7\r\n\r\n",
			want: "ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442",
		},
	}
	for _, c := range cases {
		m, err := Decode(c.req)
		if err != nil {
			t.Errorf("%s: Decode: %v", c.name, err)
			continue
		}
		if m.JA4H != c.want {
			t.Errorf("%s: JA4H = %q, want %q", c.name, m.JA4H, c.want)
		}
	}
}

// Responses get no JA4H (it is a request fingerprint).
func TestJA4HResponseNone(t *testing.T) {
	m, err := Decode("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if m.JA4H != "" {
		t.Errorf("response JA4H = %q, want empty", m.JA4H)
	}
}
