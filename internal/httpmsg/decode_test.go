package httpmsg

import (
	"strings"
	"testing"
)

// TestDecode_GET pins a typical GET request with multiple
// headers + Cookie parsing.
func TestDecode_GET(t *testing.T) {
	req := "GET /api/v1/users?limit=10 HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"User-Agent: curl/8.4.0\r\n" +
		"Accept: */*\r\n" +
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def\r\n" +
		"Cookie: session=xyz; csrf=abc123\r\n" +
		"\r\n"
	got, err := Decode(req)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.IsRequest {
		t.Error("IsRequest = false; want true")
	}
	if got.Method != "GET" {
		t.Errorf("Method = %q", got.Method)
	}
	if got.RequestURI != "/api/v1/users?limit=10" {
		t.Errorf("RequestURI = %q", got.RequestURI)
	}
	if got.Version != "HTTP/1.1" {
		t.Errorf("Version = %q", got.Version)
	}
	if got.Host != "api.example.com" {
		t.Errorf("Host = %q", got.Host)
	}
	if got.UserAgent != "curl/8.4.0" {
		t.Errorf("UserAgent = %q", got.UserAgent)
	}
	if got.Authorization == nil || got.Authorization.Scheme != "Bearer" {
		t.Errorf("Authorization = %v", got.Authorization)
	}
	if !strings.HasPrefix(got.Authorization.Parameters, "eyJhbGci") {
		t.Errorf("Authorization.Parameters = %q", got.Authorization.Parameters)
	}
	if len(got.Cookies) != 2 {
		t.Fatalf("Cookies count = %d", len(got.Cookies))
	}
	if got.Cookies[0].Name != "session" || got.Cookies[0].Value != "xyz" {
		t.Errorf("Cookies[0] = %v", got.Cookies[0])
	}
	if got.Cookies[1].Name != "csrf" || got.Cookies[1].Value != "abc123" {
		t.Errorf("Cookies[1] = %v", got.Cookies[1])
	}
}

// TestDecode_POST pins a POST request with Content-Length +
// body.
func TestDecode_POST(t *testing.T) {
	body := `{"name":"Alice","age":30}`
	req := "POST /users HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: " + intToStr(len(body)) + "\r\n" +
		"\r\n" + body
	got, err := Decode(req)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Method != "POST" {
		t.Errorf("Method = %q", got.Method)
	}
	if got.ContentLength == nil || *got.ContentLength != int64(len(body)) {
		t.Errorf("ContentLength = %v; want %d", got.ContentLength, len(body))
	}
	if got.BodyRaw != body {
		t.Errorf("BodyRaw = %q", got.BodyRaw)
	}
}

// TestDecode_200OK pins a 200 OK response with Set-Cookie.
func TestDecode_200OK(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\n" +
		"Server: nginx/1.24.0\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 13\r\n" +
		"Set-Cookie: session=newvalue; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600\r\n" +
		"\r\n" +
		`{"ok": true}`
	got, err := Decode(resp)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.IsResponse {
		t.Error("IsResponse = false; want true")
	}
	if got.StatusCode != 200 {
		t.Errorf("StatusCode = %d", got.StatusCode)
	}
	if got.StatusName != "OK" {
		t.Errorf("StatusName = %q", got.StatusName)
	}
	if got.Server != "nginx/1.24.0" {
		t.Errorf("Server = %q", got.Server)
	}
	if len(got.SetCookies) != 1 {
		t.Fatalf("SetCookies count = %d", len(got.SetCookies))
	}
	sc := got.SetCookies[0]
	if sc.Name != "session" || sc.Value != "newvalue" {
		t.Errorf("SetCookie = %v", sc)
	}
	if sc.Attributes["Path"] != "/" {
		t.Errorf("Path = %q", sc.Attributes["Path"])
	}
	if _, ok := sc.Attributes["HttpOnly"]; !ok {
		t.Error("HttpOnly attribute missing")
	}
	if _, ok := sc.Attributes["Secure"]; !ok {
		t.Error("Secure attribute missing")
	}
	if sc.Attributes["SameSite"] != "Lax" {
		t.Errorf("SameSite = %q", sc.Attributes["SameSite"])
	}
	if sc.Attributes["Max-Age"] != "3600" {
		t.Errorf("Max-Age = %q", sc.Attributes["Max-Age"])
	}
}

// TestDecode_404 pins a 404 Not Found response.
func TestDecode_404(t *testing.T) {
	resp := "HTTP/1.1 404 Not Found\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	got, err := Decode(resp)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.StatusCode != 404 {
		t.Errorf("StatusCode = %d", got.StatusCode)
	}
	if got.StatusName != "Not Found" {
		t.Errorf("StatusName = %q", got.StatusName)
	}
}

// TestDecode_ChunkedTransferEncoding pins a chunked-body
// response.
func TestDecode_ChunkedTransferEncoding(t *testing.T) {
	// Two chunks: "Hello, " (7 bytes = 0x7) + "World!" (6 = 0x6),
	// terminated by 0-length chunk.
	resp := "HTTP/1.1 200 OK\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"7\r\n" +
		"Hello, \r\n" +
		"6\r\n" +
		"World!\r\n" +
		"0\r\n" +
		"\r\n"
	got, err := Decode(resp)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.TransferEncoding != "chunked" {
		t.Errorf("TransferEncoding = %q", got.TransferEncoding)
	}
	if len(got.ChunkedBody) != 2 {
		t.Fatalf("ChunkedBody count = %d", len(got.ChunkedBody))
	}
	if got.ChunkedBody[0].Length != 7 || got.ChunkedBody[0].DataText != "Hello, " {
		t.Errorf("Chunk[0] = %v", got.ChunkedBody[0])
	}
	if got.ChunkedBody[1].Length != 6 || got.ChunkedBody[1].DataText != "World!" {
		t.Errorf("Chunk[1] = %v", got.ChunkedBody[1])
	}
}

// TestDecode_AuthorizationSchemes pins Basic / Bearer / Digest
// scheme detection.
func TestDecode_AuthorizationSchemes(t *testing.T) {
	cases := []struct {
		header string
		scheme string
	}{
		{"Basic dXNlcjpwYXNz", "Basic"},
		{"Bearer abc.def.ghi", "Bearer"},
		{"Digest username=\"alice\", realm=\"example.com\"", "Digest"},
	}
	for _, c := range cases {
		req := "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: " + c.header + "\r\n\r\n"
		got, err := Decode(req)
		if err != nil {
			t.Fatalf("Decode(%q): %v", c.header, err)
		}
		if got.Authorization == nil || got.Authorization.Scheme != c.scheme {
			t.Errorf("%s: Scheme = %v", c.header, got.Authorization)
		}
	}
}

// TestDecode_StatusCodeTable spot-checks the table coverage.
func TestDecode_StatusCodeTable(t *testing.T) {
	cases := map[int]string{
		100: "Continue",
		101: "Switching Protocols",
		200: "OK",
		201: "Created",
		301: "Moved Permanently",
		302: "Found",
		400: "Bad Request",
		401: "Unauthorized",
		404: "Not Found",
		418: "I'm a teapot (RFC 2324)",
		429: "Too Many Requests",
		500: "Internal Server Error",
		502: "Bad Gateway",
		503: "Service Unavailable",
		511: "Network Authentication Required",
	}
	for c, want := range cases {
		if got := statusName(c); got != want {
			t.Errorf("statusName(%d) = %q; want %q", c, got, want)
		}
	}
}

// TestDecode_HeaderContinuation pins line-continuation folding.
func TestDecode_HeaderContinuation(t *testing.T) {
	req := "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"X-Custom: first-value;\r\n" +
		" second-value\r\n" +
		"\r\n"
	got, err := Decode(req)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var custom *Header
	for _, h := range got.Headers {
		if h.Name == "X-Custom" {
			custom = h
			break
		}
	}
	if custom == nil {
		t.Fatal("X-Custom header missing")
	}
	if !strings.Contains(custom.Value, "second-value") {
		t.Errorf("X-Custom value not folded: %q", custom.Value)
	}
}

// TestDecode_BinaryBody surfaces non-printable bodies as hex.
func TestDecode_BinaryBody(t *testing.T) {
	binBody := string([]byte{0x00, 0x01, 0x02, 0xFF})
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Length: 4\r\n" +
		"\r\n" + binBody
	got, err := Decode(resp)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.BodyHex != "000102FF" {
		t.Errorf("BodyHex = %q", got.BodyHex)
	}
	if got.BodyRaw != "" {
		t.Errorf("BodyRaw should be empty for binary: %q", got.BodyRaw)
	}
}

// TestDecode_EmptyInput rejects empty input.
func TestDecode_EmptyInput(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty input: want error")
	}
}

// TestDecode_MalformedRequestLine rejects incomplete request
// lines.
func TestDecode_MalformedRequestLine(t *testing.T) {
	if _, err := Decode("GET\r\n\r\n"); err == nil {
		t.Error("missing URI/version: want error")
	}
	if _, err := Decode("GET /only\r\n\r\n"); err == nil {
		t.Error("missing version: want error")
	}
}

// TestDecode_MalformedStatusLine rejects non-numeric status
// codes.
func TestDecode_MalformedStatusLine(t *testing.T) {
	if _, err := Decode("HTTP/1.1 ABC OK\r\n\r\n"); err == nil {
		t.Error("non-numeric status: want error")
	}
}

// TestParseSetCookie spot-checks the Set-Cookie attribute
// parser.
func TestParseSetCookie(t *testing.T) {
	sc := parseSetCookie("foo=bar; Path=/; HttpOnly; Max-Age=86400; SameSite=Strict")
	if sc.Name != "foo" || sc.Value != "bar" {
		t.Errorf("Name/Value = %q/%q", sc.Name, sc.Value)
	}
	if sc.Attributes["Path"] != "/" {
		t.Errorf("Path = %q", sc.Attributes["Path"])
	}
	if sc.Attributes["Max-Age"] != "86400" {
		t.Errorf("Max-Age = %q", sc.Attributes["Max-Age"])
	}
	if _, ok := sc.Attributes["HttpOnly"]; !ok {
		t.Error("HttpOnly missing")
	}
}

// TestParseCookieHeader spot-checks the cookie pair parser.
func TestParseCookieHeader(t *testing.T) {
	cookies := parseCookieHeader("a=1; b=2; c=value-with-equals=inside")
	if len(cookies) != 3 {
		t.Fatalf("count = %d", len(cookies))
	}
	if cookies[2].Name != "c" || cookies[2].Value != "value-with-equals=inside" {
		t.Errorf("cookies[2] = %v", cookies[2])
	}
}

// intToStr converts an int to its base-10 string (avoids
// importing strconv just for the test).
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var out []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	if neg {
		out = append([]byte{'-'}, out...)
	}
	return string(out)
}
