package ssdp

import (
	"encoding/hex"
	"strings"
	"testing"
)

// hexify converts an ASCII SSDP message to hex for feeding the
// hex-input decoder (matches operator workflow of pasting bytes
// from a packet capture).
func hexify(s string) string {
	return hex.EncodeToString([]byte(s))
}

// TestDecodeMSearchRootDevice pins the canonical UPnP discovery
// query.
func TestDecodeMSearchRootDevice(t *testing.T) {
	msg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 3\r\n" +
		"ST: upnp:rootdevice\r\n\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Kind != KindSearch {
		t.Errorf("kind: got %q want M-SEARCH", r.Kind)
	}
	if r.StartLine != "M-SEARCH * HTTP/1.1" {
		t.Errorf("startLine: got %q", r.StartLine)
	}
	if r.Host != "239.255.255.250:1900" {
		t.Errorf("host: got %q", r.Host)
	}
	if r.MAN != "\"ssdp:discover\"" {
		t.Errorf("man: got %q", r.MAN)
	}
	if r.MX != 3 {
		t.Errorf("mx: got %d want 3", r.MX)
	}
	if r.ST != "upnp:rootdevice" {
		t.Errorf("st: got %q", r.ST)
	}
}

// TestDecodeNotifyAlive pins a canonical NOTIFY ssdp:alive
// announcement.
func TestDecodeNotifyAlive(t *testing.T) {
	msg := "NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"LOCATION: http://192.168.1.1:80/rootDesc.xml\r\n" +
		"NT: upnp:rootdevice\r\n" +
		"NTS: ssdp:alive\r\n" +
		"SERVER: Linux/3.14 UPnP/1.0 BroadCom-CPE/1.0\r\n" +
		"USN: uuid:11111111-2222-3333-4444-555555555555::upnp:rootdevice\r\n\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Kind != KindNotify {
		t.Errorf("kind: got %q want NOTIFY", r.Kind)
	}
	if r.CacheControl != "max-age=1800" {
		t.Errorf("cache-control: got %q", r.CacheControl)
	}
	if r.CacheMaxAgeSecs != 1800 {
		t.Errorf("cacheMaxAge: got %d want 1800", r.CacheMaxAgeSecs)
	}
	if r.Location != "http://192.168.1.1:80/rootDesc.xml" {
		t.Errorf("location: got %q", r.Location)
	}
	if r.NT != "upnp:rootdevice" {
		t.Errorf("nt: got %q", r.NT)
	}
	if r.NTS != "ssdp:alive" {
		t.Errorf("nts: got %q", r.NTS)
	}
	if !strings.Contains(r.Server, "UPnP/1.0") {
		t.Errorf("server missing UPnP/1.0: %q", r.Server)
	}
	if r.USNUUID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("usnUUID: got %q", r.USNUUID)
	}
	if r.USNNT != "upnp:rootdevice" {
		t.Errorf("usnNT: got %q", r.USNNT)
	}
}

// TestDecodeNotifyByebye pins a ssdp:byebye shutdown
// announcement.
func TestDecodeNotifyByebye(t *testing.T) {
	msg := "NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"NT: urn:schemas-upnp-org:device:MediaServer:1\r\n" +
		"NTS: ssdp:byebye\r\n" +
		"USN: uuid:abcdef00::urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.NTS != "ssdp:byebye" {
		t.Errorf("nts: got %q want ssdp:byebye", r.NTS)
	}
	if r.NT != "urn:schemas-upnp-org:device:MediaServer:1" {
		t.Errorf("nt: got %q", r.NT)
	}
}

// TestDecodeSearchResponse pins an HTTP/1.1 200 OK response.
func TestDecodeSearchResponse(t *testing.T) {
	msg := "HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"DATE: Wed, 21 May 2026 03:00:00 GMT\r\n" +
		"EXT:\r\n" +
		"LOCATION: http://192.168.1.10:8080/sonos.xml\r\n" +
		"SERVER: Linux UPnP/1.0 Sonos/76.4-58210\r\n" +
		"ST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n" +
		"USN: uuid:RINCON_949F3E0F1234::urn:schemas-upnp-org:device:ZonePlayer:1\r\n" +
		"X-RINCON-HOUSEHOLD: Sonos_AAAA\r\n\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Kind != KindResponse {
		t.Errorf("kind: got %q want RESPONSE", r.Kind)
	}
	if r.StatusCode != 200 {
		t.Errorf("statusCode: got %d want 200", r.StatusCode)
	}
	if r.StatusPhrase != "OK" {
		t.Errorf("statusPhrase: got %q", r.StatusPhrase)
	}
	if r.ST != "urn:schemas-upnp-org:device:ZonePlayer:1" {
		t.Errorf("st: got %q", r.ST)
	}
	if r.OtherHeaders["X-RINCON-HOUSEHOLD"] != "Sonos_AAAA" {
		t.Errorf("vendor header: got %q", r.OtherHeaders["X-RINCON-HOUSEHOLD"])
	}
	if r.OtherHeaders["DATE"] == "" {
		t.Errorf("DATE header should be surfaced as generic")
	}
}

// TestDecodeUpnpIGD pins an InternetGatewayDevice M-SEARCH —
// the entry point for UPnP-IGD WAN-port-forwarding attacks.
func TestDecodeUpnpIGD(t *testing.T) {
	msg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.ST, "InternetGatewayDevice") {
		t.Errorf("st should reference IGD: %q", r.ST)
	}
}

// TestDecodeBootIDUpdate pins a NOTIFY ssdp:update with the
// UPnP 1.1 BootID / ConfigID extension headers.
func TestDecodeBootIDUpdate(t *testing.T) {
	msg := "NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"NT: upnp:rootdevice\r\n" +
		"NTS: ssdp:update\r\n" +
		"USN: uuid:device-uuid::upnp:rootdevice\r\n" +
		"LOCATION: http://192.168.1.50:80/desc.xml\r\n" +
		"BOOTID.UPNP.ORG: 1234\r\n" +
		"CONFIGID.UPNP.ORG: 5\r\n" +
		"NEXTBOOTID.UPNP.ORG: 1235\r\n\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.NTS != "ssdp:update" {
		t.Errorf("nts: got %q want ssdp:update", r.NTS)
	}
	if r.BootID != "1234" {
		t.Errorf("bootID: got %q want 1234", r.BootID)
	}
	if r.ConfigID != "5" {
		t.Errorf("configID: got %q want 5", r.ConfigID)
	}
}

// TestExtractMaxAge handles comma-separated cache-control lists.
func TestExtractMaxAge(t *testing.T) {
	cases := map[string]int{
		"max-age=1800":               1800,
		"max-age=3600":               3600,
		"no-cache, max-age=600":      600,
		"public, max-age=86400, foo": 86400,
		"MAX-AGE=42":                 42,
		"no-cache":                   0,
		"":                           0,
	}
	for in, want := range cases {
		if got := extractMaxAge(in); got != want {
			t.Errorf("extractMaxAge(%q) = %d want %d", in, got, want)
		}
	}
}

// TestSplitUSN deconstructs various USN shapes.
func TestSplitUSN(t *testing.T) {
	cases := []struct {
		in, uuid, nt string
	}{
		{"uuid:11111111-2222-3333-4444-555555555555::upnp:rootdevice",
			"11111111-2222-3333-4444-555555555555", "upnp:rootdevice"},
		{"uuid:device-uuid", "device-uuid", ""},
		{"uuid:abc::urn:schemas-upnp-org:device:Foo:1",
			"abc", "urn:schemas-upnp-org:device:Foo:1"},
		{"NotAUuid", "", ""},
	}
	for _, c := range cases {
		uuid, nt := splitUSN(c.in)
		if uuid != c.uuid || nt != c.nt {
			t.Errorf("splitUSN(%q) = (%q, %q) want (%q, %q)",
				c.in, uuid, nt, c.uuid, c.nt)
		}
	}
}

// TestClassifyStartLine covers each catalogued message kind.
func TestClassifyStartLine(t *testing.T) {
	cases := map[string]MessageKind{
		"M-SEARCH * HTTP/1.1":    KindSearch,
		"m-search * HTTP/1.1":    KindSearch,
		"NOTIFY * HTTP/1.1":      KindNotify,
		"notify * HTTP/1.1":      KindNotify,
		"HTTP/1.1 200 OK":        KindResponse,
		"HTTP/1.0 404 Not Found": KindResponse,
		"GARBAGE":                KindUncatalogued,
	}
	for in, want := range cases {
		if got := classifyStartLine(in); got != want {
			t.Errorf("classifyStartLine(%q) = %q want %q", in, got, want)
		}
	}
}

func TestDecodeRejectsEmpty(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecodeRejectsOddNibbles(t *testing.T) {
	if _, err := Decode("ABC"); err == nil {
		t.Fatal("want error for odd-length input")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZZZ"); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
