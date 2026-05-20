package tools

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

func ssdpHexify(s string) string {
	return hex.EncodeToString([]byte(s))
}

// TestSSDPDecodeHandler_MSearch pins a canonical M-SEARCH.
func TestSSDPDecodeHandler_MSearch(t *testing.T) {
	msg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 3\r\n" +
		"ST: upnp:rootdevice\r\n\r\n"
	out, err := ssdpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ssdpHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"kind": "M-SEARCH"`,
		`"host": "239.255.255.250:1900"`,
		`"mx_max_seconds": 3`,
		`"st_search_target": "upnp:rootdevice"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSSDPDecodeHandler_NotifyAlive pins NOTIFY ssdp:alive with
// USN deconstruction.
func TestSSDPDecodeHandler_NotifyAlive(t *testing.T) {
	msg := "NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"LOCATION: http://192.168.1.1:80/rootDesc.xml\r\n" +
		"NT: upnp:rootdevice\r\n" +
		"NTS: ssdp:alive\r\n" +
		"SERVER: Linux/3.14 UPnP/1.0 BroadCom-CPE/1.0\r\n" +
		"USN: uuid:11111111-2222-3333-4444-555555555555::upnp:rootdevice\r\n\r\n"
	out, err := ssdpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ssdpHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"kind": "NOTIFY"`,
		`"cache_max_age_seconds": 1800`,
		`"nts_notification_subtype": "ssdp:alive"`,
		`"usn_uuid": "11111111-2222-3333-4444-555555555555"`,
		`"usn_nt": "upnp:rootdevice"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSSDPDecodeHandler_SearchResponse pins an HTTP/1.1 200 OK
// search response.
func TestSSDPDecodeHandler_SearchResponse(t *testing.T) {
	msg := "HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"LOCATION: http://192.168.1.10:8080/sonos.xml\r\n" +
		"SERVER: Linux UPnP/1.0 Sonos/76.4-58210\r\n" +
		"ST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n" +
		"USN: uuid:RINCON_949F3E0F1234::urn:schemas-upnp-org:device:ZonePlayer:1\r\n\r\n"
	out, err := ssdpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ssdpHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"kind": "RESPONSE"`,
		`"status_code": 200`,
		`"status_phrase": "OK"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestSSDPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ssdpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
