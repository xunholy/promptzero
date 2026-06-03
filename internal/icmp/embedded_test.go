// SPDX-License-Identifier: AGPL-3.0-or-later

package icmp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/ipdecode"
)

// pktString renders a decoded inner packet as JSON for substring assertions.
func pktString(p *ipdecode.Packet) string {
	b, _ := json.Marshal(p)
	return string(b)
}

// innerIPv4UDP is a minimal IPv4 (20-byte header) + UDP (8-byte header)
// packet: src 10.0.0.1 -> dst 10.0.0.2, UDP src port 0x04D2 (1234) ->
// dst port 0x0035 (53). This is exactly the IP-header + 8-byte quote an
// ICMP error message carries.
const innerIPv4UDP = "4500001C00000000401100000A0000010A00000204D2003500080000"

func TestDecode_V4DestUnreachable_EmbeddedDecoded(t *testing.T) {
	// ICMPv4 type 3 code 3 (port unreachable) + 4 unused + inner IPv4/UDP.
	r, err := Decode("0303 0000 00000000 "+innerIPv4UDP, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.DestUnreachable == nil {
		t.Fatal("DestUnreachable nil")
	}
	ep := r.DestUnreachable
	if ep.EmbeddedDecodeError != "" {
		t.Fatalf("embedded decode error: %q", ep.EmbeddedDecodeError)
	}
	if ep.EmbeddedDecoded == nil {
		t.Fatal("embedded packet not decoded")
	}
	pkt := ep.EmbeddedDecoded
	// The inner packet's addresses + UDP ports should now be surfaced.
	js := pktString(pkt)
	for _, want := range []string{"10.0.0.1", "10.0.0.2", "1234", "53"} {
		if !strings.Contains(js, want) {
			t.Errorf("embedded decode missing %q in %s", want, js)
		}
	}
}

func TestDecode_V6TimeExceeded_EmbeddedDecoded(t *testing.T) {
	// ICMPv6 Time Exceeded (type 3) now decodes its embedded IPv6 packet.
	// Inner: IPv6 header (version 6, next-header 17=UDP, payload len 8) +
	// UDP header. src ::1 -> dst ::2, ports 1234 -> 53.
	innerV6 := "60000000" + "0008" + "11" + "40" +
		"00000000000000000000000000000001" +
		"00000000000000000000000000000002" +
		"04D2003500080000"
	r, err := Decode("0300 0000 00000000 "+innerV6, "v6")
	if err != nil {
		t.Fatal(err)
	}
	if r.TimeExceeded == nil || r.TimeExceeded.EmbeddedDecoded == nil {
		t.Fatalf("v6 time-exceeded embedded not decoded: %+v", r.TimeExceeded)
	}
	js := pktString(r.TimeExceeded.EmbeddedDecoded)
	for _, want := range []string{"::1", "::2", "1234", "53"} {
		if !strings.Contains(js, want) {
			t.Errorf("v6 embedded decode missing %q in %s", want, js)
		}
	}
}

func TestDecode_EmbeddedGarbageSurfacedRaw(t *testing.T) {
	// Non-IP embedded bytes -> decode error surfaced, raw hex preserved.
	r, err := Decode("0303 0000 00000000 "+strings.Repeat("AA", 16), "")
	if err != nil {
		t.Fatal(err)
	}
	ep := r.DestUnreachable
	if ep == nil || ep.EmbeddedDecodeError == "" {
		t.Errorf("garbage embedded should surface a decode error: %+v", ep)
	}
	if ep.EmbeddedOriginalHex == "" {
		t.Errorf("raw embedded hex should still be present")
	}
}
