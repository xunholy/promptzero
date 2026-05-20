package tools

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func mdnsEncodeName(s string) string {
	const digits = "0123456789ABCDEF"
	var out []byte
	for _, label := range strings.Split(s, ".") {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0x00)
	h := make([]byte, len(out)*2)
	for i, v := range out {
		h[i*2] = digits[v>>4]
		h[i*2+1] = digits[v&0x0F]
	}
	return string(h)
}

// TestMDNSDecodeHandler_AirDropQuery pins a canonical
// `_airdrop._tcp.local` PTR query with the QU bit set.
func TestMDNSDecodeHandler_AirDropQuery(t *testing.T) {
	enc := mdnsEncodeName("_airdrop._tcp.local")
	in := "0000 0000 0001 0000 0000 0000 " +
		enc + " 000C 8001"
	out, err := mdnsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"name": "_airdrop._tcp.local"`,
		`"type_name": "PTR"`,
		`"qu_unicast": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestMDNSDecodeHandler_ChromecastSRV pins an SRV record decode
// — the DNS-SD instance → host:port mapping.
func TestMDNSDecodeHandler_ChromecastSRV(t *testing.T) {
	question := mdnsEncodeName("Living-Room-TV._googlecast._tcp.local")
	target := mdnsEncodeName("LivingRoomTV.local")
	rdLen := 6 + len(target)/2
	in := "1234 8400 0001 0001 0000 0000 " +
		question + " 0021 0001 " +
		question + " 0021 8001 00000078 " +
		fmt.Sprintf("%04X ", rdLen) +
		"0000 0000 1F49 " + target
	out, err := mdnsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "SRV"`,
		`"srv_port": 8009`,
		`"srv_target": "LivingRoomTV.local"`,
		`"cache_flush": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestMDNSDecodeHandler_TXTKeyValues pins TXT decoding into
// key=value pairs.
func TestMDNSDecodeHandler_TXTKeyValues(t *testing.T) {
	question := mdnsEncodeName("test._tcp.local")
	const k1 = "0D 6D 6F 64 65 6C 3D 4E 65 74 42 6F 6F 74"
	const k2 = "0C 76 65 6E 64 6F 72 3D 41 70 70 6C 65"
	const k3 = "0B 76 65 72 73 69 6F 6E 3D 32 2E 31"
	txtBody := k1 + " " + k2 + " " + k3
	in := "1234 8400 0001 0001 0000 0000 " +
		question + " 0010 0001 " +
		question + " 0010 8001 00000078 " +
		fmt.Sprintf("%04X ", 39) +
		txtBody
	out, err := mdnsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "TXT"`,
		`"model": "NetBoot"`,
		`"vendor": "Apple"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestMDNSDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := mdnsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
