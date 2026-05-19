package tools

import (
	"context"
	"strings"
	"testing"
)

// TestVXLANDecodeHandler_StandardVNI pins a canonical VXLAN
// header + inner Ethernet/IPv4 through the Spec handler.
func TestVXLANDecodeHandler_StandardVNI(t *testing.T) {
	in := "08000000 ABCDEF 00 AABBCCDDEEFF 112233445566 0800 DEADBEEF"
	out, err := vxlanDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"variant": "standard VXLAN (RFC 7348)"`,
		`"vni": 11259375`, // 0xABCDEF
		`"dst_mac": "AA:BB:CC:DD:EE:FF"`,
		`"src_mac": "11:22:33:44:55:66"`,
		`"ether_type_name": "IPv4"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestVXLANDecodeHandler_GBP pins the Cisco VXLAN-GBP variant.
func TestVXLANDecodeHandler_GBP(t *testing.T) {
	in := "88001234 000064 00 AABBCCDDEEFF 112233445566 0806 ABCD"
	out, err := vxlanDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "VXLAN-GBP (Cisco Group-Based Policy)") {
		t.Errorf("expected VXLAN-GBP variant:\n%s", out)
	}
	if !strings.Contains(out, `"group_policy_id_hex": "0x1234"`) {
		t.Errorf("expected GroupPolicyID 0x1234:\n%s", out)
	}
}

func TestVXLANDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := vxlanDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestVXLANDecodeHandler_RejectsTruncatedHeader(t *testing.T) {
	_, err := vxlanDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "08000000"})
	if err == nil {
		t.Fatal("want error for truncated header")
	}
}
