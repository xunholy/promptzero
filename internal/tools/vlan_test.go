package tools

import (
	"context"
	"strings"
	"testing"
)

// TestVLANDecodeHandler_SingleTag pins a canonical 802.1Q tag
// through the Spec handler.
func TestVLANDecodeHandler_SingleTag(t *testing.T) {
	in := "8100 0064 0800"
	out, err := vlanDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"tpid_name": "IEEE 802.1Q C-tag (Customer VLAN)"`,
		`"vid": 100`,
		`"inner_ether_type_name": "IPv4"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestVLANDecodeHandler_QinQ pins the 802.1ad double-tag
// detection path.
func TestVLANDecodeHandler_QinQ(t *testing.T) {
	in := "88A8 012C 8100 000A 0806"
	out, err := vlanDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"is_qinq": true`) {
		t.Errorf("expected is_qinq true:\n%s", out)
	}
	if !strings.Contains(out, "QinQ (IEEE 802.1ad)") {
		t.Errorf("expected QinQ note:\n%s", out)
	}
	if !strings.Contains(out, `"inner_ether_type_name": "ARP"`) {
		t.Errorf("expected ARP inner:\n%s", out)
	}
}

func TestVLANDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := vlanDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestVLANDecodeHandler_RejectsNoTag(t *testing.T) {
	_, err := vlanDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "0800AABBCCDD"})
	if err == nil {
		t.Fatal("want error when first 2 bytes are not a TPID")
	}
}
