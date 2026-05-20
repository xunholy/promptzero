package tools

import (
	"context"
	"strings"
	"testing"
)

// TestGSMTAPDecodeHandler_GSMUmL2BCCH pins a canonical GSM Um
// L2 BCCH frame.
func TestGSMTAPDecodeHandler_GSMUmL2BCCH(t *testing.T) {
	in := "02 04 01 00 0079 BA 19 000A0BCD 01 00 00 00 " +
		"2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B"
	out, err := gsmtapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"version": 2`,
		`"payload_type_name": "UM_L2"`,
		`"arfcn": 121`,
		`"signal_dbm": -70`,
		`"snr_db": 25`,
		`"sub_type_name": "BCCH"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestGSMTAPDecodeHandler_ARFCNUplinkPCS pins ARFCN uplink +
// PCS-band bit extraction.
func TestGSMTAPDecodeHandler_ARFCNUplinkPCS(t *testing.T) {
	in := "02 04 01 00 C050 BA 19 000A0BCD 03 00 00 00 AABBCC"
	out, err := gsmtapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"arfcn": 80`,
		`"arfcn_uplink": true`,
		`"arfcn_pcs_band": true`,
		`"sub_type_name": "RACH"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestGSMTAPDecodeHandler_LTERRC pins LTE RRC payload type.
func TestGSMTAPDecodeHandler_LTERRC(t *testing.T) {
	in := "02 04 0E 00 0000 00 00 00000001 00 00 00 00 DEADBEEF"
	out, err := gsmtapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"payload_type_name": "LTE_RRC"`,
		`"sub_type_name": "Downlink"`,
		`"payload_hex": "DEADBEEF"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestGSMTAPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := gsmtapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
