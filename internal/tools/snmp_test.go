package tools

import (
	"context"
	"strings"
	"testing"
)

// TestSNMPPacketDecodeHandler_v2cGetRequest pins a hand-crafted
// SNMPv2c GetRequest for sysDescr.0 through the Spec handler.
//
// Built manually:
//
//	30 29                                      SEQUENCE
//	  02 01 01                                   INTEGER version = 1 (v2c)
//	  04 06 70 75 62 6c 69 63                    OCTET STRING "public"
//	  A0 1C                                      GetRequest PDU
//	    02 04 12 34 56 78                         INTEGER request-id 0x12345678
//	    02 01 00                                  INTEGER error-status = 0
//	    02 01 00                                  INTEGER error-index = 0
//	    30 0E                                     VarBindList SEQUENCE
//	      30 0C                                     VarBind SEQUENCE
//	        06 08 2B 06 01 02 01 01 01 00         OID 1.3.6.1.2.1.1.1.0
//	        05 00                                  NULL
func TestSNMPPacketDecodeHandler_v2cGetRequest(t *testing.T) {
	hex := "30 29 02 01 01 04 06 70 75 62 6c 69 63 " +
		"A0 1C 02 04 12 34 56 78 02 01 00 02 01 00 " +
		"30 0E 30 0C 06 08 2B 06 01 02 01 01 01 00 05 00"
	out, err := snmpPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": hex})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"version": 1`) {
		t.Errorf("expected version 1:\n%s", out)
	}
	if !strings.Contains(out, `"community": "public"`) {
		t.Errorf("expected community public:\n%s", out)
	}
	if !strings.Contains(out, `"type_name": "GetRequest"`) {
		t.Errorf("expected GetRequest:\n%s", out)
	}
	if !strings.Contains(out, `"oid": "1.3.6.1.2.1.1.1.0"`) {
		t.Errorf("expected OID:\n%s", out)
	}
	if !strings.Contains(out, `"oid_name": "sysDescr.0"`) {
		t.Errorf("expected oid_name sysDescr.0:\n%s", out)
	}
}

func TestSNMPPacketDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := snmpPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestSNMPPacketDecodeHandler_RejectsBadOuter(t *testing.T) {
	_, err := snmpPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": "02 01 01"})
	if err == nil {
		t.Fatal("want error for non-SEQUENCE outer")
	}
}
