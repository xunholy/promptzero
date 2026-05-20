package dhcpv6

import (
	"strings"
	"testing"
)

func TestDecode_SOLICIT_WithClientID_IANA_ORO_ElapsedTime(t *testing.T) {
	// SOLICIT (msg type 1), txid 0xABCDEF.
	// Client ID DUID-LLT: hw=1 Ethernet, time=0x12345678,
	//   LL=001122334455.
	// IA_NA: IAID=1 T1=3600 T2=7200, no sub-opts.
	// Option Request: codes 23 (DNS), 24 (Domain List).
	// Elapsed Time: 100 centiseconds (1 s).
	in := "01 ABCDEF" +
		"0001 000E 0001 0001 12345678 001122334455" +
		"0003 000C 00000001 00000E10 00001C20" +
		"0006 0004 0017 0018" +
		"0008 0002 0064"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageType != 1 || r.MessageTypeName != "SOLICIT" {
		t.Errorf("msg type: %d %q", r.MessageType, r.MessageTypeName)
	}
	if r.TransactionID != 0xABCDEF {
		t.Errorf("txid: 0x%06X", r.TransactionID)
	}
	if len(r.Options) != 4 {
		t.Fatalf("options: %d", len(r.Options))
	}
	// Client ID DUID-LLT.
	if r.Options[0].ClientID == nil {
		t.Fatal("client ID nil")
	}
	cid := r.Options[0].ClientID
	if cid.Type != 1 || cid.TypeName != "DUID-LLT (Link-Layer + Time)" {
		t.Errorf("DUID type: %+v", cid)
	}
	if cid.HardwareType == nil || *cid.HardwareType != 1 {
		t.Errorf("hardware type: %+v", cid.HardwareType)
	}
	if cid.LinkLayerHex != "001122334455" {
		t.Errorf("link layer: %q", cid.LinkLayerHex)
	}
	// IA_NA.
	if r.Options[1].IANonTemp == nil {
		t.Fatal("IA_NA nil")
	}
	ia := r.Options[1].IANonTemp
	if ia.IAID != 1 || ia.T1Seconds != 3600 || ia.T2Seconds != 7200 {
		t.Errorf("IA_NA: %+v", ia)
	}
	// ORO.
	if got := r.Options[2].OptionRequest; len(got) != 2 ||
		got[0] != 23 || got[1] != 24 {
		t.Errorf("option request: %+v", got)
	}
	// Elapsed Time.
	if r.Options[3].ElapsedTimeCs == nil ||
		*r.Options[3].ElapsedTimeCs != 100 {
		t.Errorf("elapsed time: %+v", r.Options[3].ElapsedTimeCs)
	}
}

func TestDecode_ADVERTISE_WithServerID_IANA_IAADDR(t *testing.T) {
	// ADVERTISE (msg type 2), txid 0xABCDEF.
	// Server ID DUID-EN: enterprise=9 (Cisco), identifier=0123456789ABCDEF.
	// IA_NA: IAID=1 T1=3600 T2=7200 + nested IAADDR.
	// IAADDR: 2001:db8::1, preferred=86400, valid=172800.
	in := "02 ABCDEF" +
		"0002 000E 0002 00000009 0123456789ABCDEF" +
		"0003 0028 00000001 00000E10 00001C20" +
		"0005 0018 20010DB8000000000000000000000001 00015180 0002A300"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageTypeName != "ADVERTISE" {
		t.Errorf("msg type: %q", r.MessageTypeName)
	}
	if r.Options[0].ServerID == nil ||
		r.Options[0].ServerID.TypeName != "DUID-EN (Enterprise)" {
		t.Errorf("server ID: %+v", r.Options[0].ServerID)
	}
	sid := r.Options[0].ServerID
	if sid.EnterpriseNumber == nil || *sid.EnterpriseNumber != 9 {
		t.Errorf("enterprise: %+v", sid.EnterpriseNumber)
	}
	ia := r.Options[1].IANonTemp
	if ia == nil {
		t.Fatal("IA_NA nil")
	}
	if len(ia.SubOptions) != 1 {
		t.Fatalf("IA_NA sub-options: %d", len(ia.SubOptions))
	}
	addr := ia.SubOptions[0].IAAddress
	if addr == nil {
		t.Fatal("IAADDR nil")
	}
	if addr.Address != "2001:db8::1" {
		t.Errorf("address: %q", addr.Address)
	}
	if addr.PreferredLifetimeSec != 86400 || addr.ValidLifetimeSec != 172800 {
		t.Errorf("lifetimes: pref=%d valid=%d",
			addr.PreferredLifetimeSec, addr.ValidLifetimeSec)
	}
}

func TestDecode_REPLY_StatusCodeSuccess(t *testing.T) {
	// Status Code: 0 (Success) + message "OK".
	in := "07 ABCDEF 000D 0004 0000 4F4B"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageTypeName != "REPLY" {
		t.Errorf("msg type: %q", r.MessageTypeName)
	}
	sc := r.Options[0].StatusCode
	if sc == nil {
		t.Fatal("status code nil")
	}
	if sc.Code != 0 || sc.CodeName != "Success" {
		t.Errorf("status: %+v", sc)
	}
	if sc.Message != "OK" {
		t.Errorf("status message: %q", sc.Message)
	}
}

func TestDecode_REQUEST_WithIAPD(t *testing.T) {
	// IA_PD: IAID=1 T1=3600 T2=7200 + nested IAPREFIX.
	// IAPREFIX: preferred=3600, valid=7200, prefix_len=56,
	// prefix=2001:db8:a::/56.
	in := "03 ABCDEF" +
		"0019 0029 00000001 00000E10 00001C20" +
		"001A 0019 00000E10 00001C20 38 20010DB8000A0000000000000000000000"

	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	pd := r.Options[0].IAPDelegate
	if pd == nil {
		t.Fatal("IA_PD nil")
	}
	if len(pd.SubOptions) != 1 {
		t.Fatalf("IA_PD sub-options: %d", len(pd.SubOptions))
	}
	pfx := pd.SubOptions[0].IAPrefix
	if pfx == nil {
		t.Fatal("IAPREFIX nil")
	}
	if pfx.PrefixLength != 56 {
		t.Errorf("prefix length: %d", pfx.PrefixLength)
	}
	if pfx.Prefix != "2001:db8:a::" {
		t.Errorf("prefix: %q", pfx.Prefix)
	}
}

func TestDecode_REPLY_WithDNSServers(t *testing.T) {
	// DNS Servers: 2001:4860:4860::8888 (Google).
	in := "07 ABCDEF 0017 0010 20014860486000000000000000008888"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	dns := r.Options[0].DNSServers
	if len(dns) != 1 || dns[0] != "2001:4860:4860::8888" {
		t.Errorf("DNS: %+v", dns)
	}
}

func TestDecode_RelayForward(t *testing.T) {
	// RELAY-FORW (12), hop=1, link=fe80::1, peer=fe80::2,
	// inner OPTION_RELAY_MSG=encapsulated 4-byte SOLICIT.
	in := "0C 01" +
		"FE800000 00000000 00000000 00000001" +
		"FE800000 00000000 00000000 00000002" +
		"0009 0004 01ABCDEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageTypeName != "RELAY-FORW" {
		t.Errorf("msg type: %q", r.MessageTypeName)
	}
	if r.HopCount == nil || *r.HopCount != 1 {
		t.Errorf("hop count: %+v", r.HopCount)
	}
	if r.LinkAddress != "fe80::1" || r.PeerAddress != "fe80::2" {
		t.Errorf("relay addrs: link=%q peer=%q", r.LinkAddress, r.PeerAddress)
	}
	if r.Options[0].RelayMsgHex == nil || *r.Options[0].RelayMsgHex != "01ABCDEF" {
		t.Errorf("relay msg: %+v", r.Options[0].RelayMsgHex)
	}
}

func TestDecode_RapidCommitFlagOption(t *testing.T) {
	// OPTION_RAPID_COMMIT (code 14, length 0).
	in := "01 ABCDEF 000E 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Options[0].CodeName != "OPTION_RAPID_COMMIT" ||
		r.Options[0].Length != 0 {
		t.Errorf("rapid commit: %+v", r.Options[0])
	}
}

func TestDecode_MessageTypeTable(t *testing.T) {
	cases := map[int]string{
		1:  "SOLICIT",
		2:  "ADVERTISE",
		3:  "REQUEST",
		4:  "CONFIRM",
		5:  "RENEW",
		6:  "REBIND",
		7:  "REPLY",
		8:  "RELEASE",
		9:  "DECLINE",
		10: "RECONFIGURE",
		11: "INFORMATION-REQUEST",
		12: "RELAY-FORW",
		13: "RELAY-REPL",
	}
	for k, v := range cases {
		if got := messageTypeName(k); got != v {
			t.Errorf("messageTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_OptionCodeSpotCheck(t *testing.T) {
	cases := map[int]string{
		1:  "OPTION_CLIENTID",
		3:  "OPTION_IA_NA",
		5:  "OPTION_IAADDR",
		13: "OPTION_STATUS_CODE",
		23: "OPTION_DNS_SERVERS",
		25: "OPTION_IA_PD",
	}
	for k, v := range cases {
		if got := optionCodeName(k); got != v {
			t.Errorf("optionCodeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_DUIDTypeTable(t *testing.T) {
	cases := map[int]string{
		1: "DUID-LLT (Link-Layer + Time)",
		2: "DUID-EN (Enterprise)",
		3: "DUID-LL (Link-Layer)",
		4: "DUID-UUID",
	}
	for k, v := range cases {
		if got := duidTypeName(k); got != v {
			t.Errorf("duidTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_StatusCodeTable(t *testing.T) {
	cases := map[int]string{
		0: "Success",
		1: "UnspecFail",
		2: "NoAddrsAvail",
		3: "NoBinding",
		4: "NotOnLink",
		5: "UseMulticast",
		6: "NoPrefixAvail",
	}
	for k, v := range cases {
		if got := statusCodeName(k); got != v {
			t.Errorf("statusCodeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_UncataloguedMessageType(t *testing.T) {
	in := "63 ABCDEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(r.MessageTypeName, "uncatalogued") {
		t.Errorf("expected uncatalogued name: %q", r.MessageTypeName)
	}
}

func TestDecode_TruncatedOption_Note(t *testing.T) {
	// Option code 1 declares length 10 but only 4 bytes follow.
	in := "01 ABCDEF 0001 000A 00010001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Notes) == 0 {
		t.Fatal("expected truncation note")
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "01 AB",
		"short":   "01",
		"bad hex": "ZZ ABCDEF",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
