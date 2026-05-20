package tacacs

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestDecode_Auth_START_Unencrypted(t *testing.T) {
	// Version=0xC0 (Major=12, Minor=0), Type=1 (Auth),
	// Seq=1, Flags=0x01 (UNENCRYPTED), Session=0x12345678,
	// Length=24. Body: Action=1 (LOGIN), Priv=15, AuthType=
	// 2 (PAP), Service=1 (LOGIN), User="admin" (5), Port=
	// "tty0" (4), RemAddr="1.2.3.4" (7), Data=0.
	in := "C0 01 01 01 12345678 00000018" +
		"01 0F 02 01 05 04 07 00" +
		"61646D696E 74747930 312E322E332E34"
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.VersionMajor != 12 || r.VersionMinor != 0 {
		t.Errorf("version: %d.%d", r.VersionMajor, r.VersionMinor)
	}
	if r.PacketTypeName != "Authentication" {
		t.Errorf("packet type: %q", r.PacketTypeName)
	}
	if !r.FlagUnencrypted {
		t.Errorf("UNENCRYPTED flag should be set")
	}
	if r.AuthenticationStart == nil {
		t.Fatal("AUTH START nil")
	}
	a := r.AuthenticationStart
	if a.ActionName != "LOGIN" || a.AuthTypeName != "PAP" ||
		a.ServiceName != "LOGIN" {
		t.Errorf("enums: %+v", a)
	}
	if a.User != "admin" || a.Port != "tty0" ||
		a.RemoteAddr != "1.2.3.4" {
		t.Errorf("strings: %+v", a)
	}
}

func TestDecode_Auth_REPLY_PassWithMessage(t *testing.T) {
	// AUTH REPLY: Status=1 (PASS), Flags=0, ServerMsg=
	// "Welcome" (7), Data=0.
	in := "C0 01 02 01 12345678 0000000D" +
		"01 00 0007 0000 57656C636F6D65"
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.AuthenticationReply == nil {
		t.Fatal("AUTH REPLY nil")
	}
	a := r.AuthenticationReply
	if a.StatusName != "PASS" {
		t.Errorf("status: %q", a.StatusName)
	}
	if a.ServerMsg != "Welcome" {
		t.Errorf("server msg: %q", a.ServerMsg)
	}
}

func TestDecode_Auth_CONTINUE_WithUserMessage(t *testing.T) {
	// AUTH CONTINUE: UserMsg="pass123" (7), Data=0, no ABORT.
	in := "C0 01 03 01 12345678 0000000C" +
		"0007 0000 00 70617373313233"
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.AuthenticationCont == nil {
		t.Fatal("AUTH CONTINUE nil")
	}
	c := r.AuthenticationCont
	if c.UserMsg != "pass123" {
		t.Errorf("user msg: %q", c.UserMsg)
	}
	if c.FlagAbort {
		t.Errorf("ABORT flag should be clear")
	}
}

func TestDecode_Author_REQUEST(t *testing.T) {
	// AUTHOR REQUEST: AuthMethod=6 (TACACSPLUS), Priv=15,
	// AuthType=1 (ASCII), Service=1 (LOGIN), User="admin",
	// Port="tty0", RemAddr="1.2.3.4", ArgCount=1, Arg=
	// "service=shell" (13).
	in := "C0 02 01 01 12345678 00000026" +
		"06 0F 01 01 05 04 07 01 0D" +
		"61646D696E 74747930 312E322E332E34" +
		"736572766963653D7368656C6C"
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.AuthorizationReq == nil {
		t.Fatal("AUTHOR REQUEST nil")
	}
	a := r.AuthorizationReq
	if a.AuthTypeName != "ASCII" || a.ServiceName != "LOGIN" {
		t.Errorf("enums: %+v", a)
	}
	if a.User != "admin" {
		t.Errorf("user: %q", a.User)
	}
	if len(a.Args) != 1 || a.Args[0] != "service=shell" {
		t.Errorf("args: %+v", a.Args)
	}
}

func TestDecode_Author_RESPONSE_PassAdd(t *testing.T) {
	// AUTHOR RESPONSE: Status=1 (PASS_ADD), ArgCount=1,
	// ServerMsg="OK" (2), Data=0, Arg="priv-lvl=15" (11).
	in := "C0 02 02 01 12345678 00000014" +
		"01 01 0002 0000 0B 4F4B 707269762D6C766C3D3135"
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := r.AuthorizationResp
	if a == nil {
		t.Fatal("AUTHOR RESPONSE nil")
	}
	if a.StatusName != "PASS_ADD" {
		t.Errorf("status: %q", a.StatusName)
	}
	if a.ServerMsg != "OK" {
		t.Errorf("server msg: %q", a.ServerMsg)
	}
	if len(a.Args) != 1 || a.Args[0] != "priv-lvl=15" {
		t.Errorf("args: %+v", a.Args)
	}
}

func TestDecode_Acct_REQUEST_StartFlag(t *testing.T) {
	// ACCT REQUEST: Flags=0x02 (START), AuthMethod=6,
	// Priv=15, AuthType=1, Service=1, User="admin",
	// Port="tty0", RemAddr="1.2.3.4", ArgCount=1, Arg=
	// "task_id=42" (10).
	in := "C0 03 01 01 12345678 00000024" +
		"02 06 0F 01 01 05 04 07 01 0A" +
		"61646D696E 74747930 312E322E332E34" +
		"7461736B5F69643D3432"
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := r.AccountingReq
	if a == nil {
		t.Fatal("ACCT REQUEST nil")
	}
	if !a.FlagStart || a.FlagStop || a.FlagWatchdog {
		t.Errorf("flags: %+v", a)
	}
	if a.User != "admin" {
		t.Errorf("user: %q", a.User)
	}
	if len(a.Args) != 1 || a.Args[0] != "task_id=42" {
		t.Errorf("args: %+v", a.Args)
	}
}

func TestDecode_Acct_REPLY_Success(t *testing.T) {
	// ACCT REPLY: ServerMsg="OK" (2), Data=0, Status=1
	// (SUCCESS).
	in := "C0 03 02 01 12345678 00000007" +
		"0002 0000 01 4F4B"
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := r.AccountingReply
	if a == nil {
		t.Fatal("ACCT REPLY nil")
	}
	if a.StatusName != "SUCCESS" {
		t.Errorf("status: %q", a.StatusName)
	}
	if a.ServerMsg != "OK" {
		t.Errorf("server msg: %q", a.ServerMsg)
	}
}

func TestDecode_EncryptedBody_NoKey_Note(t *testing.T) {
	// Same headers as Test 1 but Flags=0x00 (encrypted),
	// body is opaque bytes.
	in := "C0 01 01 00 12345678 00000018" +
		"112233445566778899AABBCCDDEEFF00112233445566778899"
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.BodyEncrypted {
		t.Errorf("body should be encrypted")
	}
	if r.AuthenticationStart != nil {
		t.Errorf("body should not be decoded without key")
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "encrypted") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected encryption note in: %v", r.Notes)
	}
}

func TestDecode_EncryptedBody_RoundTripWithKey(t *testing.T) {
	// Take the Test 1 plaintext body, XOR with the
	// pseudo-pad for (session_id=0x12345678, key="secret",
	// version=0xC0, seq=1), then decode with the same key.
	plain, err := hex.DecodeString(
		"010F02010504070061646D696E74747930312E322E332E34")
	if err != nil {
		t.Fatalf("plaintext decode: %v", err)
	}
	pad := tacacsPad(0x12345678, []byte("secret"), 0xC0, 1, len(plain))
	cipher := make([]byte, len(plain))
	for i := range plain {
		cipher[i] = plain[i] ^ pad[i]
	}
	// Header has Flags=0x00 (encrypted) and matching length.
	headerHex := "C0010100" + "12345678" + "00000018"
	in := headerHex + hex.EncodeToString(cipher)
	r, err := Decode(in, "secret")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.BodyEncrypted {
		t.Errorf("body should be flagged encrypted")
	}
	if r.AuthenticationStart == nil {
		t.Fatal("AUTH START body should have decoded after decrypt")
	}
	if r.AuthenticationStart.User != "admin" {
		t.Errorf("decrypted user: %q", r.AuthenticationStart.User)
	}
}

func TestDecode_PacketTypeTable(t *testing.T) {
	cases := map[int]string{
		1: "Authentication",
		2: "Authorization",
		3: "Accounting",
	}
	for k, v := range cases {
		if got := packetTypeName(k); got != v {
			t.Errorf("packetTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_AuthTypeTable(t *testing.T) {
	cases := map[int]string{
		1: "ASCII",
		2: "PAP",
		3: "CHAP",
		4: "MS-CHAP",
		5: "ARAP",
		6: "MS-CHAPv2",
	}
	for k, v := range cases {
		if got := authTypeName(k); got != v {
			t.Errorf("authTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_ServiceTable(t *testing.T) {
	cases := map[int]string{
		0: "NONE",
		1: "LOGIN",
		2: "ENABLE",
		3: "PPP",
		6: "RCMD",
	}
	for k, v := range cases {
		if got := serviceName(k); got != v {
			t.Errorf("serviceName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_AuthReplyStatusTable(t *testing.T) {
	cases := map[int]string{
		1:    "PASS",
		2:    "FAIL",
		3:    "GETDATA",
		4:    "GETUSER",
		5:    "GETPASS",
		6:    "RESTART",
		7:    "ERROR",
		0x21: "FOLLOW",
	}
	for k, v := range cases {
		if got := authReplyStatusName(k); got != v {
			t.Errorf("authReplyStatusName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "C0 01 01",
		"short":   "C0 01 01 01 12345678",
		"bad hex": "ZZ 01 01 01 12345678 00000000",
	}
	for name, in := range cases {
		_, err := Decode(in, "")
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
