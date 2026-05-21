package mongodb

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// bsonString builds a BSON string element: type 0x02 + cstring
// name + 4-byte LE length + N bytes + 0x00 terminator.
func bsonString(name, value string) []byte {
	out := []byte{0x02}
	out = append(out, []byte(name)...)
	out = append(out, 0x00)
	l := len(value) + 1
	lb := make([]byte, 4)
	binary.LittleEndian.PutUint32(lb, uint32(l))
	out = append(out, lb...)
	out = append(out, []byte(value)...)
	out = append(out, 0x00)
	return out
}

// bsonInt32 builds a BSON int32 element.
func bsonInt32(name string, v int32) []byte {
	out := []byte{0x10}
	out = append(out, []byte(name)...)
	out = append(out, 0x00)
	vb := make([]byte, 4)
	binary.LittleEndian.PutUint32(vb, uint32(v))
	return append(out, vb...)
}

// bsonBinary builds a BSON binary element with the supplied
// subtype + bytes.
func bsonBinary(name string, subtype byte, data []byte) []byte {
	out := []byte{0x05}
	out = append(out, []byte(name)...)
	out = append(out, 0x00)
	lb := make([]byte, 4)
	binary.LittleEndian.PutUint32(lb, uint32(len(data)))
	out = append(out, lb...)
	out = append(out, subtype)
	return append(out, data...)
}

// bsonDoc wraps element bytes in a BSON document length prefix +
// trailing 0x00 terminator.
func bsonDoc(elements ...[]byte) []byte {
	var body []byte
	for _, e := range elements {
		body = append(body, e...)
	}
	total := 4 + len(body) + 1
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out[0:4], uint32(total))
	out = append(out, body...)
	out = append(out, 0x00)
	return out
}

// header builds a 16-byte MongoDB wire-protocol header.
func mongoHeader(opCode int, totalLen int) []byte {
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(h[4:8], 1)
	binary.LittleEndian.PutUint32(h[8:12], 0)
	binary.LittleEndian.PutUint32(h[12:16], uint32(opCode))
	return h
}

// opMsgMessage assembles an OP_MSG packet with a single Body
// section containing the supplied BSON document.
func opMsgMessage(doc []byte) []byte {
	body := make([]byte, 4)
	binary.LittleEndian.PutUint32(body[0:4], 0)
	body = append(body, 0x00) // section kind 0 = Body
	body = append(body, doc...)
	total := 16 + len(body)
	return append(mongoHeader(2013, total), body...)
}

// opQueryMessage assembles an OP_QUERY packet with the supplied
// fullCollectionName and BSON query.
func opQueryMessage(fullCollName string, doc []byte) []byte {
	body := make([]byte, 4)
	body = append(body, []byte(fullCollName)...)
	body = append(body, 0x00)
	body = append(body, make([]byte, 8)...) // numberToSkip + numberToReturn
	body = append(body, doc...)
	total := 16 + len(body)
	return append(mongoHeader(2004, total), body...)
}

// TestDecodeOpMsgHelloProbe pins the canonical isMaster/hello
// probe shape (sent by every driver immediately on connect).
func TestDecodeOpMsgHelloProbe(t *testing.T) {
	doc := bsonDoc(
		bsonInt32("hello", 1),
		bsonString("$db", "admin"),
	)
	pkt := opMsgMessage(doc)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.OpCodeName != "OP_MSG (modern, MongoDB 3.6+ default)" {
		t.Errorf("OpCodeName: got %q", r.OpCodeName)
	}
	if r.CommandName != "hello" {
		t.Errorf("CommandName: got %q want hello", r.CommandName)
	}
	if r.Database != "admin" {
		t.Errorf("Database: got %q want admin", r.Database)
	}
	if !r.IsHelloProbe {
		t.Errorf("IsHelloProbe should be true")
	}
}

// TestDecodeOpMsgSASLStart pins the SCRAM-SHA-256 auth-start
// shape with payload-length-only surfacing.
func TestDecodeOpMsgSASLStart(t *testing.T) {
	payloadBytes := []byte("n,,n=admin,r=fyko+d2lbbFgONRv9qkxdawL")
	doc := bsonDoc(
		bsonInt32("saslStart", 1),
		bsonString("mechanism", "SCRAM-SHA-256"),
		bsonBinary("payload", 0x00, payloadBytes),
		bsonString("$db", "admin"),
	)
	pkt := opMsgMessage(doc)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.CommandName != "saslStart" {
		t.Errorf("CommandName: got %q want saslStart", r.CommandName)
	}
	if !r.IsSASLAuth {
		t.Errorf("IsSASLAuth should be true")
	}
	if r.SASLMechanism != "SCRAM-SHA-256" {
		t.Errorf("SASLMechanism: got %q want SCRAM-SHA-256", r.SASLMechanism)
	}
	if r.SASLPayloadBytes != len(payloadBytes) {
		t.Errorf("SASLPayloadBytes: got %d want %d",
			r.SASLPayloadBytes, len(payloadBytes))
	}
}

// TestDecodeOpQueryFullCollectionName pins legacy isMaster
// shape where fullCollectionName is "admin.$cmd".
func TestDecodeOpQueryFullCollectionName(t *testing.T) {
	doc := bsonDoc(bsonInt32("isMaster", 1))
	pkt := opQueryMessage("admin.$cmd", doc)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.OpCode != 2004 {
		t.Errorf("OpCode: got %d want 2004", r.OpCode)
	}
	if r.FullCollectionName != "admin.$cmd" {
		t.Errorf("FullCollectionName: got %q", r.FullCollectionName)
	}
	if r.Database != "admin" {
		t.Errorf("Database: got %q want admin", r.Database)
	}
	if r.CommandName != "isMaster" {
		t.Errorf("CommandName: got %q want isMaster", r.CommandName)
	}
	if !r.IsHelloProbe {
		t.Errorf("IsHelloProbe should be true for isMaster")
	}
}

// TestDecodeDangerousCreateUser pins the credential-management
// classification.
func TestDecodeDangerousCreateUser(t *testing.T) {
	doc := bsonDoc(
		bsonString("createUser", "backdoor"),
		bsonString("$db", "admin"),
	)
	pkt := opMsgMessage(doc)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsDangerousCommand {
		t.Errorf("IsDangerousCommand should be true")
	}
	if !strings.Contains(r.DangerousFlag, "backdoor primitive") {
		t.Errorf("DangerousFlag should flag backdoor primitive: %q",
			r.DangerousFlag)
	}
}

// TestDecodeDangerousDropDatabase pins data destruction.
func TestDecodeDangerousDropDatabase(t *testing.T) {
	doc := bsonDoc(
		bsonInt32("dropDatabase", 1),
		bsonString("$db", "production"),
	)
	pkt := opMsgMessage(doc)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.DangerousFlag, "data destruction") {
		t.Errorf("dropDatabase should flag data destruction: %q",
			r.DangerousFlag)
	}
}

// TestDecodeDangerousEval pins the historical RCE primitive
// classification (removed in 4.4 but legacy still deployed).
func TestDecodeDangerousEval(t *testing.T) {
	doc := bsonDoc(
		bsonString("eval", "function(){return 1;}"),
		bsonString("$db", "admin"),
	)
	pkt := opMsgMessage(doc)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.DangerousFlag, "RCE primitive") {
		t.Errorf("eval should flag RCE primitive: %q", r.DangerousFlag)
	}
	if !strings.Contains(r.DangerousFlag, "REMOVED in MongoDB 4.4") {
		t.Errorf("eval should reference removal in 4.4: %q",
			r.DangerousFlag)
	}
}

// TestDecodeListDatabasesEnumeration pins the recon
// classification.
func TestDecodeListDatabasesEnumeration(t *testing.T) {
	doc := bsonDoc(
		bsonInt32("listDatabases", 1),
		bsonString("$db", "admin"),
	)
	pkt := opMsgMessage(doc)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.DangerousFlag, "enumeration") {
		t.Errorf("listDatabases should flag enumeration: %q",
			r.DangerousFlag)
	}
}

// TestDecodeBenignFind pins that ordinary commands aren't
// flagged dangerous.
func TestDecodeBenignFind(t *testing.T) {
	doc := bsonDoc(
		bsonString("find", "users"),
		bsonString("$db", "mydb"),
	)
	pkt := opMsgMessage(doc)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.IsDangerousCommand {
		t.Errorf("find should not be flagged dangerous")
	}
	if r.CommandName != "find" {
		t.Errorf("CommandName: got %q want find", r.CommandName)
	}
	if r.Database != "mydb" {
		t.Errorf("Database: got %q want mydb", r.Database)
	}
}

// TestOpCodeNameTable spot-checks each catalogued opcode.
func TestOpCodeNameTable(t *testing.T) {
	cases := map[int]string{
		1:    "OP_REPLY",
		2001: "OP_UPDATE",
		2002: "OP_INSERT",
		2004: "OP_QUERY",
		2005: "OP_GET_MORE",
		2006: "OP_DELETE",
		2007: "OP_KILL_CURSORS",
		2010: "OP_COMMAND",
		2011: "OP_COMMANDREPLY",
		2012: "OP_COMPRESSED",
		2013: "OP_MSG",
	}
	for k, marker := range cases {
		got := opCodeName(k)
		if !strings.Contains(got, marker) {
			t.Errorf("opCodeName(%d) = %q want contains %q",
				k, got, marker)
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

func TestDecodeRejectsTruncatedHeader(t *testing.T) {
	if _, err := Decode("0102"); err == nil {
		t.Fatal("want error for truncated header")
	}
}
