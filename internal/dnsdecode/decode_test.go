package dnsdecode

import (
	"encoding/binary"
	"strings"
	"testing"
)

// TestDecode_QueryA pins a simple "example.com A IN" query.
//
// Header: txn=0x1234, flags=0x0100 (RD set), QD=1, others=0
// Question: example.com (with no compression) + A + IN
func TestDecode_QueryA(t *testing.T) {
	pkt := buildQueryPacket(t, 0x1234, "example.com", 1, 1)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.TransactionID != 0x1234 {
		t.Errorf("TransactionID = 0x%04X; want 0x1234", got.TransactionID)
	}
	if got.Flags.QR != 0 {
		t.Errorf("QR = %d; want 0 (query)", got.Flags.QR)
	}
	if got.Flags.QRName != "query" {
		t.Errorf("QRName = %q", got.Flags.QRName)
	}
	if got.Flags.OpcodeName != "QUERY" {
		t.Errorf("OpcodeName = %q", got.Flags.OpcodeName)
	}
	if !got.Flags.RecursionDesired {
		t.Error("RecursionDesired = false; want true")
	}
	if got.Flags.RCodeName != "NOERROR" {
		t.Errorf("RCodeName = %q", got.Flags.RCodeName)
	}
	if got.QDCount != 1 {
		t.Errorf("QDCount = %d; want 1", got.QDCount)
	}
	if len(got.Questions) != 1 {
		t.Fatalf("Questions count = %d", len(got.Questions))
	}
	q := got.Questions[0]
	if q.Name != "example.com" {
		t.Errorf("Question.Name = %q", q.Name)
	}
	if q.Type != 1 {
		t.Errorf("Question.Type = %d; want 1", q.Type)
	}
	if q.TypeName != "A" {
		t.Errorf("Question.TypeName = %q", q.TypeName)
	}
	if q.ClassName != "IN" {
		t.Errorf("Question.ClassName = %q", q.ClassName)
	}
}

// TestDecode_ResponseA pins a typical A response with one
// answer.
//
// Header: txn=0x5678, flags=0x8180 (QR + RD + RA, NOERROR)
// QD=1, AN=1, NS=0, AR=0
// Question: example.com A IN
// Answer: example.com (compressed) A IN TTL=300 RDATA=93.184.216.34
func TestDecode_ResponseA(t *testing.T) {
	pkt := buildResponseAPacket(t, 0x5678, "example.com", "93.184.216.34", 300)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Flags.QR != 1 {
		t.Errorf("QR = %d; want 1 (response)", got.Flags.QR)
	}
	if !got.Flags.RecursionAvail {
		t.Error("RecursionAvail = false; want true")
	}
	if len(got.Answers) != 1 {
		t.Fatalf("Answers count = %d", len(got.Answers))
	}
	a := got.Answers[0]
	if a.Name != "example.com" {
		t.Errorf("Answer.Name = %q (compression should resolve)", a.Name)
	}
	if a.TTL != 300 {
		t.Errorf("Answer.TTL = %d; want 300", a.TTL)
	}
	if a.IPv4 != "93.184.216.34" {
		t.Errorf("Answer.IPv4 = %q", a.IPv4)
	}
}

// TestDecode_ResponseAAAA pins an AAAA response decode.
func TestDecode_ResponseAAAA(t *testing.T) {
	pkt := buildResponseAAAAPacket(t, 0x9999, "example.com",
		[16]byte{0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x88})
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := got.Answers[0]
	if a.TypeName != "AAAA" {
		t.Errorf("TypeName = %q", a.TypeName)
	}
	if a.IPv6 != "2606:2800:220::188" {
		t.Errorf("IPv6 = %q; want '2606:2800:220::188'", a.IPv6)
	}
}

// TestDecode_ResponseCNAME pins a CNAME chain.
func TestDecode_ResponseCNAME(t *testing.T) {
	pkt := buildResponseCNAMEPacket(t, "www.example.com", "example.com")
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := got.Answers[0]
	if a.TypeName != "CNAME" {
		t.Errorf("TypeName = %q", a.TypeName)
	}
	if a.Target != "example.com" {
		t.Errorf("Target = %q", a.Target)
	}
}

// TestDecode_ResponseMX pins an MX response.
func TestDecode_ResponseMX(t *testing.T) {
	pkt := buildResponseMXPacket(t, "example.com", 10, "mail.example.com")
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := got.Answers[0]
	if a.TypeName != "MX" {
		t.Errorf("TypeName = %q", a.TypeName)
	}
	if a.MX == nil {
		t.Fatal("MX nil")
	}
	if a.MX.Preference != 10 {
		t.Errorf("Preference = %d", a.MX.Preference)
	}
	if a.MX.Exchange != "mail.example.com" {
		t.Errorf("Exchange = %q", a.MX.Exchange)
	}
}

// TestDecode_ResponseTXT pins a TXT response (SPF / DMARC /
// arbitrary policy text).
func TestDecode_ResponseTXT(t *testing.T) {
	pkt := buildResponseTXTPacket(t, "example.com",
		[]string{"v=spf1 include:_spf.example.com ~all", "verification=abc123"})
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := got.Answers[0]
	if len(a.TextRecords) != 2 {
		t.Fatalf("TextRecords count = %d", len(a.TextRecords))
	}
	if a.TextRecords[0] != "v=spf1 include:_spf.example.com ~all" {
		t.Errorf("TextRecords[0] = %q", a.TextRecords[0])
	}
}

// TestDecode_ResponseSRV pins an SRV response.
func TestDecode_ResponseSRV(t *testing.T) {
	pkt := buildResponseSRVPacket(t, "_sip._tcp.example.com", 10, 60, 5060, "sip.example.com")
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := got.Answers[0]
	if a.SRV == nil {
		t.Fatal("SRV nil")
	}
	if a.SRV.Priority != 10 {
		t.Errorf("Priority = %d", a.SRV.Priority)
	}
	if a.SRV.Port != 5060 {
		t.Errorf("Port = %d", a.SRV.Port)
	}
	if a.SRV.Target != "sip.example.com" {
		t.Errorf("Target = %q", a.SRV.Target)
	}
}

// TestDecode_NXDOMAIN pins an NXDOMAIN response.
func TestDecode_NXDOMAIN(t *testing.T) {
	pkt := buildQueryPacket(t, 0xDEAD, "nonexistent.example.com", 1, 1)
	// Flip QR + set RCODE=3 (NXDOMAIN) in flags
	binary.BigEndian.PutUint16(pkt[2:4], 0x8183)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Flags.RCodeName != "NXDOMAIN" {
		t.Errorf("RCodeName = %q; want NXDOMAIN", got.Flags.RCodeName)
	}
}

// TestDecode_CAA pins a CAA record decode.
func TestDecode_CAA(t *testing.T) {
	pkt := buildResponseCAAPacket(t, "example.com", 0, "issue", "letsencrypt.org")
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := got.Answers[0]
	if a.CAA == nil {
		t.Fatal("CAA nil")
	}
	if a.CAA.Tag != "issue" {
		t.Errorf("CAA.Tag = %q", a.CAA.Tag)
	}
	if a.CAA.Value != "letsencrypt.org" {
		t.Errorf("CAA.Value = %q", a.CAA.Value)
	}
}

// TestDecode_OPT_EDNS pins an EDNS OPT pseudo-record.
//
// OPT layout: name=root(0x00), type=41, class=UDP-size,
// TTL=extended-RCODE(8) + version(8) + DO(1) + Z(15), rdlen+data
func TestDecode_OPT_EDNS(t *testing.T) {
	pkt := buildQueryWithOPT(t, 0x1111, "example.com", 4096, true)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.Additional) != 1 {
		t.Fatalf("Additional count = %d", len(got.Additional))
	}
	opt := got.Additional[0]
	if opt.TypeName != "OPT (EDNS)" {
		t.Errorf("TypeName = %q", opt.TypeName)
	}
	if opt.OPT == nil {
		t.Fatal("OPT nil")
	}
	if opt.OPT.UDPSize != 4096 {
		t.Errorf("UDPSize = %d", opt.OPT.UDPSize)
	}
	if !opt.OPT.DOFlag {
		t.Error("DOFlag = false; want true (DNSSEC requested)")
	}
}

// TestDecode_NameCompression exercises the pointer-resolution
// path explicitly.
func TestDecode_NameCompression(t *testing.T) {
	pkt := buildResponseAPacket(t, 0x1234, "subdomain.example.com", "1.2.3.4", 60)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// Both question and answer name should resolve to the same
	// full FQDN even though the answer uses a pointer.
	if got.Questions[0].Name != "subdomain.example.com" {
		t.Errorf("Question.Name = %q", got.Questions[0].Name)
	}
	if got.Answers[0].Name != "subdomain.example.com" {
		t.Errorf("Answer.Name = %q (compression should resolve)", got.Answers[0].Name)
	}
}

// TestDecode_NamePointerLoop catches a deliberately-crafted
// pointer loop. RFC 1035 doesn't allow loops; we cap the
// recursion depth.
func TestDecode_NamePointerLoop(t *testing.T) {
	// Build a header + a self-referencing pointer at offset 12.
	// 12: 0xC0 0x0C → pointer to offset 12 itself.
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	hdr[5] = 1 // QDCOUNT = 1
	body := []byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01}
	pkt := append(hdr, body...)
	if _, err := DecodeBytes(pkt); err == nil {
		t.Error("pointer loop: want error")
	}
}

// TestDecode_TooShort rejects buffers < 12 bytes.
func TestDecode_TooShort(t *testing.T) {
	if _, err := Decode("00 01 02"); err == nil {
		t.Error("3-byte input: want error")
	}
}

// TestDecode_BadHex rejects garbage.
func TestDecode_BadHex(t *testing.T) {
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
}

// TestRRTypeNameTable spot-checks.
func TestRRTypeNameTable(t *testing.T) {
	cases := map[int]string{
		1:   "A",
		2:   "NS",
		5:   "CNAME",
		6:   "SOA",
		12:  "PTR",
		15:  "MX",
		16:  "TXT",
		28:  "AAAA",
		33:  "SRV",
		41:  "OPT (EDNS)",
		43:  "DS",
		48:  "DNSKEY",
		257: "CAA",
	}
	for tp, want := range cases {
		if got := rrTypeName(tp); got != want {
			t.Errorf("rrTypeName(%d) = %q; want %q", tp, got, want)
		}
	}
}

// TestRCodeNameTable spot-checks.
func TestRCodeNameTable(t *testing.T) {
	cases := map[int]string{
		0:  "NOERROR",
		2:  "SERVFAIL",
		3:  "NXDOMAIN",
		5:  "REFUSED",
		9:  "NOTAUTH",
		23: "BADCOOKIE",
	}
	for rc, want := range cases {
		if got := rcodeName(rc); got != want {
			t.Errorf("rcodeName(%d) = %q; want %q", rc, got, want)
		}
	}
}

// --- test helpers --------------------------------------------------

func encodeName(name string) []byte {
	if name == "" {
		return []byte{0x00}
	}
	var out []byte
	for _, lbl := range strings.Split(name, ".") {
		if len(lbl) == 0 {
			continue
		}
		out = append(out, byte(len(lbl)))
		out = append(out, []byte(lbl)...)
	}
	out = append(out, 0x00)
	return out
}

func buildHeader(txn uint16, flags uint16, qd, an, ns, ar uint16) []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[0:2], txn)
	binary.BigEndian.PutUint16(h[2:4], flags)
	binary.BigEndian.PutUint16(h[4:6], qd)
	binary.BigEndian.PutUint16(h[6:8], an)
	binary.BigEndian.PutUint16(h[8:10], ns)
	binary.BigEndian.PutUint16(h[10:12], ar)
	return h
}

func buildQueryPacket(t *testing.T, txn uint16, name string, qtype, qclass int) []byte {
	t.Helper()
	h := buildHeader(txn, 0x0100, 1, 0, 0, 0)
	q := encodeName(name)
	qType := make([]byte, 4)
	binary.BigEndian.PutUint16(qType[0:2], uint16(qtype))
	binary.BigEndian.PutUint16(qType[2:4], uint16(qclass))
	return append(append(h, q...), qType...)
}

func buildResponseAPacket(t *testing.T, txn uint16, name, ipv4 string, ttl uint32) []byte {
	t.Helper()
	h := buildHeader(txn, 0x8180, 1, 1, 0, 0)
	q := encodeName(name)
	qType := []byte{0x00, 0x01, 0x00, 0x01} // A IN
	// Answer: pointer to question name (offset 12) + TYPE +
	// CLASS + TTL + RDLENGTH + RDATA
	ans := []byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01}
	ttlBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ttlBytes, ttl)
	ans = append(ans, ttlBytes...)
	ans = append(ans, 0x00, 0x04) // RDLENGTH = 4
	ipParts := strings.Split(ipv4, ".")
	for _, p := range ipParts {
		var v byte
		_, _ = fmtSscanByte(p, &v)
		ans = append(ans, v)
	}
	return append(append(append(h, q...), qType...), ans...)
}

func buildResponseAAAAPacket(t *testing.T, txn uint16, name string, ipv6 [16]byte) []byte {
	t.Helper()
	h := buildHeader(txn, 0x8180, 1, 1, 0, 0)
	q := encodeName(name)
	qType := []byte{0x00, 0x1C, 0x00, 0x01} // AAAA IN
	ans := []byte{0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x10}
	ans = append(ans, ipv6[:]...)
	return append(append(append(h, q...), qType...), ans...)
}

func buildResponseCNAMEPacket(t *testing.T, name, target string) []byte {
	t.Helper()
	h := buildHeader(0x4242, 0x8180, 1, 1, 0, 0)
	q := encodeName(name)
	qType := []byte{0x00, 0x05, 0x00, 0x01} // CNAME IN
	tgt := encodeName(target)
	ans := []byte{0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C}
	rdLen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLen, uint16(len(tgt)))
	ans = append(ans, rdLen...)
	ans = append(ans, tgt...)
	return append(append(append(h, q...), qType...), ans...)
}

func buildResponseMXPacket(t *testing.T, name string, pref int, exchange string) []byte {
	t.Helper()
	h := buildHeader(0x5050, 0x8180, 1, 1, 0, 0)
	q := encodeName(name)
	qType := []byte{0x00, 0x0F, 0x00, 0x01} // MX IN
	exch := encodeName(exchange)
	ans := []byte{0xC0, 0x0C, 0x00, 0x0F, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C}
	rdLen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLen, uint16(2+len(exch)))
	ans = append(ans, rdLen...)
	prefBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(prefBytes, uint16(pref))
	ans = append(ans, prefBytes...)
	ans = append(ans, exch...)
	return append(append(append(h, q...), qType...), ans...)
}

func buildResponseTXTPacket(t *testing.T, name string, texts []string) []byte {
	t.Helper()
	h := buildHeader(0x7070, 0x8180, 1, 1, 0, 0)
	q := encodeName(name)
	qType := []byte{0x00, 0x10, 0x00, 0x01} // TXT IN
	var rdata []byte
	for _, txt := range texts {
		rdata = append(rdata, byte(len(txt)))
		rdata = append(rdata, []byte(txt)...)
	}
	ans := []byte{0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C}
	rdLen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLen, uint16(len(rdata)))
	ans = append(ans, rdLen...)
	ans = append(ans, rdata...)
	return append(append(append(h, q...), qType...), ans...)
}

func buildResponseSRVPacket(t *testing.T, name string, prio, weight, port int, target string) []byte {
	t.Helper()
	h := buildHeader(0x8080, 0x8180, 1, 1, 0, 0)
	q := encodeName(name)
	qType := []byte{0x00, 0x21, 0x00, 0x01} // SRV IN
	tgt := encodeName(target)
	rdata := make([]byte, 6)
	binary.BigEndian.PutUint16(rdata[0:2], uint16(prio))
	binary.BigEndian.PutUint16(rdata[2:4], uint16(weight))
	binary.BigEndian.PutUint16(rdata[4:6], uint16(port))
	rdata = append(rdata, tgt...)
	ans := []byte{0xC0, 0x0C, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C}
	rdLen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLen, uint16(len(rdata)))
	ans = append(ans, rdLen...)
	ans = append(ans, rdata...)
	return append(append(append(h, q...), qType...), ans...)
}

func buildResponseCAAPacket(t *testing.T, name string, flags int, tag, value string) []byte {
	t.Helper()
	h := buildHeader(0xCACA, 0x8180, 1, 1, 0, 0)
	q := encodeName(name)
	qType := []byte{0x01, 0x01, 0x00, 0x01} // CAA (257) IN
	rdata := []byte{byte(flags), byte(len(tag))}
	rdata = append(rdata, []byte(tag)...)
	rdata = append(rdata, []byte(value)...)
	ans := []byte{0xC0, 0x0C, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C}
	rdLen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLen, uint16(len(rdata)))
	ans = append(ans, rdLen...)
	ans = append(ans, rdata...)
	return append(append(append(h, q...), qType...), ans...)
}

func buildQueryWithOPT(t *testing.T, txn uint16, name string, udpSize int, doFlag bool) []byte {
	t.Helper()
	h := buildHeader(txn, 0x0120, 1, 0, 0, 1) // RD + AD
	q := encodeName(name)
	qType := []byte{0x00, 0x01, 0x00, 0x01}
	// OPT record: name=root (0x00), type=41, class=UDP-size,
	// TTL: bytes [ext_rcode, version, DO+Z high, Z low], RDLEN=0
	opt := []byte{0x00, 0x00, 0x29}
	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(classBytes, uint16(udpSize))
	opt = append(opt, classBytes...)
	ttlBytes := []byte{0x00, 0x00, 0x00, 0x00}
	if doFlag {
		ttlBytes[2] = 0x80
	}
	opt = append(opt, ttlBytes...)
	opt = append(opt, 0x00, 0x00) // RDLEN=0
	return append(append(append(h, q...), qType...), opt...)
}

// fmtSscanByte is a tiny stdlib-only int parser for IPv4
// octets used by the test helpers.
func fmtSscanByte(s string, out *byte) (int, error) {
	var v int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, nil
		}
		v = v*10 + int(c-'0')
	}
	*out = byte(v)
	return 1, nil
}
