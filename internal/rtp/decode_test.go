package rtp

import (
	"strings"
	"testing"
)

func TestDecode_RTP_Minimal_PCMU(t *testing.T) {
	// V=2 P=0 X=0 CC=0 M=0 PT=0 (PCMU), seq 0x1234,
	// ts 0, SSRC 0xDEADBEEF, payload AABBCCDD.
	in := "8000 1234 00000000 DEADBEEF AABBCCDD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Kind != "rtp" {
		t.Fatalf("kind: got %q want rtp", r.Kind)
	}
	if r.RTP.PayloadType != 0 || r.RTP.PayloadTypeName != "PCMU/8000/1" {
		t.Errorf("PT: %d %q", r.RTP.PayloadType, r.RTP.PayloadTypeName)
	}
	if r.RTP.SequenceNumber != 0x1234 {
		t.Errorf("seq: %d", r.RTP.SequenceNumber)
	}
	if r.RTP.SSRC != 0xDEADBEEF {
		t.Errorf("ssrc: %x", r.RTP.SSRC)
	}
	if r.RTP.PayloadHex != "AABBCCDD" || r.RTP.PayloadLength != 4 {
		t.Errorf("payload: %q len=%d", r.RTP.PayloadHex, r.RTP.PayloadLength)
	}
}

func TestDecode_RTP_CSRCList(t *testing.T) {
	// V=2 CC=2 M=1 PT=96 (dynamic), two CSRC, 1-byte payload.
	in := "82E0 0001 00000040 11111111 22222222 33333333 FF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RTP.CSRCCount != 2 || len(r.RTP.CSRC) != 2 {
		t.Fatalf("CSRC count: %d (list %d)", r.RTP.CSRCCount, len(r.RTP.CSRC))
	}
	if r.RTP.CSRC[0] != 0x22222222 || r.RTP.CSRC[1] != 0x33333333 {
		t.Errorf("CSRC: %x %x", r.RTP.CSRC[0], r.RTP.CSRC[1])
	}
	if !r.RTP.Marker {
		t.Errorf("marker bit not set")
	}
	if r.RTP.PayloadTypeName != "dynamic (negotiated in SDP)" {
		t.Errorf("PT name: %q", r.RTP.PayloadTypeName)
	}
}

func TestDecode_RTP_Extension(t *testing.T) {
	// V=2 X=1 CC=0 PT=10 (L16/44100/2), extension profile 0xBEDE
	// length 1 word (4 bytes data), then 2-byte payload.
	in := "900A 0002 00000080 CAFEBABE BEDE0001 10000000 0102"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.RTP.Extension {
		t.Fatal("extension bit not set")
	}
	if r.RTP.ExtensionProfile == nil || *r.RTP.ExtensionProfile != 0xBEDE {
		t.Errorf("ext profile: %v", r.RTP.ExtensionProfile)
	}
	if r.RTP.ExtensionLengthW == nil || *r.RTP.ExtensionLengthW != 1 {
		t.Errorf("ext length words: %v", r.RTP.ExtensionLengthW)
	}
	if r.RTP.ExtensionDataHex != "10000000" {
		t.Errorf("ext data: %q", r.RTP.ExtensionDataHex)
	}
	if r.RTP.PayloadHex != "0102" {
		t.Errorf("payload: %q", r.RTP.PayloadHex)
	}
	if r.RTP.PayloadTypeName != "L16/44100/2" {
		t.Errorf("PT name: %q", r.RTP.PayloadTypeName)
	}
}

func TestDecode_RTP_Padding(t *testing.T) {
	// V=2 P=1 PT=8 (PCMA), 4-byte payload, 3 padding bytes
	// (last byte = 3 = pad count). Total = 12 + 4 + 3 = 19 bytes.
	in := "A008 0003 000000C0 FEEDFACE 01020304 000003"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.RTP.Padding {
		t.Fatal("padding bit not set")
	}
	if r.RTP.PaddingLength != 3 {
		t.Errorf("pad length: %d", r.RTP.PaddingLength)
	}
	if r.RTP.PayloadHex != "01020304" || r.RTP.PayloadLength != 4 {
		t.Errorf("payload: %q len=%d", r.RTP.PayloadHex, r.RTP.PayloadLength)
	}
	if r.RTP.PayloadTypeName != "PCMA/8000/1" {
		t.Errorf("PT name: %q", r.RTP.PayloadTypeName)
	}
}

func TestDecode_RTCP_SR(t *testing.T) {
	// PT=200, RC=1.
	in := "81C8 000C DEADBEEF 83AA7E80 00000000 000003E8 " +
		"0000000A 00000280 " +
		"CAFEBABE 00000005 0000004A 00000005 12345678 00000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Kind != "rtcp" {
		t.Fatalf("kind: got %q want rtcp", r.Kind)
	}
	if len(r.RTCP) != 1 {
		t.Fatalf("expected 1 RTCP packet, got %d", len(r.RTCP))
	}
	pkt := r.RTCP[0]
	if pkt.Type != 200 || pkt.SR == nil {
		t.Fatalf("expected SR, got type=%d SR=%v", pkt.Type, pkt.SR)
	}
	if pkt.SR.SenderSSRC != 0xDEADBEEF {
		t.Errorf("sender SSRC: %x", pkt.SR.SenderSSRC)
	}
	if pkt.SR.SenderPacketCount != 10 || pkt.SR.SenderOctetCount != 0x280 {
		t.Errorf("counts: %d / %d", pkt.SR.SenderPacketCount, pkt.SR.SenderOctetCount)
	}
	if len(pkt.SR.Reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(pkt.SR.Reports))
	}
	rep := pkt.SR.Reports[0]
	if rep.SourceSSRC != 0xCAFEBABE {
		t.Errorf("source SSRC: %x", rep.SourceSSRC)
	}
	if rep.CumulativeLost != 5 {
		t.Errorf("cum lost: %d", rep.CumulativeLost)
	}
	if rep.ExtendedHighSeq != 0x4A {
		t.Errorf("ext high seq: %d", rep.ExtendedHighSeq)
	}
}

func TestDecode_RTCP_RR_Empty(t *testing.T) {
	// PT=201, RC=0, single reporter SSRC.
	in := "80C9 0001 12345678"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RTCP[0].RR == nil || r.RTCP[0].RR.ReporterSSRC != 0x12345678 {
		t.Fatalf("RR: %+v", r.RTCP[0].RR)
	}
	if len(r.RTCP[0].RR.Reports) != 0 {
		t.Errorf("expected 0 reports, got %d", len(r.RTCP[0].RR.Reports))
	}
}

func TestDecode_RTCP_SDES(t *testing.T) {
	// PT=202, SC=1, one chunk with CNAME="user".
	in := "81CA 0003 ABCDEF01 0104 75736572 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RTCP[0].SDES == nil || len(r.RTCP[0].SDES.Chunks) != 1 {
		t.Fatalf("SDES: %+v", r.RTCP[0].SDES)
	}
	ch := r.RTCP[0].SDES.Chunks[0]
	if ch.SSRC != 0xABCDEF01 {
		t.Errorf("chunk SSRC: %x", ch.SSRC)
	}
	if len(ch.Items) != 1 || ch.Items[0].TypeName != "CNAME" || ch.Items[0].Text != "user" {
		t.Errorf("items: %+v", ch.Items)
	}
}

func TestDecode_RTCP_BYE(t *testing.T) {
	// PT=203, SC=1, source 0xDEADBEEF, reason "bye".
	in := "81CB 0002 DEADBEEF 03 627965"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RTCP[0].BYE == nil {
		t.Fatal("BYE nil")
	}
	if len(r.RTCP[0].BYE.Sources) != 1 || r.RTCP[0].BYE.Sources[0] != 0xDEADBEEF {
		t.Errorf("sources: %+v", r.RTCP[0].BYE.Sources)
	}
	if r.RTCP[0].BYE.Reason != "bye" {
		t.Errorf("reason: %q", r.RTCP[0].BYE.Reason)
	}
}

func TestDecode_RTCP_Composite_SR_SDES(t *testing.T) {
	// SR + SDES back-to-back in one UDP datagram (canonical
	// pattern for RTCP transmission per RFC 3550 §6.1).
	sr := "81C8 000C DEADBEEF 83AA7E80 00000000 000003E8 " +
		"0000000A 00000280 " +
		"CAFEBABE 00000005 0000004A 00000005 12345678 00000001"
	sdes := "81CA 0003 ABCDEF01 0104 75736572 0000"
	r, err := Decode(sr + sdes)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.RTCP) != 2 {
		t.Fatalf("expected 2 RTCP packets, got %d", len(r.RTCP))
	}
	if r.RTCP[0].Type != 200 || r.RTCP[1].Type != 202 {
		t.Errorf("types: %d %d", r.RTCP[0].Type, r.RTCP[1].Type)
	}
	if !strings.Contains(r.RTCPSummary, "SR") || !strings.Contains(r.RTCPSummary, "SDES") {
		t.Errorf("summary: %q", r.RTCPSummary)
	}
}

func TestDecode_RTCP_PSFB_PLI(t *testing.T) {
	// PT=206 (PSFB), FMT=1 (PLI). Sender + media SSRC, no FCI.
	in := "81CE 0002 11111111 22222222"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RTCP[0].FB == nil {
		t.Fatal("FB nil")
	}
	if r.RTCP[0].FB.FormatName != "PLI (Picture Loss Indication, RFC 4585)" {
		t.Errorf("FMT name: %q", r.RTCP[0].FB.FormatName)
	}
	if r.RTCP[0].FB.SenderSSRC != 0x11111111 || r.RTCP[0].FB.MediaSSRC != 0x22222222 {
		t.Errorf("SSRCs: %x / %x", r.RTCP[0].FB.SenderSSRC, r.RTCP[0].FB.MediaSSRC)
	}
}

func TestDecode_RTCP_RTPFB_NACK(t *testing.T) {
	// PT=205 (RTPFB), FMT=1 (Generic NACK), 4-byte FCI.
	in := "81CD 0003 11111111 22222222 00010001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RTCP[0].FB.FormatName != "Generic NACK (RFC 4585)" {
		t.Errorf("FMT name: %q", r.RTCP[0].FB.FormatName)
	}
	if r.RTCP[0].FB.FCIHex != "00010001" {
		t.Errorf("FCI: %q", r.RTCP[0].FB.FCIHex)
	}
}

func TestDecode_RTCP_APP(t *testing.T) {
	// PT=204 (APP), SSRC + name="TEST" + 4 bytes data.
	in := "80CC 0003 12345678 54455354 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RTCP[0].APP == nil {
		t.Fatal("APP nil")
	}
	if r.RTCP[0].APP.Name != "TEST" {
		t.Errorf("name: %q", r.RTCP[0].APP.Name)
	}
	if r.RTCP[0].APP.DataHex != "DEADBEEF" {
		t.Errorf("data: %q", r.RTCP[0].APP.DataHex)
	}
}

func TestDecode_RTCP_XR(t *testing.T) {
	// PT=207 (XR). SSRC + one block: BT=1 type-specific=0
	// length=1 word → block bytes = (1+1)*4 = 8, body 4 bytes.
	in := "80CF 0003 12345678 01000001 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RTCP[0].XR == nil || len(r.RTCP[0].XR.Blocks) != 1 {
		t.Fatalf("XR: %+v", r.RTCP[0].XR)
	}
	blk := r.RTCP[0].XR.Blocks[0]
	if blk.BlockType != 1 || blk.BlockLengthW != 1 || blk.BlockBytes != 8 {
		t.Errorf("block: %+v", blk)
	}
	if blk.BodyHex != "DEADBEEF" {
		t.Errorf("body: %q", blk.BodyHex)
	}
}

func TestDecode_PayloadTypeTable(t *testing.T) {
	cases := []struct {
		pt   byte
		name string
	}{
		{0, "PCMU/8000/1"},
		{3, "GSM/8000/1"},
		{8, "PCMA/8000/1"},
		{9, "G722/8000/1"},
		{18, "G729/8000/1"},
		{26, "JPEG/90000"},
		{33, "MP2T/90000"},
	}
	for _, c := range cases {
		// Construct minimal RTP header with this PT.
		hex := []byte{0x80, c.pt, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}
		got := rtpPayloadTypeName(int(c.pt))
		if got != c.name {
			t.Errorf("PT %d: got %q want %q", c.pt, got, c.name)
		}
		r, err := Decode(toHex(hex))
		if err != nil {
			t.Errorf("PT %d Decode: %v", c.pt, err)
		} else if r.RTP.PayloadTypeName != c.name {
			t.Errorf("PT %d packet name: %q", c.pt, r.RTP.PayloadTypeName)
		}
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":               "",
		"odd hex":             "8000123",
		"too short":           "8000",
		"version 1 RTP":       "40000000 00000000 00000000",
		"version 3 RTCP-PT":   "C0C80001 12345678",
		"RTCP-conflict PT":    "804B 0001 00000000 DEADBEEF",
		"truncated CSRC":      "82001234 00000000 DEADBEEF 11111111",
		"RTCP length too big": "81C800FF DEADBEEF",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestDecode_DynamicPT_AVPF(t *testing.T) {
	// PT=111 (dynamic, often Opus in WebRTC).
	in := "806F 0010 00000000 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RTP.PayloadType != 111 {
		t.Errorf("PT: %d", r.RTP.PayloadType)
	}
	if r.RTP.PayloadTypeName != "dynamic (negotiated in SDP)" {
		t.Errorf("PT name: %q", r.RTP.PayloadTypeName)
	}
}

// toHex is a small test helper to convert a byte slice to
// uppercase hex without using fmt.Sprintf in tight loops.
func toHex(b []byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0F]
	}
	return string(out)
}
