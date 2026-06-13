package pmkidcap

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/pcap"
)

func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }

// eapolM1 builds an EAPOL-Key message-1 frame carrying a PMKID KDE (validated
// against internal/eapol). All-zero pmkid models hostapd's "no PMKID" case.
func eapolM1(pmkid []byte) []byte {
	kde := append([]byte{0xDD, 0x14, 0x00, 0x0F, 0xAC, 0x04}, pmkid...)
	var d []byte
	d = append(d, 0x02)            // descriptor type (RSN)
	d = append(d, be16(0x008A)...) // key info: M1 (pairwise + ack, version 2)
	d = append(d, be16(16)...)     // key length
	d = append(d, make([]byte, 8)...)
	d = append(d, make([]byte, 32)...) // nonce (ANonce)
	d = append(d, make([]byte, 16)...) // key IV
	d = append(d, make([]byte, 8)...)  // RSC
	d = append(d, make([]byte, 8)...)  // key ID
	d = append(d, make([]byte, 16)...) // MIC (zero for M1)
	d = append(d, be16(uint16(len(kde)))...)
	d = append(d, kde...)
	f := []byte{0x02, 0x03} // 802.1X version + type (EAPOL-Key)
	f = append(f, be16(uint16(len(d)))...)
	return append(f, d...)
}

func beaconFrame(bssid []byte, ssid string) []byte {
	b := []byte{0x80, 0x00, 0x00, 0x00} // mgmt(0) beacon(8), no flags
	b = append(b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	b = append(b, bssid...) // Addr2 SA
	b = append(b, bssid...) // Addr3 BSSID
	b = append(b, 0x00, 0x10)
	b = append(b, make([]byte, 8)...) // timestamp
	b = append(b, 0x64, 0x00)         // beacon interval
	b = append(b, 0x01, 0x00)         // capabilities (ESS)
	b = append(b, 0x00, byte(len(ssid)))
	return append(b, []byte(ssid)...)
}

// m1DataFrame builds a QoS data frame (FromDS) AP -> STA carrying LLC/SNAP + the
// EAPOL M1. With the DS-bit-correct decoder, BSSID = Addr2, DA(=STA) = Addr1.
func m1DataFrame(bssid, sta, pmkid []byte) []byte {
	b := []byte{0x88, 0x02, 0x00, 0x00} // QoS data (type2 subtype8), FromDS
	b = append(b, sta...)               // Addr1 = RA = DA (STA)
	b = append(b, bssid...)             // Addr2 = TA = BSSID (AP)
	b = append(b, bssid...)             // Addr3 = SA (AP)
	b = append(b, 0x00, 0x10)           // Sequence Control
	b = append(b, 0x00, 0x00)           // QoS Control
	b = append(b, llcSnapEAPOL...)
	return append(b, eapolM1(pmkid)...)
}

func buildPcap(t testing.TB, lt pcap.LinkType, frames ...[]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := pcap.NewWriter(&buf, lt)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ts := time.Unix(1700000000, 0)
	for _, f := range frames {
		if lt == pcap.LinkTypeIEEE802_11Radiotap {
			f = append(pcap.RadiotapHeader{}.Bytes(), f...) // 16-byte radiotap prefix
		}
		if err := w.WritePacket(ts, f); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
	}
	return buf.Bytes()
}

var (
	testBSSID = []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	testSTA   = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
)

func realPMKID() []byte {
	p := make([]byte, 16)
	for i := range p {
		p[i] = byte(0xA0 + i)
	}
	return p
}

func TestExtract_BeaconPlusM1(t *testing.T) {
	cap := buildPcap(t, pcap.LinkTypeIEEE802_11,
		beaconFrame(testBSSID, "testnet"),
		m1DataFrame(testBSSID, testSTA, realPMKID()),
	)
	r, err := Extract(cap)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.Packets != 2 || r.NetworksSeen != 1 || len(r.PMKIDs) != 1 {
		t.Fatalf("packets=%d networks=%d pmkids=%d; want 2/1/1", r.Packets, r.NetworksSeen, len(r.PMKIDs))
	}
	e := r.PMKIDs[0]
	if e.PMKID != "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" {
		t.Errorf("PMKID = %q", e.PMKID)
	}
	if e.ESSID != "testnet" {
		t.Errorf("ESSID = %q, want testnet", e.ESSID)
	}
	want := "WPA*01*a0a1a2a3a4a5a6a7a8a9aaabacadaeaf*aabbccddeeff*112233445566*746573746e6574***"
	if e.HC22000Line != want {
		t.Errorf("HC22000Line =\n %s\nwant\n %s", e.HC22000Line, want)
	}
}

func TestExtract_Radiotap(t *testing.T) {
	cap := buildPcap(t, pcap.LinkTypeIEEE802_11Radiotap,
		beaconFrame(testBSSID, "rtnet"),
		m1DataFrame(testBSSID, testSTA, realPMKID()),
	)
	r, err := Extract(cap)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(r.PMKIDs) != 1 || r.PMKIDs[0].ESSID != "rtnet" || r.PMKIDs[0].HC22000Line == "" {
		t.Errorf("radiotap extraction failed: %+v", r.PMKIDs)
	}
}

func TestExtract_ZeroPMKIDDropped(t *testing.T) {
	cap := buildPcap(t, pcap.LinkTypeIEEE802_11,
		beaconFrame(testBSSID, "testnet"),
		m1DataFrame(testBSSID, testSTA, make([]byte, 16)), // all-zero PMKID
	)
	r, err := Extract(cap)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(r.PMKIDs) != 0 {
		t.Errorf("all-zero PMKID must be dropped, got %+v", r.PMKIDs)
	}
}

func TestExtract_PMKIDWithoutESSID(t *testing.T) {
	cap := buildPcap(t, pcap.LinkTypeIEEE802_11,
		m1DataFrame(testBSSID, testSTA, realPMKID()), // no beacon → no ESSID
	)
	r, err := Extract(cap)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(r.PMKIDs) != 1 || r.PMKIDs[0].HC22000Line != "" || !strings.Contains(r.PMKIDs[0].Note, "ESSID") {
		t.Errorf("expected a PMKID with no line + an ESSID note, got %+v", r.PMKIDs)
	}
}

func TestExtract_Dedup(t *testing.T) {
	m1 := m1DataFrame(testBSSID, testSTA, realPMKID())
	cap := buildPcap(t, pcap.LinkTypeIEEE802_11, beaconFrame(testBSSID, "testnet"), m1, m1, m1)
	r, err := Extract(cap)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(r.PMKIDs) != 1 {
		t.Errorf("duplicate PMKIDs should collapse to 1, got %d", len(r.PMKIDs))
	}
}

func TestExtract_RejectsNon80211(t *testing.T) {
	cap := buildPcap(t, pcap.LinkTypeEthernet, []byte{0x00, 0x01, 0x02, 0x03})
	if _, err := Extract(cap); err == nil {
		t.Error("expected an error for a non-802.11 (Ethernet) capture")
	}
}

func FuzzExtract(f *testing.F) {
	f.Add(buildPcap(f, pcap.LinkTypeIEEE802_11, beaconFrame(testBSSID, "n"), m1DataFrame(testBSSID, testSTA, realPMKID())))
	f.Add(buildPcapng(105, beaconFrame(testBSSID, "n"), m1DataFrame(testBSSID, testSTA, realPMKID())))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, in []byte) {
		_, _ = Extract(in)
	})
}

// --- pcapng container tests ----------------------------------------------

func u32le(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

// ngBlock wraps a pcapng block-specific body in the outer Block Type + Total
// Length framing (body padded to a 4-byte boundary).
func ngBlock(blockType uint32, body []byte) []byte {
	if pad := (4 - len(body)%4) % 4; pad != 0 {
		body = append(body, make([]byte, pad)...)
	}
	total := uint32(12 + len(body))
	out := append(u32le(blockType), u32le(total)...)
	out = append(out, body...)
	return append(out, u32le(total)...)
}

// buildPcapng assembles a minimal pcapng (SHB + IDB + one EPB per frame).
func buildPcapng(linkType uint16, frames ...[]byte) []byte {
	// SHB: byte-order magic + version 1.0 + section length -1.
	shbBody := append(u32le(0x1A2B3C4D), []byte{0x01, 0x00, 0x00, 0x00}...)
	shbBody = append(shbBody, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	out := ngBlock(0x0A0D0D0A, shbBody)
	// IDB: link type + reserved + snaplen.
	idbBody := []byte{byte(linkType), byte(linkType >> 8), 0x00, 0x00}
	idbBody = append(idbBody, u32le(0)...)
	out = append(out, ngBlock(0x00000001, idbBody)...)
	for _, f := range frames {
		epb := u32le(0)                             // interface id 0
		epb = append(epb, u32le(0)...)              // ts high
		epb = append(epb, u32le(0)...)              // ts low
		epb = append(epb, u32le(uint32(len(f)))...) // captured length
		epb = append(epb, u32le(uint32(len(f)))...) // original length
		epb = append(epb, f...)
		out = append(out, ngBlock(0x00000006, epb)...)
	}
	return out
}

func TestExtract_PcapngRaw80211(t *testing.T) {
	cap := buildPcapng(105,
		beaconFrame(testBSSID, "NgNet"),
		m1DataFrame(testBSSID, testSTA, realPMKID()),
	)
	r, err := Extract(cap)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.Format != "pcapng" {
		t.Errorf("Format = %q, want pcapng", r.Format)
	}
	if len(r.PMKIDs) != 1 || r.PMKIDs[0].ESSID != "NgNet" {
		t.Fatalf("pmkids = %+v", r.PMKIDs)
	}
	want := "WPA*01*a0a1a2a3a4a5a6a7a8a9aaabacadaeaf*aabbccddeeff*112233445566*4e674e6574***"
	if r.PMKIDs[0].HC22000Line != want {
		t.Errorf("line = %s\nwant %s", r.PMKIDs[0].HC22000Line, want)
	}
}

func TestExtract_PcapngRadiotap(t *testing.T) {
	rt := func(f []byte) []byte { return append(pcap.RadiotapHeader{}.Bytes(), f...) }
	cap := buildPcapng(127,
		rt(beaconFrame(testBSSID, "NgRt")),
		rt(m1DataFrame(testBSSID, testSTA, realPMKID())),
	)
	r, err := Extract(cap)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(r.PMKIDs) != 1 || r.PMKIDs[0].ESSID != "NgRt" || r.PMKIDs[0].HC22000Line == "" {
		t.Errorf("radiotap pcapng extraction failed: %+v", r.PMKIDs)
	}
}

func TestExtract_PcapngNon80211Rejected(t *testing.T) {
	cap := buildPcapng(1 /* Ethernet */, []byte{0x00, 0x01, 0x02, 0x03})
	if _, err := Extract(cap); err == nil {
		t.Error("expected an error for a pcapng with no 802.11 interface")
	}
}
