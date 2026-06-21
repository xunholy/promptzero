package eapolcap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/hashcat"
	"github.com/xunholy/promptzero/internal/pcap"
)

func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }

// eapolKey builds an EAPOL-Key frame with the given key-info word, replay
// counter, 32-byte nonce and 16-byte MIC. Layout matches internal/eapol's
// fixed offsets (RC b[9:17], nonce b[17:49], MIC b[81:97]).
func eapolKey(keyInfo uint16, rc, nonce, mic []byte) []byte {
	var d []byte
	d = append(d, 0x02)                // descriptor type (RSN)
	d = append(d, be16(keyInfo)...)    // key info
	d = append(d, be16(16)...)         // key length
	d = append(d, rc...)               // replay counter (8)
	d = append(d, nonce...)            // key nonce (32)
	d = append(d, make([]byte, 16)...) // key IV
	d = append(d, make([]byte, 8)...)  // RSC
	d = append(d, make([]byte, 8)...)  // key ID
	d = append(d, mic...)              // MIC (16)
	d = append(d, be16(0)...)          // key data length 0
	f := []byte{0x02, 0x03}            // 802.1X version + type (EAPOL-Key)
	f = append(f, be16(uint16(len(d)))...)
	return append(f, d...)
}

func eapolM1(rc, anonce []byte) []byte { return eapolKey(0x008A, rc, anonce, make([]byte, 16)) }
func eapolM2(rc, snonce, mic []byte) []byte {
	return eapolKey(0x010A, rc, snonce, mic)
}

func beaconFrame(bssid []byte, ssid string) []byte {
	b := []byte{0x80, 0x00, 0x00, 0x00}
	b = append(b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	b = append(b, bssid...)
	b = append(b, bssid...)
	b = append(b, 0x00, 0x10)
	b = append(b, make([]byte, 8)...)
	b = append(b, 0x64, 0x00)
	b = append(b, 0x01, 0x00)
	b = append(b, 0x00, byte(len(ssid)))
	return append(b, []byte(ssid)...)
}

// m1Frame builds a QoS data frame FromDS (AP -> STA) carrying LLC/SNAP + the M1.
func m1Frame(bssid, sta, rc, anonce []byte) []byte {
	b := []byte{0x88, 0x02, 0x00, 0x00} // QoS data, FromDS
	b = append(b, sta...)               // Addr1 = DA (STA)
	b = append(b, bssid...)             // Addr2 = BSSID (AP)
	b = append(b, bssid...)             // Addr3 = SA (AP)
	b = append(b, 0x00, 0x10)           // Sequence Control
	b = append(b, 0x00, 0x00)           // QoS Control
	b = append(b, llcSnapEAPOL...)
	return append(b, eapolM1(rc, anonce)...)
}

// m2Frame builds a QoS data frame ToDS (STA -> AP) carrying LLC/SNAP + the M2.
func m2Frame(bssid, sta, rc, snonce, mic []byte) []byte {
	b := []byte{0x88, 0x01, 0x00, 0x00} // QoS data, ToDS
	b = append(b, bssid...)             // Addr1 = BSSID (AP)
	b = append(b, sta...)               // Addr2 = SA (STA)
	b = append(b, bssid...)             // Addr3 = DA
	b = append(b, 0x00, 0x20)           // Sequence Control
	b = append(b, 0x00, 0x00)           // QoS Control
	b = append(b, llcSnapEAPOL...)
	return append(b, eapolM2(rc, snonce, mic)...)
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
			f = append(pcap.RadiotapHeader{}.Bytes(), f...)
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
	testRC    = []byte{0, 0, 0, 0, 0, 0, 0, 1}
)

func anonce() []byte {
	n := make([]byte, 32)
	for i := range n {
		n[i] = byte(0xA0 + i)
	}
	return n
}

func snonce() []byte {
	n := make([]byte, 32)
	for i := range n {
		n[i] = byte(0x50 + i)
	}
	return n
}

func micBytes() []byte {
	m := make([]byte, 16)
	for i := range m {
		m[i] = byte(0xC0 + i)
	}
	return m
}

// expectedLine builds the oracle line via the shipped, hashcat-anchored builder
// from the same fields the extractor should recover.
func expectedLine(t testing.TB, essid string) string {
	t.Helper()
	// The emitted EAPOL frame is the M2 frame with the MIC field zeroed.
	frame := eapolM2(testRC, snonce(), micBytes())
	zeroed := make([]byte, len(frame))
	copy(zeroed, frame)
	for i := micOffset; i < micEnd; i++ {
		zeroed[i] = 0
	}
	line, err := hashcat.EAPOL(
		hex.EncodeToString(micBytes()),
		hex.EncodeToString(testBSSID),
		hex.EncodeToString(testSTA),
		[]byte(essid),
		hex.EncodeToString(anonce()),
		hex.EncodeToString(zeroed),
		"00",
	)
	if err != nil {
		t.Fatalf("oracle hashcat.EAPOL: %v", err)
	}
	return line
}

func TestExtract_BeaconPlusHandshake(t *testing.T) {
	cap := buildPcap(t, pcap.LinkTypeIEEE802_11,
		beaconFrame(testBSSID, "testnet"),
		m1Frame(testBSSID, testSTA, testRC, anonce()),
		m2Frame(testBSSID, testSTA, testRC, snonce(), micBytes()),
	)
	r, err := Extract(cap)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(r.Handshakes) != 1 {
		t.Fatalf("handshakes = %d, want 1: %+v", len(r.Handshakes), r.Handshakes)
	}
	h := r.Handshakes[0]
	if h.BSSID != "aabbccddeeff" || h.StationMAC != "112233445566" {
		t.Errorf("macs = %s / %s", h.BSSID, h.StationMAC)
	}
	if h.ANonce != hex.EncodeToString(anonce()) {
		t.Errorf("anonce = %s", h.ANonce)
	}
	if h.MIC != hex.EncodeToString(micBytes()) {
		t.Errorf("mic = %s", h.MIC)
	}
	if h.ESSID != "testnet" {
		t.Errorf("essid = %s", h.ESSID)
	}
	if h.MessagePair != "00" {
		t.Errorf("message_pair = %s, want 00", h.MessagePair)
	}
	if got, want := h.HC22000Line, expectedLine(t, "testnet"); got != want {
		t.Errorf("line =\n %s\nwant\n %s", got, want)
	}
}

func TestExtract_Radiotap(t *testing.T) {
	cap := buildPcap(t, pcap.LinkTypeIEEE802_11Radiotap,
		beaconFrame(testBSSID, "rtnet"),
		m1Frame(testBSSID, testSTA, testRC, anonce()),
		m2Frame(testBSSID, testSTA, testRC, snonce(), micBytes()),
	)
	r, err := Extract(cap)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(r.Handshakes) != 1 || r.Handshakes[0].ESSID != "rtnet" || r.Handshakes[0].HC22000Line == "" {
		t.Errorf("radiotap extraction failed: %+v", r.Handshakes)
	}
}

func TestExtract_M2WithoutM1(t *testing.T) {
	cap := buildPcap(t, pcap.LinkTypeIEEE802_11,
		beaconFrame(testBSSID, "testnet"),
		m2Frame(testBSSID, testSTA, testRC, snonce(), micBytes()), // no M1
	)
	r, err := Extract(cap)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(r.Handshakes) != 0 {
		t.Errorf("an M2 with no matching M1 must not yield a handshake, got %+v", r.Handshakes)
	}
}

func TestExtract_MismatchedReplayCounter(t *testing.T) {
	otherRC := []byte{0, 0, 0, 0, 0, 0, 0, 9}
	cap := buildPcap(t, pcap.LinkTypeIEEE802_11,
		beaconFrame(testBSSID, "testnet"),
		m1Frame(testBSSID, testSTA, testRC, anonce()),
		m2Frame(testBSSID, testSTA, otherRC, snonce(), micBytes()), // different RC
	)
	r, err := Extract(cap)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(r.Handshakes) != 0 {
		t.Errorf("M1/M2 with mismatched replay counters must not pair, got %+v", r.Handshakes)
	}
}

func TestExtract_HandshakeWithoutESSID(t *testing.T) {
	cap := buildPcap(t, pcap.LinkTypeIEEE802_11,
		m1Frame(testBSSID, testSTA, testRC, anonce()),
		m2Frame(testBSSID, testSTA, testRC, snonce(), micBytes()),
	)
	r, err := Extract(cap)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(r.Handshakes) != 1 || r.Handshakes[0].HC22000Line != "" || !strings.Contains(r.Handshakes[0].Note, "ESSID") {
		t.Errorf("expected a handshake with no line + an ESSID note, got %+v", r.Handshakes)
	}
}

func TestExtract_Dedup(t *testing.T) {
	m1 := m1Frame(testBSSID, testSTA, testRC, anonce())
	m2 := m2Frame(testBSSID, testSTA, testRC, snonce(), micBytes())
	cap := buildPcap(t, pcap.LinkTypeIEEE802_11, beaconFrame(testBSSID, "testnet"), m1, m2, m1, m2)
	r, err := Extract(cap)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(r.Handshakes) != 1 {
		t.Errorf("duplicate handshakes should collapse to 1, got %d", len(r.Handshakes))
	}
}

func TestExtract_RejectsNon80211(t *testing.T) {
	cap := buildPcap(t, pcap.LinkTypeEthernet, []byte{0x00, 0x01, 0x02, 0x03})
	if _, err := Extract(cap); err == nil {
		t.Error("expected an error for a non-802.11 (Ethernet) capture")
	}
}

func FuzzExtract(f *testing.F) {
	f.Add(buildPcap(f, pcap.LinkTypeIEEE802_11,
		beaconFrame(testBSSID, "n"),
		m1Frame(testBSSID, testSTA, testRC, anonce()),
		m2Frame(testBSSID, testSTA, testRC, snonce(), micBytes())))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, in []byte) {
		_, _ = Extract(in)
	})
}
