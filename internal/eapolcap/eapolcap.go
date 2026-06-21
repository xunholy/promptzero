// Package eapolcap extracts WPA/WPA2 4-way-handshake (EAPOL type-02) hashes
// from an 802.11 packet capture and emits ready-to-crack hashcat mode-22000
// lines.
//
// The 4-way handshake is the classic WPA2 capture: when a client associates,
// the AP and station exchange four EAPOL-Key frames. Message 1 (AP -> STA)
// carries the ANonce; message 2 (STA -> AP) carries the SNonce and the MIC
// computed over the EAPOL frame with the PTK. With the ANonce (from M1), the
// MIC and the MIC-bearing EAPOL frame (from M2), and both MACs and the ESSID, a
// crackable hash is recovered. The canonical pcap -> .hc22000 converter is
// hcxpcapngtool (a third-party C binary); this does the dominant M1+M2 case
// natively, composing the in-tree decoders: the pcap / pcapng readers
// (internal/pcap, internal/pcapng), the DS-bit-correct 802.11 frame parser
// (internal/ieee80211), the EAPOL-Key dissector (internal/eapol), and the
// mode-22000 line builder (internal/hashcat, anchored on hashcat's published
// example). It is the type-02 counterpart of internal/pmkidcap (type-01,
// clientless PMKID); the capture-walk deliberately mirrors that package rather
// than coupling the two extractors.
//
// No confidently-wrong output: only 802.11 / radiotap link types are decoded
// (link type 105 / 127); a handshake is emitted only when a real M1 (Ack, no
// MIC) is paired with a real M2 (MIC set) sharing the same BSSID, station MAC
// and 8-byte replay counter — the structural guarantee they belong to the same
// exchange; the MIC field is zeroed in the emitted EAPOL frame (as hashcat
// requires); the all-zero MIC an incomplete M2 would carry is dropped; and the
// crackable line is built only once the ESSID has been seen in a beacon /
// probe-response / association-request (a handshake with no ESSID is reported,
// with a note, but no line is fabricated).
//
// Two message pairs are extracted: M1+M2 (ANonce from M1, hashcat message_pair
// 0x00) and — when M1 was missed — M2+M3 (ANonce from the M3 whose replay
// counter is the M2's + 1, message_pair 0x02; the M2 still supplies the MIC and
// the MIC-bearing frame). The 0x02 index is anchored on hashcat's own published
// mode-22000 example, which is itself an M2+M3 case. Clean-capture lines carry
// no nonce-correction flags (0x10/0x20/0x80); the M1+M4 and M3+M4 pairings and
// nonce-error-correction heuristics remain deferred.
//
// Wrap-vs-native: native — orchestration over in-tree decoders plus a fixed
// LLC/SNAP + EtherType check and the documented EAPOL-Key frame layout; stdlib
// only, no new go.mod dependency.
package eapolcap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/eapol"
	"github.com/xunholy/promptzero/internal/hashcat"
	"github.com/xunholy/promptzero/internal/ieee80211"
	"github.com/xunholy/promptzero/internal/pcap"
	"github.com/xunholy/promptzero/internal/pcapng"
)

// Handshake is one recovered WPA/WPA2 4-way handshake (M1 + M2).
type Handshake struct {
	BSSID         string `json:"bssid"`
	StationMAC    string `json:"station_mac"`
	ESSID         string `json:"essid,omitempty"`
	ANonce        string `json:"anonce"`         // from M1
	MIC           string `json:"mic"`            // from M2
	ReplayCounter string `json:"replay_counter"` // shared by M1 and M2
	MessagePair   string `json:"message_pair"`   // "00" (M1+M2)
	// HC22000Line is the ready-to-crack hashcat mode-22000 line, built only when
	// the ESSID is known.
	HC22000Line string `json:"hc22000_line,omitempty"`
	Note        string `json:"note,omitempty"`

	// eapolZero is the MIC-zeroed M2 EAPOL frame (hex) carried internally
	// until the line is built; unexported so it stays out of the JSON.
	eapolZero string
}

// Result is the outcome of a capture scan.
type Result struct {
	Format       string      `json:"format"`
	LinkType     string      `json:"link_type"`
	Packets      int         `json:"packets"`
	NetworksSeen int         `json:"networks_seen"`
	Handshakes   []Handshake `json:"handshakes"`
	HashcatCmd   string      `json:"hashcat_command,omitempty"`
	Note         string      `json:"note"`
}

// llcSnapEAPOL is the LLC/SNAP header that prefixes an EAPOL payload in an
// 802.11 data frame: AA-AA-03 (SNAP) + 00-00-00 (OUI) + 88-8E (EtherType EAPOL).
var llcSnapEAPOL = []byte{0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E} //nolint:gochecknoglobals

// pcapngMagic is the Section Header Block type that opens every pcapng file.
var pcapngMagic = []byte{0x0A, 0x0D, 0x0D, 0x0A} //nolint:gochecknoglobals

// micOffset / micEnd bracket the 16-byte MIC field in an EAPOL-Key frame: the
// 4-byte 802.1X header + descriptor(1) + key info(2) + key length(2) + replay
// counter(8) + key nonce(32) + key IV(16) + key RSC(8) + key ID(8) = 81.
const (
	micOffset = 81
	micEnd    = 97
)

// m1 holds the ANonce captured from an EAPOL message-1, keyed by the exchange
// it belongs to.
type m1 struct {
	anonce string
	bssid  string
	sta    string
	rc     string
}

// m2 holds the MIC-bearing message-2 fields needed to build the crackable line.
type m2 struct {
	bssid     string
	sta       string
	rc        string
	mic       string
	eapolZero string // the EAPOL frame, hex, with the MIC field zeroed
}

// scanner accumulates the SSID-per-BSSID map and the pending M1/M2/M3 frames
// across a capture, regardless of the on-disk container format.
type scanner struct {
	res         *Result
	ssidByBSSID map[string]string
	m1s         map[string]m1     // key: bssid|sta|rc
	m3s         map[string]string // key: bssid|sta|rc -> ANonce (M3 carries it)
	m2s         []m2
	seen        map[string]bool // dedup key: bssid|sta|rc|mic
}

func newScanner(format string) *scanner {
	return &scanner{
		res:         &Result{Format: format},
		ssidByBSSID: map[string]string{},
		m1s:         map[string]m1{},
		m3s:         map[string]string{},
		seen:        map[string]bool{},
	}
}

func hsKey(bssid, sta, rc string) string {
	return strings.ToLower(bssid + "|" + sta + "|" + rc)
}

// rcPlusOne returns the 8-byte big-endian replay counter incremented by one, as
// a 16-char hex string — the relationship between an M2's replay counter and
// the M3 of the same handshake (the AP increments it by one between the two
// message pairs). Returns "" for an unparseable counter, which then matches no
// stored M3 (so a malformed counter never produces a false pairing).
func rcPlusOne(rcHex string) string {
	b, err := hex.DecodeString(rcHex)
	if err != nil || len(b) != 8 {
		return ""
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, binary.BigEndian.Uint64(b)+1)
	return hex.EncodeToString(out)
}

// norm lower-cases a hex value and strips the ':' / '-' separators the 802.11
// and EAPOL decoders emit, so the recovered MACs / nonces / MIC are stored and
// serialised in the same clean form as internal/pmkidcap's PMKID.
func norm(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", "-", "").Replace(s))
}

// frame processes one captured frame, stripping a radiotap header first when the
// link type calls for it.
func (s *scanner) frame(lt pcap.LinkType, frame []byte) {
	s.res.Packets++
	if lt == pcap.LinkTypeIEEE802_11Radiotap {
		frame = stripRadiotap(frame)
	}
	f, err := ieee80211.DecodeBytes(frame)
	if err != nil {
		return
	}
	switch ieee80211.FrameType(f.FrameControl.Type) {
	case ieee80211.FrameTypeManagement:
		if ssid := ssidFromIEs(f); ssid != "" && f.BSSID != "" {
			s.ssidByBSSID[norm(f.BSSID)] = ssid
		}
	case ieee80211.FrameTypeData:
		s.dataFrame(&f)
	}
}

// dataFrame pulls an EAPOL-Key M1 or M2 out of a data frame.
func (s *scanner) dataFrame(f *ieee80211.Frame) {
	body, err := hex.DecodeString(f.MACBodyHex)
	if err != nil || len(body) < len(llcSnapEAPOL) || !bytes.Equal(body[:len(llcSnapEAPOL)], llcSnapEAPOL) {
		return
	}
	eapolFrame := body[len(llcSnapEAPOL):]
	key, err := eapol.DecodeBytes(eapolFrame)
	if err != nil {
		return
	}

	// The station is whichever of SA / DA is not the BSSID — correct for both
	// M1 (AP -> STA: SA == BSSID, so STA == DA) and M2 (STA -> AP: SA == STA).
	bssid := f.BSSID
	sta := f.SA
	if sta == "" || strings.EqualFold(sta, bssid) {
		sta = f.DA
	}
	if bssid == "" || sta == "" {
		return
	}

	bssid, sta = norm(bssid), norm(sta)
	rc := norm(key.ReplayCounter)
	switch key.HandshakeMessage {
	case "M1":
		// M1 carries no MIC; capture its ANonce for pairing.
		s.m1s[hsKey(bssid, sta, rc)] = m1{
			anonce: norm(key.KeyNonce), bssid: bssid, sta: sta, rc: rc,
		}
	case "M2":
		if len(eapolFrame) < micEnd {
			return
		}
		mic := norm(key.KeyMIC)
		if mic == "" || mic == strings.Repeat("0", 32) {
			return // no usable MIC
		}
		zeroed := make([]byte, len(eapolFrame))
		copy(zeroed, eapolFrame)
		for i := micOffset; i < micEnd; i++ {
			zeroed[i] = 0
		}
		s.m2s = append(s.m2s, m2{
			bssid: bssid, sta: sta, rc: rc,
			mic: mic, eapolZero: hex.EncodeToString(zeroed),
		})
	case "M3":
		// M3 (AP -> STA) carries the same ANonce the AP put in M1, so it lets
		// an M2 be paired even when M1 was missed (capture started mid-
		// handshake). Its replay counter is the M2's + 1.
		s.m3s[hsKey(bssid, sta, rc)] = norm(key.KeyNonce)
	}
}

// addHandshake records one recovered handshake, deduped by BSSID / station /
// replay counter / MIC so the same M2 is never emitted twice (e.g. once via M1
// and once via M3). ANonce + message_pair vary by which message supplied them.
func (s *scanner) addHandshake(two m2, anonce, messagePair string) {
	dkey := hsKey(two.bssid, two.sta, two.rc) + "|" + two.mic
	if s.seen[dkey] {
		return
	}
	s.seen[dkey] = true
	s.res.Handshakes = append(s.res.Handshakes, Handshake{
		BSSID: two.bssid, StationMAC: two.sta,
		ANonce: anonce, MIC: two.mic,
		ReplayCounter: two.rc, MessagePair: messagePair,
		eapolZero: two.eapolZero,
	})
}

// finish pairs each M2 with the message that supplies the ANonce — its M1
// (same replay counter, hashcat message_pair 00, preferred) or, when M1 was
// missed, its M3 (replay counter + 1, message_pair 02) — then resolves the
// ESSID, builds the crackable lines, and fills the summary fields.
func (s *scanner) finish() *Result {
	// Pass 1: M1+M2 — ANonce from M1, same replay counter.
	for _, two := range s.m2s {
		if one, ok := s.m1s[hsKey(two.bssid, two.sta, two.rc)]; ok {
			s.addHandshake(two, one.anonce, "00")
		}
	}
	// Pass 2: M2+M3 — ANonce from the M3 whose replay counter is the M2's + 1.
	// An M2 already paired with an M1 above is skipped by addHandshake's dedup
	// (same MIC), so M1+M2 wins when both are present.
	for _, two := range s.m2s {
		if anonce, ok := s.m3s[hsKey(two.bssid, two.sta, rcPlusOne(two.rc))]; ok {
			s.addHandshake(two, anonce, "02")
		}
	}

	for i := range s.res.Handshakes {
		h := &s.res.Handshakes[i]
		h.ESSID = s.ssidByBSSID[h.BSSID]
		if h.ESSID == "" {
			h.Note = "ESSID not seen in this capture — supply it to wifi_eapol_hc22000 to build the line"
			continue
		}
		line, err := hashcat.EAPOL(h.MIC, h.BSSID, h.StationMAC, []byte(h.ESSID), h.ANonce, h.eapolZero, h.MessagePair)
		if err != nil {
			h.Note = "could not build hc22000 line: " + err.Error()
			continue
		}
		h.HC22000Line = line
	}

	s.res.NetworksSeen = len(s.ssidByBSSID)
	s.res.Note = noteFor(s.res)
	if len(s.res.Handshakes) > 0 {
		s.res.HashcatCmd = "hashcat -m 22000 -a 0 capture.hc22000 wordlist.txt"
	}
	return s.res
}

// is80211 reports whether a link type is one of the 802.11 captures we decode.
func is80211(lt pcap.LinkType) bool {
	return lt == pcap.LinkTypeIEEE802_11 || lt == pcap.LinkTypeIEEE802_11Radiotap
}

// Extract scans an 802.11 capture for WPA/WPA2 4-way handshakes (M1+M2) and
// emits ready-to-crack hashcat mode-22000 lines. Both classic libpcap and
// pcapng (the format Marauder / hcxdumptool write) containers are accepted.
func Extract(capture []byte) (*Result, error) {
	if bytes.HasPrefix(capture, pcapngMagic) {
		return extractPcapng(capture)
	}
	return extractPcap(capture)
}

// extractPcap handles a classic libpcap container (single link type for the file).
func extractPcap(capture []byte) (*Result, error) {
	r, err := pcap.NewReader(bytes.NewReader(capture))
	if err != nil {
		return nil, fmt.Errorf("eapolcap: %w", err)
	}
	lt := r.LinkType()
	if !is80211(lt) {
		return nil, fmt.Errorf("eapolcap: link type %d is not an 802.11 capture (want 105 or 127)", lt)
	}
	s := newScanner("pcap")
	s.res.LinkType = pcap.LinkTypeName(uint32(lt))
	for {
		_, frame, err := r.Next()
		if err != nil {
			break // EOF or a truncated trailing record — stop cleanly
		}
		s.frame(lt, frame)
	}
	return s.finish(), nil
}

// extractPcapng handles a pcapng container, looking up each Enhanced Packet
// Block's link type from its interface.
func extractPcapng(capture []byte) (*Result, error) {
	sum, err := pcapng.Inspect(capture, pcapng.InspectOpts{MaxRecords: 0, MaxPayloadBytes: 1 << 16})
	if err != nil {
		return nil, fmt.Errorf("eapolcap: pcapng: %w", err)
	}
	s := newScanner("pcapng")
	saw80211 := false
	for _, sec := range sum.Sections {
		for _, rec := range sec.Records {
			lt := interfaceLinkType(sec.Interfaces, rec.InterfaceID)
			if !is80211(lt) {
				continue
			}
			saw80211 = true
			if s.res.LinkType == "" {
				s.res.LinkType = pcap.LinkTypeName(uint32(lt))
			}
			frame, derr := hex.DecodeString(rec.PayloadHex)
			if derr != nil {
				continue
			}
			s.frame(lt, frame)
		}
	}
	if !saw80211 {
		return nil, fmt.Errorf("eapolcap: pcapng has no 802.11 interface (link type 105 / 127)")
	}
	return s.finish(), nil
}

// interfaceLinkType resolves an EPB's interface id to its link type, defaulting
// to the first interface when the id is out of range.
func interfaceLinkType(ifaces []pcapng.Interface, id uint32) pcap.LinkType {
	if int(id) < len(ifaces) {
		return pcap.LinkType(ifaces[id].LinkType)
	}
	if len(ifaces) > 0 {
		return pcap.LinkType(ifaces[0].LinkType)
	}
	return 0
}

// ssidFromIEs returns the decoded SSID from a management frame's IEs, or "".
func ssidFromIEs(f ieee80211.Frame) string {
	for _, ie := range f.InformationElements {
		if ie.ID != 0 { // 0 = SSID
			continue
		}
		if ie.Decoded != nil {
			if s, ok := ie.Decoded["ssid"].(string); ok {
				return s
			}
		}
	}
	return ""
}

// stripRadiotap removes a radiotap header, whose little-endian it_len lives at
// bytes 2..4. Returns the input unchanged if it is too short or the length is
// implausible (so a malformed header can never slice out of range).
func stripRadiotap(frame []byte) []byte {
	if len(frame) < 4 {
		return frame
	}
	itLen := int(binary.LittleEndian.Uint16(frame[2:4]))
	if itLen < 4 || itLen > len(frame) {
		return frame
	}
	return frame[itLen:]
}

func noteFor(res *Result) string {
	withLine := 0
	for i := range res.Handshakes {
		if res.Handshakes[i].HC22000Line != "" {
			withLine++
		}
	}
	if len(res.Handshakes) == 0 {
		return fmt.Sprintf("Scanned %d packets across %d network(s); no crackable handshake found. "+
			"Absence is not proof none exists — only the M1+M2 and M2+M3 message pairs are extracted. Offline; no network, no device.",
			res.Packets, res.NetworksSeen)
	}
	return fmt.Sprintf("Found %d handshake(s) (%d ready-to-crack with ESSID) across %d packets / %d network(s). "+
		"Native M1+M2 / M2+M3 path — no hcxpcapngtool. Offline; no network, no device.",
		len(res.Handshakes), withLine, res.Packets, res.NetworksSeen)
}
