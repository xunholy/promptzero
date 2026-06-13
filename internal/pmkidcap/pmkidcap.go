// Package pmkidcap extracts WPA/WPA2 PMKID hashes from an 802.11 packet capture
// and emits ready-to-crack hashcat mode-22000 lines.
//
// The clientless PMKID attack is the dominant modern WPA2 capture: a single
// EAPOL message-1 frame from the AP carries the PMKID in an RSN PMKID KDE, so a
// crackable hash is recovered with no client handshake. The canonical pcap →
// .hc22000 converter is hcxpcapngtool (a third-party C binary marauder_handoff
// shells out to). This does the PMKID case natively, in pure Go, by composing
// the in-tree decoders: the pcap reader (internal/pcap), the 802.11 frame parser
// (internal/ieee80211 — DS-bit-correct addresses and the QoS/+HTC-correct body
// offset), the EAPOL-Key dissector (internal/eapol — the PMKID KDE), and the
// mode-22000 line builder (internal/hashcat, anchored on hashcat's example).
//
// Both container formats are handled: classic libpcap and pcapng (the format
// Marauder / hcxdumptool actually write), each carrying 802.11 with or without a
// radiotap header.
//
// No confidently-wrong output: only 802.11 / radiotap link types are decoded
// (link type 105 / 127); a PMKID is taken only from an EAPOL message-1 with
// unencrypted key data and a 16-byte RSN PMKID KDE; the all-zero PMKID hostapd
// sends when none is available is dropped (not crackable); and the ready-to-crack
// line is built only once the network's ESSID has been seen in a beacon /
// probe-response / association-request (a PMKID with no ESSID is reported, but no
// line is fabricated for it).
//
// Wrap-vs-native: native — orchestration over in-tree decoders (the libpcap and
// pcapng readers, the 802.11 parser, the EAPOL dissector, the hashcat builder)
// plus a fixed LLC/SNAP + EtherType check; stdlib only, no new go.mod dependency.
// The EAPOL 4-way (type-02) handshake is deferred (it needs M1–M4 pairing).
package pmkidcap

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

// Entry is one recovered PMKID.
type Entry struct {
	PMKID      string `json:"pmkid"`
	BSSID      string `json:"bssid"`
	StationMAC string `json:"station_mac"`
	// ESSID is the network name, resolved from a beacon / probe-response /
	// association-request seen in the same capture; empty when not seen.
	ESSID string `json:"essid,omitempty"`
	// HC22000Line is the ready-to-crack hashcat mode-22000 line, built only when
	// the ESSID is known.
	HC22000Line string `json:"hc22000_line,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Result is the outcome of a capture scan.
type Result struct {
	Format       string  `json:"format"`
	LinkType     string  `json:"link_type"`
	Packets      int     `json:"packets"`
	NetworksSeen int     `json:"networks_seen"`
	PMKIDs       []Entry `json:"pmkids"`
	HashcatCmd   string  `json:"hashcat_command,omitempty"`
	Note         string  `json:"note"`
}

// llcSnapEAPOL is the LLC/SNAP header that prefixes an EAPOL payload in an
// 802.11 data frame: AA-AA-03 (SNAP) + 00-00-00 (OUI) + 88-8E (EtherType EAPOL).
var llcSnapEAPOL = []byte{0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E} //nolint:gochecknoglobals

// pcapngMagic is the Section Header Block type that opens every pcapng file
// (a palindrome, byte-order independent).
var pcapngMagic = []byte{0x0A, 0x0D, 0x0D, 0x0A} //nolint:gochecknoglobals

// scanner accumulates the SSID-per-BSSID map and the recovered PMKIDs across a
// capture, regardless of the on-disk container format.
type scanner struct {
	res         *Result
	ssidByBSSID map[string]string
	seen        map[string]bool // dedup key: bssid|sta|pmkid
}

func newScanner(format string) *scanner {
	return &scanner{
		res:         &Result{Format: format},
		ssidByBSSID: map[string]string{},
		seen:        map[string]bool{},
	}
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
			s.ssidByBSSID[f.BSSID] = ssid
		}
	case ieee80211.FrameTypeData:
		applyDataFrame(s.res, &f, s.seen)
	}
}

// finish resolves each PMKID's ESSID, builds the crackable lines, and fills the
// summary fields.
func (s *scanner) finish() *Result {
	for i := range s.res.PMKIDs {
		e := &s.res.PMKIDs[i]
		e.ESSID = s.ssidByBSSID[e.BSSID]
		if e.ESSID == "" {
			e.Note = "ESSID not seen in this capture — supply it to wifi_pmkid_hc22000 to build the line"
			continue
		}
		if line, err := hashcat.PMKID(e.PMKID, e.BSSID, e.StationMAC, []byte(e.ESSID)); err == nil {
			e.HC22000Line = line
		}
	}
	s.res.NetworksSeen = len(s.ssidByBSSID)
	s.res.Note = noteFor(s.res)
	if len(s.res.PMKIDs) > 0 {
		s.res.HashcatCmd = "hashcat -m 22000 -a 0 capture.hc22000 wordlist.txt"
	}
	return s.res
}

// is80211 reports whether a link type is one of the 802.11 captures we decode.
func is80211(lt pcap.LinkType) bool {
	return lt == pcap.LinkTypeIEEE802_11 || lt == pcap.LinkTypeIEEE802_11Radiotap
}

// Extract scans an 802.11 capture for clientless PMKIDs and emits ready-to-crack
// hashcat mode-22000 lines. Both classic libpcap and pcapng (the format Marauder
// / hcxdumptool write) containers are accepted.
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
		return nil, fmt.Errorf("pmkidcap: %w", err)
	}
	lt := r.LinkType()
	if !is80211(lt) {
		return nil, fmt.Errorf("pmkidcap: link type %d is not an 802.11 capture (want 105 or 127)", lt)
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
// Block's link type from its interface. The in-tree pcapng decoder is asked for
// every record with full payloads (the summary caps are disabled here).
func extractPcapng(capture []byte) (*Result, error) {
	sum, err := pcapng.Inspect(capture, pcapng.InspectOpts{MaxRecords: 0, MaxPayloadBytes: 1 << 16})
	if err != nil {
		return nil, fmt.Errorf("pmkidcap: pcapng: %w", err)
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
		return nil, fmt.Errorf("pmkidcap: pcapng has no 802.11 interface (link type 105 / 127)")
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

// applyDataFrame pulls a PMKID from a data frame carrying an EAPOL message-1.
func applyDataFrame(res *Result, f *ieee80211.Frame, seen map[string]bool) {
	body, err := hex.DecodeString(f.MACBodyHex)
	if err != nil || len(body) < len(llcSnapEAPOL) || !bytes.Equal(body[:len(llcSnapEAPOL)], llcSnapEAPOL) {
		return
	}
	key, err := eapol.DecodeBytes(body[len(llcSnapEAPOL):])
	if err != nil || key.HandshakeMessage != "M1" || key.KeyInfo.EncryptedKeyData {
		return
	}
	pmkid := pmkidFromKDEs(key)
	if pmkid == "" {
		return
	}
	bssid := f.BSSID
	sta := f.DA
	if sta == "" || strings.EqualFold(sta, bssid) {
		sta = f.SA
	}
	dkey := strings.ToLower(bssid + "|" + sta + "|" + pmkid)
	if seen[dkey] {
		return
	}
	seen[dkey] = true
	res.PMKIDs = append(res.PMKIDs, Entry{PMKID: pmkid, BSSID: bssid, StationMAC: sta})
}

// pmkidFromKDEs returns the lower-cased 16-byte RSN PMKID from an EAPOL key's
// KDE list, or "" when there is no usable PMKID (wrong length, or the all-zero
// placeholder hostapd emits when it has none).
func pmkidFromKDEs(key eapol.EAPOLKey) string {
	for _, kde := range key.KDEs {
		if kde.DataType != 4 { // 4 = PMKID
			continue
		}
		h := strings.ToLower(strings.TrimSpace(kde.DataHex))
		if len(h) != 32 {
			continue
		}
		if h == strings.Repeat("0", 32) {
			continue // hostapd's "no PMKID" placeholder
		}
		return h
	}
	return ""
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
	for i := range res.PMKIDs {
		if res.PMKIDs[i].HC22000Line != "" {
			withLine++
		}
	}
	if len(res.PMKIDs) == 0 {
		return fmt.Sprintf("Scanned %d packets across %d network(s); no clientless PMKID found. "+
			"Absence is not proof none exists — only EAPOL message-1 PMKIDs are extracted. Offline; no network, no device.",
			res.Packets, res.NetworksSeen)
	}
	return fmt.Sprintf("Found %d PMKID(s) (%d ready-to-crack with ESSID) across %d packets / %d network(s). "+
		"Native PMKID path — no hcxpcapngtool. Offline; no network, no device.",
		len(res.PMKIDs), withLine, res.Packets, res.NetworksSeen)
}
