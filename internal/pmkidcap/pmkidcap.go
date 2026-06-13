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
// No confidently-wrong output: only classic libpcap 802.11 / radiotap captures
// are accepted (pcapng is left to hcxpcapngtool); a PMKID is taken only from an
// EAPOL message-1 with unencrypted key data and a 16-byte RSN PMKID KDE; the
// all-zero PMKID hostapd sends when none is available is dropped (not crackable);
// and the ready-to-crack line is built only once the network's ESSID has been
// seen in a beacon / probe-response / association-request (a PMKID with no ESSID
// is reported, but no line is fabricated for it).
//
// Wrap-vs-native: native — orchestration over in-tree decoders plus a fixed
// LLC/SNAP + EtherType check; stdlib only, no new go.mod dependency. Covers
// classic pcap (LINKTYPE_IEEE802_11 / _RADIOTAP); pcapng and the EAPOL 4-way
// (type-02) handshake are deferred (the latter needs M1–M4 pairing).
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

// Extract scans a classic-libpcap 802.11 capture for clientless PMKIDs.
func Extract(capture []byte) (*Result, error) {
	r, err := pcap.NewReader(bytes.NewReader(capture))
	if err != nil {
		return nil, fmt.Errorf("pmkidcap: %w", err)
	}
	lt := r.LinkType()
	radiotap := lt == pcap.LinkTypeIEEE802_11Radiotap
	if lt != pcap.LinkTypeIEEE802_11 && !radiotap {
		return nil, fmt.Errorf("pmkidcap: link type %d is not an 802.11 capture (want 105 or 127); pcapng is not supported", lt)
	}

	res := &Result{Format: "pcap", LinkType: pcap.LinkTypeName(uint32(lt))}
	ssidByBSSID := map[string]string{}
	seen := map[string]bool{} // dedup key: bssid|sta|pmkid

	for {
		_, frame, err := r.Next()
		if err != nil {
			break // EOF or a truncated trailing record — stop cleanly
		}
		res.Packets++
		if radiotap {
			frame = stripRadiotap(frame)
		}
		f, derr := ieee80211.DecodeBytes(frame)
		if derr != nil {
			continue
		}
		switch ieee80211.FrameType(f.FrameControl.Type) {
		case ieee80211.FrameTypeManagement:
			if ssid := ssidFromIEs(f); ssid != "" && f.BSSID != "" {
				ssidByBSSID[f.BSSID] = ssid
			}
		case ieee80211.FrameTypeData:
			applyDataFrame(res, &f, seen)
		}
	}

	// Resolve ESSIDs and build the crackable lines.
	for i := range res.PMKIDs {
		e := &res.PMKIDs[i]
		e.ESSID = ssidByBSSID[e.BSSID]
		if e.ESSID == "" {
			e.Note = "ESSID not seen in this capture — supply it to wifi_pmkid_hc22000 to build the line"
			continue
		}
		if line, err := hashcat.PMKID(e.PMKID, e.BSSID, e.StationMAC, []byte(e.ESSID)); err == nil {
			e.HC22000Line = line
		}
	}
	res.NetworksSeen = len(ssidByBSSID)
	res.Note = noteFor(res)
	if len(res.PMKIDs) > 0 {
		res.HashcatCmd = "hashcat -m 22000 -a 0 capture.hc22000 wordlist.txt"
	}
	return res, nil
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
