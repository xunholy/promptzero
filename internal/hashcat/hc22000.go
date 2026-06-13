// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hashcat builds hashcat-crackable hash lines natively, in pure Go.
//
// # Wrap-vs-native judgement
//
// Native. The canonical pcap → .hc22000 converter in the ecosystem is
// hcxpcapngtool (hcxtools), a separate C binary the marauder_handoff_hashcat
// tool shells out to. The hashcat mode-22000 LINE FORMAT, however, is a
// short, fully-documented, deterministic text layout — a "*"-delimited
// record — that needs no external binary to assemble once the operator
// holds the fields. Reimplementing the PMKID-line format natively removes a
// third-party dependency for the clientless-PMKID case (the dominant modern
// WPA2 capture): given the PMKID and the two MACs + ESSID an operator
// already has (from wifi_eapol_decode, a Marauder sniffpmkid run, or a
// Proxmark-style capture), it emits the ready-to-crack line offline.
//
// Correctness is anchored on hashcat's own published example hash for mode
// 22000 (the ESSID field decodes to the ASCII "hashcat-essid", a strong
// self-consistency check that the example is reproduced exactly).
//
// # Covered
//
//   - PMKID lines (message type 01): WPA*01*PMKID*AP_MAC*STA_MAC*ESSID***.
//   - EAPOL 4-way-handshake lines (message type 02):
//     WPA*02*MIC*AP_MAC*STA_MAC*ESSID*ANONCE*EAPOL*MESSAGEPAIR. Built from the
//     fields an operator already holds once a handshake is decoded (MIC, AP
//     nonce, the EAPOL frame bytes, the message-pair byte). Anchored on
//     hashcat's published mode-22000 EAPOL example (the ESSID decodes to ASCII
//     "TP-LINK_HASHCAT_TEST").
//
// # Deliberately deferred
//
//   - pcapng PARSING — extracting those type-02 fields from a raw capture
//     (pairing M1/M2/M3/M4, computing the message-pair flags) is the larger
//     native-pcapng effort hcxpcapngtool still does. This package assembles the
//     line once the fields are in hand; it does not parse the capture.
package hashcat

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// PMKID builds a hashcat mode-22000 PMKID (type 01) line from the four
// fields of a clientless-PMKID capture. The output is the single line
//
//	WPA*01*<pmkid>*<ap_mac>*<sta_mac>*<essid_hex>***
//
// with the three trailing fields (ANONCE, EAPOL, MESSAGEPAIR) empty, as
// hashcat requires for a PMKID record. All hex is lower-cased. The caller
// adds a trailing newline when writing a .hc22000 file.
//
// pmkid must be 16 bytes (32 hex chars); apMAC and staMAC must be 6 bytes
// each (separators and a 0x prefix are tolerated); essid must be 1..32
// bytes (the 802.11 SSID length limit). A confidently-malformed field is
// rejected rather than emitted, so the line never silently fails to crack.
func PMKID(pmkid, apMAC, staMAC string, essid []byte) (string, error) {
	p, err := parseFixed(pmkid, 16, "pmkid")
	if err != nil {
		return "", err
	}
	ap, err := parseFixed(apMAC, 6, "ap_mac")
	if err != nil {
		return "", err
	}
	sta, err := parseFixed(staMAC, 6, "sta_mac")
	if err != nil {
		return "", err
	}
	if len(essid) == 0 || len(essid) > 32 {
		return "", fmt.Errorf("hashcat: essid must be 1..32 bytes; got %d", len(essid))
	}
	return fmt.Sprintf("WPA*01*%s*%s*%s*%s***",
		hex.EncodeToString(p),
		hex.EncodeToString(ap),
		hex.EncodeToString(sta),
		hex.EncodeToString(essid)), nil
}

// EAPOL builds a hashcat mode-22000 EAPOL 4-way-handshake (type 02) line from
// the fields of a decoded handshake. The output is the single line
//
//	WPA*02*<mic>*<ap_mac>*<sta_mac>*<essid_hex>*<anonce>*<eapol>*<message_pair>
//
// All hex is lower-cased. The caller adds a trailing newline when writing a
// .hc22000 file.
//
// mic must be 16 bytes; apMAC and staMAC 6 bytes each; anonce 32 bytes;
// messagePair 1 byte (separators and a 0x prefix are tolerated on every hex
// field); essid 1..32 bytes; eapol 1..256 bytes (hashcat's EAPOL field cap). A
// confidently-malformed field is rejected rather than emitted, so the line never
// silently fails to crack.
func EAPOL(mic, apMAC, staMAC string, essid []byte, anonce, eapol, messagePair string) (string, error) {
	m, err := parseFixed(mic, 16, "mic")
	if err != nil {
		return "", err
	}
	ap, err := parseFixed(apMAC, 6, "ap_mac")
	if err != nil {
		return "", err
	}
	sta, err := parseFixed(staMAC, 6, "sta_mac")
	if err != nil {
		return "", err
	}
	an, err := parseFixed(anonce, 32, "anonce")
	if err != nil {
		return "", err
	}
	mp, err := parseFixed(messagePair, 1, "message_pair")
	if err != nil {
		return "", err
	}
	ea, err := parseVar(eapol, 1, 256, "eapol")
	if err != nil {
		return "", err
	}
	if len(essid) == 0 || len(essid) > 32 {
		return "", fmt.Errorf("hashcat: essid must be 1..32 bytes; got %d", len(essid))
	}
	return fmt.Sprintf("WPA*02*%s*%s*%s*%s*%s*%s*%s",
		hex.EncodeToString(m),
		hex.EncodeToString(ap),
		hex.EncodeToString(sta),
		hex.EncodeToString(essid),
		hex.EncodeToString(an),
		hex.EncodeToString(ea),
		hex.EncodeToString(mp)), nil
}

// parseVar strips separators / 0x, hex-decodes, and requires the byte length to
// fall within [min, max], returning a clear error otherwise.
func parseVar(s string, minLen, maxLen int, field string) ([]byte, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(strings.TrimSpace(s))
	if strings.HasPrefix(strings.ToLower(clean), "0x") {
		clean = clean[2:]
	}
	if clean == "" {
		return nil, fmt.Errorf("hashcat: %s is required (%d..%d bytes hex)", field, minLen, maxLen)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hashcat: %s is not valid hex: %w", field, err)
	}
	if len(b) < minLen || len(b) > maxLen {
		return nil, fmt.Errorf("hashcat: %s must be %d..%d bytes; got %d", field, minLen, maxLen, len(b))
	}
	return b, nil
}

// parseFixed strips separators / 0x, hex-decodes, and requires exactly n
// bytes, returning a clear error otherwise.
func parseFixed(s string, n int, field string) ([]byte, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(strings.TrimSpace(s))
	if strings.HasPrefix(strings.ToLower(clean), "0x") {
		clean = clean[2:]
	}
	if clean == "" {
		return nil, fmt.Errorf("hashcat: %s is required (%d bytes hex)", field, n)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hashcat: %s is not valid hex: %w", field, err)
	}
	if len(b) != n {
		return nil, fmt.Errorf("hashcat: %s must be exactly %d bytes; got %d", field, n, len(b))
	}
	return b, nil
}
