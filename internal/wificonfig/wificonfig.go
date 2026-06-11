// Package wificonfig extracts stored WiFi network credentials from the five
// config formats found on compromised hosts: wpa_supplicant.conf (Linux /
// embedded / routers), NetworkManager `.nmconnection` (Linux desktop), the
// Windows `netsh wlan export profile` XML, the Android WifiConfigStore.xml
// (`/data/misc/wifi/`), and the OpenWrt `/etc/config/wireless` UCI file.
//
// This is the host-side complement to the project's RF-side WiFi tooling: once
// an operator has a foothold on a host, its saved WiFi configs hand over the
// pre-shared keys directly — no handshake capture or cracking required. The
// recovered PSK / EAP identity is the explicit deliverable, so (unlike the
// credential-container decoders that only flag a secret's presence) the
// passphrase IS surfaced — it is the loot the operator came for.
//
// No confidently-wrong output: the format is detected by its unambiguous
// syntax; a Windows key stored DPAPI-`protected` is reported as encrypted (the
// plaintext is NOT invented); a network with no key is reported as open /
// key-less; and input matching none of the three formats is rejected.
//
// Wrap-vs-native: native — hand scanners for the wpa_supplicant block syntax and
// the NetworkManager INI, plus stdlib encoding/xml for the Windows profile; no
// new go.mod dependency. Formats per wpa_supplicant.conf(5), the
// NetworkManager nm-settings(5) keyfile, and the Microsoft WLAN_profile schema.
package wificonfig

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// Network is one extracted WiFi network.
type Network struct {
	SSID string `json:"ssid"`
	// KeyMgmt is the normalized security: "WPA-PSK", "WPA-EAP", "WEP", "OPEN".
	KeyMgmt string `json:"key_mgmt"`
	// PSK is the recovered pre-shared key — a passphrase, or a 64-hex PMK, or
	// (Windows) an encrypted blob flagged via PSKEncrypted.
	PSK     string `json:"psk,omitempty"`
	PSKType string `json:"psk_type,omitempty"` // "passphrase" / "hex" / "wep-key"
	// PSKEncrypted is true when the key is stored encrypted (Windows DPAPI
	// protected) and could not be recovered in plaintext.
	PSKEncrypted bool `json:"psk_encrypted,omitempty"`
	// EAP fields (enterprise networks).
	EAPMethod   string `json:"eap_method,omitempty"`
	Identity    string `json:"identity,omitempty"`
	EAPPassword string `json:"eap_password,omitempty"`
	Hidden      bool   `json:"hidden,omitempty"`
}

// HasCredential reports whether a usable secret was recovered for this network.
func (n Network) HasCredential() bool {
	return (n.PSK != "" && !n.PSKEncrypted) || n.EAPPassword != ""
}

// Result is the decoded config.
type Result struct {
	// Format is "wpa_supplicant", "NetworkManager", or "windows-wlan-xml".
	Format          string    `json:"format"`
	Networks        []Network `json:"networks"`
	CredentialCount int       `json:"credential_count"`
	Note            string    `json:"note"`
}

// Decode detects the WiFi config format and extracts its networks.
func Decode(input string) (*Result, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return nil, fmt.Errorf("wificonfig: empty input")
	}

	var res *Result
	var err error
	switch {
	case strings.Contains(s, "<WLANProfile"):
		res, err = parseWindowsXML(s)
	case strings.Contains(s, "WifiConfigStore") || strings.Contains(s, "<WifiConfiguration"):
		res, err = parseAndroidXML(s)
	case strings.Contains(s, "network={"):
		res = parseWpaSupplicant(s)
	case strings.Contains(s, "config wifi-iface"):
		res = parseOpenWrt(s)
	case strings.Contains(s, "[wifi]") || (strings.Contains(s, "[connection]") && strings.Contains(s, "type=wifi")):
		res = parseNetworkManager(s)
	default:
		return nil, fmt.Errorf("wificonfig: unrecognised WiFi config (not wpa_supplicant / NetworkManager / OpenWrt / Android / Windows WLAN XML)")
	}
	if err != nil {
		return nil, err
	}

	for _, n := range res.Networks {
		if n.HasCredential() {
			res.CredentialCount++
		}
	}
	res.Note = "Recovered WiFi network credentials from a host config — the PSK / EAP identity is the " +
		"extraction goal and is surfaced verbatim. Offline parse of operator-supplied loot; nothing is " +
		"transmitted or connected."
	return res, nil
}

// parseWpaSupplicant extracts network={…} blocks from a wpa_supplicant.conf.
func parseWpaSupplicant(s string) *Result {
	res := &Result{Format: "wpa_supplicant"}
	for _, block := range splitBlocks(s, "network={", "}") {
		n := Network{KeyMgmt: "OPEN"}
		for _, line := range strings.Split(block, "\n") {
			key, val, ok := splitKV(line, "=")
			if !ok {
				continue
			}
			switch key {
			case "ssid":
				n.SSID = unquote(val)
			case "scan_ssid":
				n.Hidden = strings.TrimSpace(val) == "1"
			case "key_mgmt":
				n.KeyMgmt = normalizeKeyMgmt(val)
			case "psk":
				n.PSK, n.PSKType = parsePSK(val)
			case "wep_key0":
				n.PSK, n.PSKType, n.KeyMgmt = unquote(val), "wep-key", "WEP"
			case "eap":
				n.EAPMethod = strings.TrimSpace(val)
			case "identity":
				n.Identity = unquote(val)
			case "password":
				n.EAPPassword = unquote(val)
			}
		}
		if n.KeyMgmt == "OPEN" && n.PSK != "" {
			n.KeyMgmt = "WPA-PSK"
		}
		res.Networks = append(res.Networks, n)
	}
	return res
}

// parseNetworkManager extracts the single network from a `.nmconnection` keyfile.
func parseNetworkManager(s string) *Result {
	res := &Result{Format: "NetworkManager"}
	sections := parseINI(s)
	n := Network{KeyMgmt: "OPEN"}
	if w, ok := sections["wifi"]; ok {
		n.SSID = w["ssid"]
		if w["hidden"] == "true" {
			n.Hidden = true
		}
	}
	if sec, ok := sections["wifi-security"]; ok {
		n.KeyMgmt = normalizeKeyMgmt(sec["key-mgmt"])
		if sec["psk"] != "" {
			n.PSK, n.PSKType = parsePSK(sec["psk"])
		}
		if sec["wep-key0"] != "" {
			n.PSK, n.PSKType, n.KeyMgmt = sec["wep-key0"], "wep-key", "WEP"
		}
	}
	if sec, ok := sections["802-1x"]; ok {
		n.KeyMgmt = "WPA-EAP"
		n.EAPMethod = sec["eap"]
		n.Identity = sec["identity"]
		n.EAPPassword = sec["password"]
	}
	res.Networks = append(res.Networks, n)
	return res
}

// wlanProfile mirrors the Windows WLAN_profile XML schema (the fields we need).
type wlanProfile struct {
	XMLName    xml.Name `xml:"WLANProfile"`
	SSIDConfig struct {
		SSID struct {
			Name string `xml:"name"`
		} `xml:"SSID"`
	} `xml:"SSIDConfig"`
	MSM struct {
		Security struct {
			AuthEncryption struct {
				Authentication string `xml:"authentication"`
			} `xml:"authEncryption"`
			SharedKey struct {
				KeyType     string `xml:"keyType"`
				Protected   string `xml:"protected"`
				KeyMaterial string `xml:"keyMaterial"`
			} `xml:"sharedKey"`
		} `xml:"security"`
	} `xml:"MSM"`
}

// parseWindowsXML extracts the profile from a `netsh wlan export profile` XML.
func parseWindowsXML(s string) (*Result, error) {
	var p wlanProfile
	if err := xml.Unmarshal([]byte(s), &p); err != nil {
		return nil, fmt.Errorf("wificonfig: invalid WLAN profile XML: %w", err)
	}
	n := Network{
		SSID:    p.SSIDConfig.SSID.Name,
		KeyMgmt: normalizeKeyMgmt(p.MSM.Security.AuthEncryption.Authentication),
	}
	sk := p.MSM.Security.SharedKey
	if sk.KeyMaterial != "" {
		if strings.EqualFold(strings.TrimSpace(sk.Protected), "true") {
			n.PSK, n.PSKEncrypted = sk.KeyMaterial, true
		} else {
			n.PSK = sk.KeyMaterial
			if strings.EqualFold(sk.KeyType, "networkKey") {
				n.PSKType = "hex"
			} else {
				n.PSKType = "passphrase"
			}
		}
	}
	return &Result{Format: "windows-wlan-xml", Networks: []Network{n}}, nil
}

// androidStore mirrors the Android WifiConfigStore.xml schema (the subset we
// need). The root element differs by Android version (WifiConfigStore vs
// WifiConfigStoreData), so it is matched loosely via XMLName.
type androidStore struct {
	Networks []struct {
		Config struct {
			Strings []struct {
				Name  string `xml:"name,attr"`
				Value string `xml:",chardata"`
			} `xml:"string"`
		} `xml:"WifiConfiguration"`
	} `xml:"NetworkList>Network"`
}

// parseAndroidXML extracts networks from an Android WifiConfigStore.xml. SSID and
// PreSharedKey are stored as XML-escaped, quote-wrapped <string name="…"> values.
func parseAndroidXML(s string) (*Result, error) {
	var store androidStore
	if err := xml.Unmarshal([]byte(s), &store); err != nil {
		return nil, fmt.Errorf("wificonfig: invalid Android WifiConfigStore XML: %w", err)
	}
	res := &Result{Format: "android-wificonfigstore"}
	for _, net := range store.Networks {
		n := Network{KeyMgmt: "OPEN"}
		for _, f := range net.Config.Strings {
			v := unquote(strings.TrimSpace(f.Value))
			switch f.Name {
			case "SSID":
				n.SSID = v
			case "PreSharedKey":
				n.PSK, n.PSKType = parsePSK(strings.TrimSpace(f.Value))
			case "KeyMgmt":
				// rarely a string; tolerate it
			}
		}
		if n.PSK != "" {
			n.KeyMgmt = "WPA-PSK"
		}
		res.Networks = append(res.Networks, n)
	}
	return res, nil
}

// parseOpenWrt extracts `config wifi-iface` blocks from an OpenWrt
// /etc/config/wireless (UCI). `config wifi-device` blocks (radio config, no
// SSID) are skipped.
func parseOpenWrt(s string) *Result {
	res := &Result{Format: "openwrt-uci"}
	lines := strings.Split(s, "\n")
	var cur *Network
	flush := func() {
		if cur != nil {
			if cur.KeyMgmt == "" {
				cur.KeyMgmt = "OPEN"
			}
			res.Networks = append(res.Networks, *cur)
			cur = nil
		}
	}
	for _, line := range lines {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "config wifi-iface"):
			flush()
			cur = &Network{}
		case strings.HasPrefix(t, "config "):
			flush() // a non-iface section ends the current iface
		case cur != nil && strings.HasPrefix(t, "option "):
			key, val := uciOption(t)
			switch key {
			case "ssid":
				cur.SSID = val
			case "key":
				cur.PSK, cur.PSKType = parsePSK(val)
			case "encryption":
				cur.KeyMgmt = openwrtEncryption(val)
			case "eap_type":
				cur.EAPMethod = val
			case "identity":
				cur.Identity = val
			case "auth_secret", "password":
				cur.EAPPassword = val
			case "hidden":
				cur.Hidden = val == "1"
			}
		}
	}
	flush()
	// A PSK present but encryption unset/none ⇒ still PSK-secured.
	for i := range res.Networks {
		if res.Networks[i].PSK != "" && res.Networks[i].KeyMgmt == "OPEN" {
			res.Networks[i].KeyMgmt = "WPA-PSK"
		}
	}
	return res
}

// openwrtEncryption maps a UCI `option encryption` value to a normal label.
func openwrtEncryption(v string) string {
	t := strings.ToLower(strings.TrimSpace(v))
	switch {
	case t == "" || t == "none":
		return "OPEN"
	case strings.HasPrefix(t, "wpa"), strings.HasPrefix(t, "wpa2-eap"), strings.Contains(t, "eap"):
		if strings.Contains(t, "eap") {
			return "WPA-EAP"
		}
		return "WPA-PSK"
	case strings.HasPrefix(t, "psk"), strings.HasPrefix(t, "sae"):
		return "WPA-PSK"
	case strings.HasPrefix(t, "wep"):
		return "WEP"
	default:
		return strings.TrimSpace(v)
	}
}

// uciOption parses a UCI `option <key> '<value>'` (or "value") line.
func uciOption(line string) (key, val string) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "option"))
	sp := strings.IndexByte(rest, ' ')
	if sp < 0 {
		return rest, ""
	}
	key = strings.TrimSpace(rest[:sp])
	val = strings.TrimSpace(rest[sp+1:])
	val = strings.Trim(val, "'\"")
	return key, val
}

// --- helpers ---

// normalizeKeyMgmt maps a producer-specific security token to a normal label.
func normalizeKeyMgmt(v string) string {
	switch t := strings.ToUpper(strings.TrimSpace(v)); {
	case t == "" || t == "NONE" || strings.HasPrefix(t, "OPEN"):
		return "OPEN"
	case strings.Contains(t, "EAP") || strings.Contains(t, "802.1X") || strings.Contains(t, "8021X"):
		return "WPA-EAP"
	case strings.Contains(t, "PSK") || strings.Contains(t, "WPA"):
		return "WPA-PSK"
	case strings.Contains(t, "WEP"):
		return "WEP"
	default:
		return strings.TrimSpace(v)
	}
}

// parsePSK classifies a wpa_supplicant/NM psk value: a quoted passphrase, or a
// bare 64-hex PMK.
func parsePSK(v string) (psk, typ string) {
	t := strings.TrimSpace(v)
	if strings.HasPrefix(t, "\"") {
		return unquote(t), "passphrase"
	}
	if len(t) == 64 && isHex(t) {
		return t, "hex"
	}
	return t, "passphrase"
}

// splitBlocks returns the bodies between each open/close marker pair.
func splitBlocks(s, open, close string) []string {
	var out []string
	for rest := s; ; {
		i := strings.Index(rest, open)
		if i < 0 {
			return out
		}
		rest = rest[i+len(open):]
		j := strings.Index(rest, close)
		if j < 0 {
			out = append(out, rest)
			return out
		}
		out = append(out, rest[:j])
		rest = rest[j+len(close):]
	}
}

// splitKV splits "key<sep>value" with leading whitespace/comments stripped.
func splitKV(line, sep string) (key, val string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return "", "", false
	}
	i := strings.Index(line, sep)
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// parseINI parses a minimal INI into section -> key -> value.
func parseINI(s string) map[string]map[string]string {
	out := map[string]map[string]string{}
	cur := ""
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			cur = t[1 : len(t)-1]
			out[cur] = map[string]string{}
			continue
		}
		if cur == "" {
			continue
		}
		if k, v, ok := splitKV(t, "="); ok {
			out[cur][k] = v
		}
	}
	return out
}

// unquote strips one layer of surrounding double quotes.
func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"") {
		return v[1 : len(v)-1]
	}
	return v
}

// isHex reports whether s is all hex digits.
func isHex(s string) bool {
	for _, c := range s {
		if !isHexDigit(c) {
			return false
		}
	}
	return s != ""
}

// isHexDigit reports whether c is an ASCII hex digit.
func isHexDigit(c rune) bool {
	switch {
	case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		return true
	default:
		return false
	}
}
