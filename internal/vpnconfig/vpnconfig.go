// Package vpnconfig extracts VPN credentials from the two config formats found
// on compromised hosts: WireGuard `.conf` (wg-quick) and OpenVPN `.ovpn`.
//
// A VPN config is among the highest-value loot artifacts: the WireGuard
// interface PrivateKey, or an OpenVPN client key / inline username+password,
// grants the operator the host's own VPN access — a direct pivot onto the
// internal network it tunnels to, with no further cracking. This extracts that
// material offline and surfaces it (the key IS the loot), along with the peers /
// remote servers it connects to.
//
// No confidently-wrong output: the format is detected by its unambiguous syntax;
// the credential is surfaced verbatim when present and reported absent when not;
// and input matching neither format is rejected.
//
// Wrap-vs-native: native — a minimal INI scanner for the WireGuard config and a
// directive/inline-block scanner for OpenVPN; stdlib only, no new go.mod
// dependency. Formats per wg-quick(8) and the OpenVPN 2.x reference manual.
package vpnconfig

import (
	"fmt"
	"strings"
)

// Peer is one WireGuard [Peer].
type Peer struct {
	PublicKey    string `json:"public_key,omitempty"`
	PresharedKey string `json:"preshared_key,omitempty"`
	Endpoint     string `json:"endpoint,omitempty"`
	AllowedIPs   string `json:"allowed_ips,omitempty"`
}

// Result is the decoded VPN config.
type Result struct {
	// Format is "wireguard" or "openvpn".
	Format string `json:"format"`

	// WireGuard.
	PrivateKey string `json:"private_key,omitempty"`
	Address    string `json:"address,omitempty"`
	DNS        string `json:"dns,omitempty"`
	ListenPort string `json:"listen_port,omitempty"`
	Peers      []Peer `json:"peers,omitempty"`

	// OpenVPN.
	Remotes            []string `json:"remotes,omitempty"`
	Proto              string   `json:"proto,omitempty"`
	AuthMethod         string   `json:"auth_method,omitempty"`
	EmbeddedPrivateKey bool     `json:"embedded_private_key,omitempty"`
	CACertPresent      bool     `json:"ca_cert_present,omitempty"`
	ClientCertPresent  bool     `json:"client_cert_present,omitempty"`
	Username           string   `json:"username,omitempty"`
	Password           string   `json:"password,omitempty"`

	// HasCredential is true when usable secret material was recovered.
	HasCredential bool   `json:"has_credential"`
	Note          string `json:"note"`
}

// Decode detects the VPN config format and extracts its credentials.
func Decode(input string) (*Result, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return nil, fmt.Errorf("vpnconfig: empty input")
	}
	switch {
	case strings.Contains(s, "[Interface]") || strings.Contains(s, "[Peer]"):
		return decodeWireGuard(s), nil
	case isOpenVPN(s):
		return decodeOpenVPN(s), nil
	default:
		return nil, fmt.Errorf("vpnconfig: unrecognised VPN config (not WireGuard or OpenVPN)")
	}
}

// isOpenVPN reports whether s looks like an OpenVPN config.
func isOpenVPN(s string) bool {
	return strings.Contains(s, "<ca>") || strings.Contains(s, "<key>") ||
		hasLineDirective(s, "remote ") || hasLineDirective(s, "client") ||
		hasLineDirective(s, "dev tun") || hasLineDirective(s, "dev tap")
}

// decodeWireGuard parses a wg-quick .conf.
func decodeWireGuard(s string) *Result {
	res := &Result{Format: "wireguard"}
	var cur *Peer
	flushPeer := func() {
		if cur != nil {
			res.Peers = append(res.Peers, *cur)
			cur = nil
		}
	}
	section := ""
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			flushPeer()
			section = strings.ToLower(t[1 : len(t)-1])
			if section == "peer" {
				cur = &Peer{}
			}
			continue
		}
		key, val, ok := splitKV(t)
		if !ok {
			continue
		}
		switch section {
		case "interface":
			switch strings.ToLower(key) {
			case "privatekey":
				res.PrivateKey = val
			case "address":
				res.Address = val
			case "dns":
				res.DNS = val
			case "listenport":
				res.ListenPort = val
			}
		case "peer":
			if cur == nil {
				cur = &Peer{}
			}
			switch strings.ToLower(key) {
			case "publickey":
				cur.PublicKey = val
			case "presharedkey":
				cur.PresharedKey = val
			case "endpoint":
				cur.Endpoint = val
			case "allowedips":
				cur.AllowedIPs = val
			}
		}
	}
	flushPeer()
	if res.PrivateKey != "" {
		res.HasCredential = true
	}
	res.Note = "Recovered WireGuard config — the interface PrivateKey grants the host's VPN access (a direct " +
		"network pivot) and is surfaced verbatim. Offline parse of operator-supplied loot; nothing connects."
	return res
}

// decodeOpenVPN parses an .ovpn config: remote servers, protocol, auth method,
// embedded key/cert presence, and any inline username/password.
func decodeOpenVPN(s string) *Result {
	res := &Result{Format: "openvpn"}
	lines := strings.Split(s, "\n")
	authUserPass := false
	for i := 0; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		switch {
		case strings.HasPrefix(t, "remote "):
			res.Remotes = append(res.Remotes, strings.TrimSpace(strings.TrimPrefix(t, "remote ")))
		case strings.HasPrefix(t, "proto "):
			res.Proto = strings.TrimSpace(strings.TrimPrefix(t, "proto "))
		case t == "<ca>":
			res.CACertPresent = true
		case t == "<cert>":
			res.ClientCertPresent = true
		case t == "<key>":
			// An embedded <key> block holding a PEM private key.
			if blockContains(lines, i, "</key>", "PRIVATE KEY") {
				res.EmbeddedPrivateKey = true
			}
		case strings.HasPrefix(t, "auth-user-pass"):
			authUserPass = true
		case t == "<auth-user-pass>":
			// Inline credentials: first two non-tag lines are user / pass.
			u, pw := inlineUserPass(lines, i)
			res.Username, res.Password = u, pw
			authUserPass = true
		}
	}
	res.AuthMethod = openvpnAuthMethod(res, authUserPass)
	res.HasCredential = res.EmbeddedPrivateKey || res.Password != ""
	res.Note = "Recovered OpenVPN config — an embedded client key or inline credentials grant the host's VPN " +
		"access (a network pivot). Offline parse of operator-supplied loot; the remote(s) below are the " +
		"server endpoints."
	return res
}

// openvpnAuthMethod classifies the auth based on what is present.
func openvpnAuthMethod(res *Result, userPass bool) string {
	cert := res.EmbeddedPrivateKey || res.ClientCertPresent
	switch {
	case cert && userPass:
		return "certificate + user-pass"
	case cert:
		return "certificate"
	case userPass:
		return "user-pass"
	default:
		return "unknown"
	}
}

// blockContains reports whether the lines from start until the closing tag
// contain the marker substring.
func blockContains(lines []string, start int, closeTag, marker string) bool {
	for i := start + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == closeTag {
			return false
		}
		if strings.Contains(lines[i], marker) {
			return true
		}
	}
	return false
}

// inlineUserPass returns the first two non-tag lines after an <auth-user-pass> tag.
func inlineUserPass(lines []string, start int) (user, pass string) {
	var vals []string
	for i := start + 1; i < len(lines) && len(vals) < 2; i++ {
		t := strings.TrimSpace(lines[i])
		if t == "</auth-user-pass>" {
			break
		}
		if t == "" {
			continue
		}
		vals = append(vals, t)
	}
	if len(vals) >= 1 {
		user = vals[0]
	}
	if len(vals) >= 2 {
		pass = vals[1]
	}
	return user, pass
}

// hasLineDirective reports whether any line starts with the directive.
func hasLineDirective(s, directive string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), directive) {
			return true
		}
	}
	return false
}

// splitKV splits "Key = Value" / "Key=Value", trimming whitespace.
func splitKV(line string) (key, val string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}
