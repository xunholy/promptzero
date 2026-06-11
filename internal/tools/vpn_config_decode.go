// vpn_config_decode.go — host-side VPN-credential extractor Spec, delegating to
// internal/vpnconfig.
//
// Wrap-vs-native: native — a minimal INI scanner for WireGuard + a
// directive/inline-block scanner for OpenVPN; no new go.mod dep. A VPN config
// off a foothold grants the host's own VPN access — a direct network pivot.
// Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/vpnconfig"
)

func init() { //nolint:gochecknoinits
	Register(vpnConfigDecodeSpec)
}

var vpnConfigDecodeSpec = Spec{
	Name: "vpn_config_decode",
	Description: "Extract **VPN credentials** from a host config — among the **highest-value loot artifacts**: " +
		"the WireGuard interface **PrivateKey**, or an OpenVPN client **key / inline username+password**, " +
		"grants the operator the host's own VPN access — a **direct pivot onto the internal network** it " +
		"tunnels to, with no further cracking. Recognises **WireGuard `.conf`** (wg-quick) and **OpenVPN " +
		"`.ovpn`**.\n\n" +
		"For **WireGuard** it reports the interface PrivateKey, address, DNS, and each **[Peer]** (public key, " +
		"preshared key, endpoint, allowed IPs). For **OpenVPN** it reports the **remote** server(s), protocol, " +
		"the **auth method** (certificate / user-pass / both), whether a client **private key is embedded** " +
		"(`<key>` PEM block), and any **inline username+password**. The credential is the **explicit " +
		"extraction goal**, so the key / password **is** surfaced verbatim. **No confidently-wrong output**: " +
		"the format is detected by its unambiguous syntax; a credential is surfaced when present and reported " +
		"absent otherwise (a `has_credential` flag); and input matching neither format is rejected. No " +
		"network, no device, transmits nothing — Low risk. Pairs with `wifi_config_decode` / " +
		"`bluez_pairing_decode` (the host-loot extraction set).\n\n" +
		"Source: docs/catalog/gap-analysis.md (network / credential forensics). Wrap-vs-native: native — INI + " +
		"directive scanners, no new go.mod dep; formats per wg-quick(8) and the OpenVPN 2.x manual.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"config":{"type":"string","description":"The VPN config file contents (WireGuard .conf or OpenVPN .ovpn)."}
		},
		"required":["config"]
	}`),
	Required:  []string{"config"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   vpnConfigDecodeHandler,
}

func vpnConfigDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	cfg := strings.TrimSpace(str(p, "config"))
	if cfg == "" {
		return "", fmt.Errorf("vpn_config_decode: 'config' is required")
	}
	res, err := vpnconfig.Decode(cfg)
	if err != nil {
		return "", fmt.Errorf("vpn_config_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
