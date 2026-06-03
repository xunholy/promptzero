// wifi_wsc_decode.go — host-side Wi-Fi Simple Config (WSC / WPS) credential
// dissector Spec, delegating to internal/wsc.
//
// Wrap-vs-native: native — the WSC credential is a flat sequence of
// big-endian (type:2, length:2, value) TLVs with a nested Credential
// attribute; fixed binary parsing, no dependency. The attribute IDs and
// auth/encryption flag values are taken verbatim from the Wi-Fi Simple
// Config spec as published in hostap's src/wps/wps_defs.h. Offline read of
// operator-supplied bytes — no hardware, transmits nothing.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/wsc"
)

func init() { //nolint:gochecknoinits
	Register(wifiWSCDecodeSpec)
}

var wifiWSCDecodeSpec = Spec{
	Name: "wifi_wsc_decode",
	Description: "Decode a Wi-Fi Simple Config (WSC / WPS) credential blob — the `application/vnd.wfa.wsc` " +
		"payload. This is the credential behind a **tap-to-connect Wi-Fi NFC tag** (an NDEF MIME record) and " +
		"the Credential carried in WPS Registrar protocol messages (M7/M8). Decoding it recovers the " +
		"provisioned network's **SSID**, authentication type, encryption type, MAC, and — the operative field " +
		"for an authorized engagement — the **network key (the PSK)**.\n\n" +
		"Field: **hex** (the WSC attribute blob, hex — ':' / '-' / whitespace ignored). Walks the WSC TLV " +
		"grammar (big-endian type:2 / length:2 / value); the Credential attribute (0x100E) is recursed into " +
		"and its SSID (0x1045), Authentication Type (0x1003, decoded into Open / WPA-PSK / WPA2-PSK / " +
		"WPA-Enterprise / WPA2-Enterprise flags), Encryption Type (0x100F → None / WEP / TKIP / AES), " +
		"Network Key (0x1027), MAC Address (0x1020), and Network Index (0x1026) are surfaced. " +
		"Top-level non-credential attributes are surfaced raw; an Encrypted Settings attribute (0x1018, the " +
		"AES-protected M7/M8 form) is reported present-but-encrypted, not guessed at; unknown auth/encr " +
		"flag bits are surfaced rather than dropped — no confidently-wrong output.\n\n" +
		"Pure offline decode of operator-supplied bytes — no hardware, transmits nothing, so it is Low risk. " +
		"The same blob is decoded automatically when it appears as the MIME payload of an `ndef_decode` " +
		"record. Wrap-vs-native: native — fixed WSC TLV parsing (attribute IDs per hostap wps_defs.h).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded WSC (application/vnd.wfa.wsc) credential blob. ':' / '-' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wifiWSCDecodeHandler,
}

func wifiWSCDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("wifi_wsc_decode: 'hex' is required")
	}
	res, err := wsc.DecodeHex(raw)
	if err != nil {
		return "", fmt.Errorf("wifi_wsc_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
