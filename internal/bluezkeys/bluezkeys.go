// Package bluezkeys extracts Bluetooth pairing keys from a Linux BlueZ device
// `info` file (/var/lib/bluetooth/<adapter>/<device>/info).
//
// It is the BLE/Bluetooth analogue of the WiFi config extractor: a foothold on a
// Linux host yields, for every device the host has paired with, the long-term
// cryptographic material — the BR/EDR LinkKey, and for LE the LongTermKey (LTK),
// IdentityResolvingKey (IRK), and signing keys (CSRK). With these an operator
// can decrypt sniffed traffic for the bonded link, resolve a device's
// resolvable-private address (IRK), or impersonate the bonded device — directly
// useful alongside a BLE sniffer or the Flipper's BLE radio.
//
// The keys are the explicit extraction goal, so they are surfaced verbatim (the
// device MAC is the directory name, not in the file, so it is reported as
// supplied-by-path). No confidently-wrong output: the file is recognised only by
// a BlueZ-specific key section, an unpaired/cleared file is reported key-less,
// and input that is not a BlueZ info file is rejected.
//
// Wrap-vs-native: native — a minimal GKeyFile (INI) scanner over the documented
// BlueZ storage format (bluez doc/settings-storage.txt; src/device.c
// load_info/store_info); stdlib only, no new go.mod dependency.
package bluezkeys

import (
	"fmt"
	"strings"
)

// Key is one recovered pairing key.
type Key struct {
	// Kind: LinkKey, LongTermKey, PeripheralLongTermKey, IdentityResolvingKey,
	// LocalSignatureKey, RemoteSignatureKey.
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Detail string `json:"detail,omitempty"`
}

// Result is the decoded BlueZ info file.
type Result struct {
	Name         string `json:"name,omitempty"`
	AddressType  string `json:"address_type,omitempty"`
	Technologies string `json:"technologies,omitempty"`
	Class        string `json:"class,omitempty"`
	// Transport is derived: "BR/EDR", "LE", or "dual".
	Transport string `json:"transport,omitempty"`
	Keys      []Key  `json:"keys"`
	Note      string `json:"note"`
}

// keySections maps a BlueZ key group to its output Kind. Presence of any of
// these is what identifies the file as a BlueZ info file.
var keySections = map[string]string{
	"LinkKey":               "LinkKey",
	"LongTermKey":           "LongTermKey",
	"SlaveLongTermKey":      "PeripheralLongTermKey", // pre-5.x name
	"PeripheralLongTermKey": "PeripheralLongTermKey",
	"IdentityResolvingKey":  "IdentityResolvingKey",
	"LocalSignatureKey":     "LocalSignatureKey",
	"RemoteSignatureKey":    "RemoteSignatureKey",
}

// Decode parses a BlueZ device info file.
func Decode(input string) (*Result, error) {
	if strings.TrimSpace(input) == "" {
		return nil, fmt.Errorf("bluezkeys: empty input")
	}
	ini := parseINI(input)

	hasKeySection := false
	for grp := range keySections {
		if _, ok := ini[grp]; ok {
			hasKeySection = true
			break
		}
	}
	if !hasKeySection {
		return nil, fmt.Errorf("bluezkeys: not a BlueZ device info file (no LinkKey / LongTermKey / IdentityResolvingKey section)")
	}

	res := &Result{Keys: []Key{}}
	if g, ok := ini["General"]; ok {
		res.Name = g["Name"]
		res.AddressType = g["AddressType"]
		res.Technologies = g["SupportedTechnologies"]
		res.Class = g["Class"]
	}

	for _, grp := range []string{
		"LinkKey", "LongTermKey", "PeripheralLongTermKey", "SlaveLongTermKey",
		"IdentityResolvingKey", "LocalSignatureKey", "RemoteSignatureKey",
	} {
		sec, ok := ini[grp]
		if !ok || sec["Key"] == "" {
			continue
		}
		res.Keys = append(res.Keys, Key{
			Kind:   keySections[grp],
			Value:  sec["Key"],
			Detail: keyDetail(grp, sec),
		})
	}

	res.Transport = deriveTransport(res)
	if len(res.Keys) == 0 {
		res.Note = "BlueZ info file with no stored pairing keys (device unpaired or keys cleared). "
	}
	res.Note += "Recovered Bluetooth pairing material from a host BlueZ store — the keys are the extraction " +
		"goal and are surfaced verbatim. The device MAC is the info-file's directory name (supplied by path, " +
		"not in the file). Offline parse of operator-supplied loot; nothing is transmitted or paired."
	return res, nil
}

// keyDetail summarises the non-key fields of a key section.
func keyDetail(grp string, sec map[string]string) string {
	var parts []string
	switch grp {
	case "LinkKey":
		addKV(&parts, "type", sec["Type"])
	case "LongTermKey", "PeripheralLongTermKey", "SlaveLongTermKey":
		addKV(&parts, "enc_size", sec["EncSize"])
		addKV(&parts, "ediv", sec["EDiv"])
		addKV(&parts, "rand", sec["Rand"])
		addKV(&parts, "authenticated", sec["Authenticated"])
	case "LocalSignatureKey", "RemoteSignatureKey":
		addKV(&parts, "counter", sec["Counter"])
		addKV(&parts, "authenticated", sec["Authenticated"])
	}
	return strings.Join(parts, " ")
}

func addKV(parts *[]string, k, v string) {
	if v != "" {
		*parts = append(*parts, k+"="+v)
	}
}

// deriveTransport classifies the bond as BR/EDR, LE, or dual from the keys and
// the declared technologies.
func deriveTransport(res *Result) string {
	bredr, le := false, false
	for _, k := range res.Keys {
		switch k.Kind {
		case "LinkKey":
			bredr = true
		case "LongTermKey", "PeripheralLongTermKey", "IdentityResolvingKey",
			"LocalSignatureKey", "RemoteSignatureKey":
			le = true
		}
	}
	// Fall back to the declared technologies when no key disambiguates.
	t := res.Technologies
	if strings.Contains(t, "BR/EDR") {
		bredr = true
	}
	if strings.Contains(t, "LE") {
		le = true
	}
	switch {
	case bredr && le:
		return "dual"
	case le:
		return "LE"
	case bredr:
		return "BR/EDR"
	default:
		return ""
	}
}

// parseINI parses a GKeyFile/INI into group -> key -> value.
func parseINI(s string) map[string]map[string]string {
	out := map[string]map[string]string{}
	cur := ""
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			cur = t[1 : len(t)-1]
			out[cur] = map[string]string{}
			continue
		}
		if cur == "" {
			continue
		}
		if i := strings.IndexByte(t, '='); i >= 0 {
			out[cur][strings.TrimSpace(t[:i])] = strings.TrimSpace(t[i+1:])
		}
	}
	return out
}
