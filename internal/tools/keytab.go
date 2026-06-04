// keytab.go — host-side MIT Kerberos keytab parser Spec, delegating to
// internal/keytab.
//
// Wrap-vs-native: native — the keytab is a documented big-endian length-prefixed
// binary format; the parse is a byte-cursor walk. The file-format complement to
// kerberos_decode (the wire protocol). Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/keytab"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(keytabDecodeSpec)
}

var keytabDecodeSpec = Spec{
	Name: "keytab_decode",
	Description: "Parse an MIT Kerberos keytab file (the binary `.keytab` format, version 0x0502) into its " +
		"entries — service / account principals, key-version numbers (KVNO), encryption types, and the raw " +
		"key bytes. A keytab recovered from a compromised host is **high-value Active Directory loot**: it " +
		"holds the long-term Kerberos keys of the principals it serves, used for offline ticket forging " +
		"(**silver tickets**), **pass-the-key / overpass-the-hash**, and — for the **RC4 (etype 23)** entries " +
		"— the account's **NT hash** directly (flagged). The file-format complement to kerberos_decode " +
		"(which dissects the Kerberos wire protocol).\n\n" +
		"Paste the keytab bytes as hex and get, per entry: the **principal** (components joined `/` + `@realm`), " +
		"realm + components, **name_type** (KRB5_NT_PRINCIPAL / SRV_HST / …), **kvno** (8-bit or the 32-bit " +
		"extended form), **enctype** id + name (aes256 / aes128 / arcfour-RC4 / des3 / …), timestamp, and the " +
		"**key** (hex). Deleted/hole entries (negative size) are counted and skipped.\n\n" +
		"Pure offline parser — length fields are bounds-checked, a truncated/malformed entry is rejected " +
		"(never a partial decode), and the legacy 0x0501 host-byte-order variant is reported rather than " +
		"mis-decoded. No network, no device, transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (AD-pentest loot decode — pairs with kerberos_decode + the " +
		"krb5 roasting-hash detection; a keytab's keys feed silver-ticket / pass-the-key workflows). Wrap-" +
		"vs-native: native — a documented big-endian length-prefixed format, encoding/binary only. Anchored " +
		"to a keytab confirmed by the authoritative MIT `ktutil`.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded MIT keytab file (.keytab, version 0x0502). ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   keytabDecodeHandler,
}

func keytabDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("keytab_decode: 'hex' is required")
	}
	res, err := keytab.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("keytab_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
