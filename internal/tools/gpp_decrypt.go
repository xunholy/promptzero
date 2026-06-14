// gpp_decrypt.go — host-side Group Policy Preferences cpassword decryptor Spec,
// delegating to internal/gpp.
//
// Wrap-vs-native: native — Go stdlib crypto/aes + crypto/cipher + encoding/xml,
// no new go.mod dep. Decrypts SYSVOL GPP cpassword values with the Microsoft-
// published AES key. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/gpp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(gppDecryptSpec)
}

var gppDecryptSpec = Spec{
	Name: "gpp_decrypt",
	Description: "Decrypt **Group Policy Preferences (GPP) `cpassword`** values from an Active Directory **SYSVOL** " +
		"share. GPP let a domain admin push local accounts, scheduled tasks, services, mapped drives, and data " +
		"sources to every domain machine; the password lives in an XML file (**Groups.xml**, Services.xml, " +
		"ScheduledTasks.xml, DataSources.xml, Drives.xml, Printers.xml) as an AES-256-encrypted `cpassword` " +
		"attribute. The catch: **Microsoft published the AES key** (MS-GPPREF §2.2.1.1), so any user who can read " +
		"SYSVOL can decrypt every cpassword **offline** — one of the highest-impact AD findings (MS14-025 stopped " +
		"new ones but legacy SYSVOL files persist for years). Paste either a **raw cpassword** string or a whole " +
		"**GPP XML** snippet: it extracts every cpassword (with the co-located account name — `userName` / " +
		"`accountName` / `runAs` / `newName`) and decrypts it to the **cleartext password**.\n\n" +
		"**No confidently-wrong output**: the AES key, the all-zero IV, the CBC mode, and the UTF-16LE plaintext " +
		"are all fixed by the spec — nothing is guessed; an empty cpassword (a cleared field) is reported as **no " +
		"password set**, and a wrong-length / bad-padding ciphertext is an error on that entry, never a garbled " +
		"guess. No network, no device, transmits nothing, and the only key used is the public one — Low risk. " +
		"Pairs with the AD loot tooling (`kerberos_decode`, `ldap_decode`, the NetNTLM / hash identifiers).\n\n" +
		"Provide the cpassword string or GPP XML as text. Source: docs/catalog/gap-analysis.md (Active Directory " +
		"credential triage). Wrap-vs-native: native — `crypto/aes` + `encoding/xml`, no new go.mod dep; anchored " +
		"to the well-known public cpassword vectors (openssl-cross-checked).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"gpp":{"type":"string","description":"A GPP cpassword value, or a GPP XML snippet (Groups.xml / Services.xml / etc.)."}
		},
		"required":["gpp"]
	}`),
	Required:  []string{"gpp"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   gppDecryptHandler,
}

func gppDecryptHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := str(p, "gpp")
	if strings.TrimSpace(in) == "" {
		return "", fmt.Errorf("gpp_decrypt: 'gpp' is required")
	}
	res, err := gpp.Decode([]byte(in))
	if err != nil {
		return "", fmt.Errorf("gpp_decrypt: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
