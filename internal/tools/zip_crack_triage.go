// zip_crack_triage.go — host-side encrypted-ZIP crack-triage Spec, delegating to
// internal/ziptriage.
//
// Wrap-vs-native: native — encoding/binary over the documented ZIP central
// directory + WinZip AES extra field; no new go.mod dep. Answers the operator's
// first question about a password-protected archive — which encryption scheme,
// and which hashcat mode. Offline; no network or device. Reuses
// decodeBinaryInput (kdbx_decode.go) for the base64/hex file input.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/ziptriage"
)

func init() { //nolint:gochecknoinits
	Register(zipCrackTriageSpec)
}

var zipCrackTriageSpec = Spec{
	Name: "zip_crack_triage",
	Description: "Triage a **password-protected ZIP** for cracking. Encrypted archives are among the most " +
		"common high-value loot artifacts, and the operator's first question is *\"can I crack this, and with " +
		"which hashcat mode?\"* — which hinges entirely on **how** the ZIP is encrypted. Legacy **ZipCrypto** " +
		"(PKWARE traditional) is a weak, fast target (and has a known-plaintext break); **WinZip AES** " +
		"(128/192/256-bit) is a slow PBKDF2-HMAC-SHA1 target. This decodes the ZIP central directory " +
		"**offline** and reports the encryption scheme, the AES strength + AE version when applicable, the " +
		"number of encrypted entries, and the matching **hashcat mode** (`13600` for WinZip AES; the " +
		"`17200`/`17210`/`17220`/`17225` family for ZipCrypto by compression + file count).\n\n" +
		"Provide the `.zip` file **base64-encoded** (or hex). **No confidently-wrong output**: it reports the " +
		"archive's **encryption structure only** — it does **not** crack, decrypt, or emit the `zip2john` hash " +
		"(that needs the encrypted record bytes and is out of scope); an archive with **no encrypted entries** " +
		"is reported as such (nothing to crack — there is no password), and input that is not a ZIP is " +
		"rejected. No network, no device, transmits nothing — Low risk. Sibling of `kdbx_decode`; pairs with " +
		"`hash_identify` and the hashcat tooling.\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential forensics / crack triage). Wrap-vs-native: native — " +
		"encoding/binary over the ZIP APPNOTE central directory + the WinZip AES 0x9901 extra field, no new " +
		"go.mod dep; anchored to real ZipCrypto (`zip -P`) and AES (`7z`) archives.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"data":{"type":"string","description":"The .zip file contents, base64-encoded (or hex)."}
		},
		"required":["data"]
	}`),
	Required:  []string{"data"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   zipCrackTriageHandler,
}

func zipCrackTriageHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "data"))
	if in == "" {
		return "", fmt.Errorf("zip_crack_triage: 'data' is required")
	}
	raw, err := decodeBinaryInput(in)
	if err != nil {
		return "", fmt.Errorf("zip_crack_triage: %w", err)
	}
	res, err := ziptriage.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("zip_crack_triage: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
