// ansible_vault_decode.go — host-side Ansible Vault crack-triage Spec,
// delegating to internal/ansiblevault.
//
// Wrap-vs-native: native — a header parse over the documented Ansible Vault
// format; no new go.mod dep. Ansible Vault is ubiquitous in DevOps / IaC repos,
// so a vault file is common loot on a CI/ops host; this answers "can I crack it,
// which hashcat mode?" offline. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ansiblevault"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ansibleVaultDecodeSpec)
}

var ansibleVaultDecodeSpec = Spec{
	Name: "ansible_vault_decode",
	Description: "Triage an **Ansible Vault** file for cracking — a crack-triage sibling of `zip_crack_triage` / " +
		"`kdbx_decode` for the DevOps / infrastructure-as-code domain. Ansible Vault (`$ANSIBLE_VAULT;…`) is " +
		"the standard at-rest encryption for secrets in Ansible playbooks and roles, so a vault file is a " +
		"**common loot artifact** on a CI/ops host or in a pulled repo — and its password protects **every** " +
		"value inside. This parses the header **offline** and reports the **version** (1.1 / 1.2), the " +
		"**cipher** (AES256), the optional **vault-id** (the key label, useful for targeting), the envelope " +
		"size, and the matching **hashcat mode (16900)**.\n\n" +
		"**No confidently-wrong output**: the file is recognised only by its `$ANSIBLE_VAULT;` magic header; " +
		"it reports the **envelope parameters only** — it does **not** crack, decrypt, or emit the " +
		"`ansible2john` hash (that needs the hex-decoded salt / HMAC / ciphertext); and a non-vault input is " +
		"rejected. The KDF is **PBKDF2-HMAC-SHA256 (10000 iterations)** — a slow per-guess target. No network, " +
		"no device, transmits nothing — Low risk. Pairs with `hash_identify` and the hashcat tooling.\n\n" +
		"Source: docs/catalog/gap-analysis.md (crack triage / infra forensics). Wrap-vs-native: native — a " +
		"header parse over the documented format, no new go.mod dep; anchored to real ansible-vault output.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"vault":{"type":"string","description":"The Ansible Vault file contents ($ANSIBLE_VAULT;…)."}
		},
		"required":["vault"]
	}`),
	Required:  []string{"vault"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ansibleVaultDecodeHandler,
}

func ansibleVaultDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	vault := strings.TrimSpace(str(p, "vault"))
	if vault == "" {
		return "", fmt.Errorf("ansible_vault_decode: 'vault' is required")
	}
	res, err := ansiblevault.Decode(vault)
	if err != nil {
		return "", fmt.Errorf("ansible_vault_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
