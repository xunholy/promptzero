// pdf_crack_triage.go — host-side encrypted-PDF crack-triage Spec, delegating to
// internal/pdftriage.
//
// Wrap-vs-native: native — a byte scan over the documented PDF Standard
// encryption dictionary; no new go.mod dep. Answers the operator's first
// question about a password-protected PDF — which cipher, and which hashcat
// mode. Offline; no network or device. Reuses decodeBinaryInput (kdbx_decode.go)
// for the base64/hex file input.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pdftriage"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pdfCrackTriageSpec)
}

var pdfCrackTriageSpec = Spec{
	Name: "pdf_crack_triage",
	Description: "Triage a **password-protected PDF** for cracking — the crack-triage sibling of `kdbx_decode` " +
		"and `zip_crack_triage`. Encrypted PDFs (financial, legal, scanned documents) are among the most " +
		"common high-value loot artifacts, and the operator's first question is *\"can I crack this, and with " +
		"which hashcat mode?\"*. The answer is fully determined by the PDF **Standard security handler**'s " +
		"algorithm (`/V`), revision (`/R`), key length, and — for `/V 4` — the crypt-filter method (`/CFM`): " +
		"RC4-40 (R2) → hashcat `10400`, RC4-128 (R3, or R4 with `/V2`) → `10500`, AES-128 (R4 with `/AESV2`) → " +
		"`10600`, and AES-256 (R5/R6, `/AESV3`) → `10700`. This extracts those parameters **offline**.\n\n" +
		"The PDF spec (ISO 32000-1 §7.6.1) requires the `/Encrypt` dictionary to be a **direct, uncompressed " +
		"object**, so reading the Standard handler dictionary from the raw bytes is reliable. Provide the " +
		"`.pdf` file **base64-encoded** (or hex). **No confidently-wrong output**: it reports the encryption " +
		"**parameters only** — it does **not** crack, decrypt, or emit the `pdf2john` hash; a PDF with **no " +
		"`/Encrypt`** is reported as not password-protected (nothing to crack); a non-Standard (public-key) " +
		"handler is **named but not given a password hashcat mode**; and non-PDF input is rejected. No " +
		"network, no device, transmits nothing — Low risk. Pairs with `hash_identify` and the hashcat " +
		"tooling.\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential forensics / crack triage). Wrap-vs-native: native — " +
		"a byte scan over the PDF encryption dictionary, no new go.mod dep; anchored to real pikepdf/qpdf " +
		"encrypted PDFs (R4 RC4, R4 AES-128, R6 AES-256).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"data":{"type":"string","description":"The .pdf file contents, base64-encoded (or hex)."}
		},
		"required":["data"]
	}`),
	Required:  []string{"data"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pdfCrackTriageHandler,
}

func pdfCrackTriageHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "data"))
	if in == "" {
		return "", fmt.Errorf("pdf_crack_triage: 'data' is required")
	}
	raw, err := decodeBinaryInput(in)
	if err != nil {
		return "", fmt.Errorf("pdf_crack_triage: %w", err)
	}
	res, err := pdftriage.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("pdf_crack_triage: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
