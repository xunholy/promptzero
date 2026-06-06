// sv_decode.go — host-side IEC 61850-9-2 Sampled Values (SV / SMV) decoder
// Spec, delegating to internal/sv.
//
// Wrap-vs-native: native — the same shape as GOOSE: an 8-byte APPID/length/
// reserved header + an ASN.1 BER savPdu (tag 0x60) whose seqASDU (0xA2) holds
// ASDUs (0x30) of context-tagged fields; a deterministic BER walk, stdlib
// only. The substation process-bus sampled-measurement decoder — surfaces the
// stream (svID), the sample counter (smpCnt), the sync source and the raw
// sampled-value block. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/sv"
)

func init() { //nolint:gochecknoinits
	Register(svDecodeSpec)
}

var svDecodeSpec = Spec{
	Name: "sampled_values_decode",
	Description: "Decode an **IEC 61850-9-2 / 9-2LE Sampled Values (SV / SMV)** message — the substation-automation " +
		"multicast that streams digitised **current and voltage samples** from a **merging unit** to the " +
		"protection and measurement IEDs over the process bus. SV rides directly over Ethernet (EtherType " +
		"**0x88BA**, no IP / no UDP) at a high fixed sample rate. It is the sampled-measurement sibling of " +
		"`goose_decode` (EtherType 0x88B8) and a real **substation-security target**: SV is unauthenticated by " +
		"default, so an attacker on the process bus who injects forged SV frames — replaying an old sample " +
		"block or spoofing the **sample counter** — can feed protection relays false current/voltage and " +
		"trigger or block a trip (the SV-injection attack class). A captured SV frame identifies the **stream** " +
		"(svID — the merging unit), the **sample counter** (smpCnt — the per-sample sequence number replay / " +
		"spoof attacks manipulate), the configuration revision, the **synchronisation source** (smpSynch — " +
		"whether the samples are GPS-disciplined), and surfaces the raw sampled-value block — the recon " +
		"headline for process-bus reconnaissance.\n\n" +
		"Decodes the 8-byte APPID / length / reserved header and the ASN.1 BER savPdu: noASDU, the optional " +
		"IEC 62351 security field (raw), and each ASDU's svID, datSet, smpCnt, confRev, refrTm, smpSynch (with " +
		"a clock-source name), smpRate and smpMod.\n\n" +
		"No confidently-wrong output: the savPdu / ASDU tag layout follows the authoritative IEC 61850-9-2 " +
		"ASN.1 (matching Wireshark's sv dissector) — there is no scapy model for SV (nor GOOSE), so " +
		"verification is by the deterministic, byte-checkable BER walk against spec-built vectors. The " +
		"**sampled-value data block itself (the `sample` field) is dataset-configuration-dependent and is " +
		"surfaced as raw hex** (decoding individual channel values without the dataset definition would be " +
		"confidently-wrong), exactly as `goose_decode` surfaces allData; the security field is surfaced raw; a " +
		"missing 0x60 outer tag or a truncated TLV is reported, not guessed. No network, no device, transmits " +
		"nothing, so it is Low risk. The input is the SV message starting at the APPID (after the Ethernet " +
		"header + 0x88BA EtherType). ':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (substation process-bus / IEC 61850 recon; the SV sibling of " +
		"goose_decode). Wrap-vs-native: native — a BER tag/length/value walk, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The IEC 61850-9-2 Sampled Values message starting at the APPID (after the Ethernet header + 0x88BA EtherType) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   svDecodeHandler,
}

func svDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("sampled_values_decode: 'hex' is required")
	}
	res, err := sv.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("sampled_values_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
