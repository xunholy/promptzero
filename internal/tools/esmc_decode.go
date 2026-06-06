// esmc_decode.go — host-side ESMC (Ethernet Synchronization Messaging Channel
// / SyncE, ITU-T G.8264) decoder Spec, delegating to internal/esmc.
//
// Wrap-vs-native: native — a fixed 10-byte Slow-Protocol/ESMC header + a short
// TLV stream (the QL TLV is type + length + a 1-byte SSM code); a byte/bit
// read + a TLV walk, stdlib only. The SyncE frequency-sync control-channel
// decoder — surfaces the advertised clock Quality Level + event/information
// type from a captured ESMC frame. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/esmc"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(esmcDecodeSpec)
}

var esmcDecodeSpec = Spec{
	Name: "esmc_decode",
	Description: "Decode an **ESMC (Ethernet Synchronization Messaging Channel)** frame — the control channel of " +
		"**Synchronous Ethernet (SyncE)**, ITU-T G.8264. SyncE distributes a physical-layer frequency " +
		"reference across an Ethernet network (the way SDH/SONET did over TDM); ESMC is the small Slow-Protocol " +
		"frame (EtherType 0x8809, subtype 0x0A) that advertises the **Synchronization Status Message (SSM)** — " +
		"the **Quality Level (QL)** of the clock each node is traceable to. It is the **frequency-sync " +
		"companion to PTP / IEEE 1588** (`ptpv2_decode`, phase/time sync): together they carry the timing plane " +
		"that **5G fronthaul, power-grid teleprotection and broadcast** networks depend on. Timing is an " +
		"emerging **attack surface** — degrading or spoofing the advertised QL can push a network onto a worse " +
		"clock or trigger a sync-loss reconfiguration — so a captured ESMC frame reveals the timing hierarchy: " +
		"the advertised clock **Quality Level** (PRC / SSU / EEC / DNU), whether the frame is a periodic " +
		"**information** heartbeat or an **event** (a QL change), and (in the enhanced TLV) the source clock " +
		"identity.\n\n" +
		"Decodes the 10-byte header (subtype, ITU OUI, ITU subtype, version, event flag) and the TLV stream " +
		"(Quality Level + Enhanced Quality Level).\n\n" +
		"No confidently-wrong output: the header and the QL / Enhanced-QL TLVs were verified field-for-field " +
		"against scapy's ESMC layer. The one genuine ambiguity is the SSM-code → QL name: ITU-T G.781 defines " +
		"option tables (Option I = ETSI/SDH, Option II = ANSI/SONET) that assign **different** names to the " +
		"same 4-bit code, and the in-use option is a deployment setting **not carried on the wire** — so the " +
		"raw SSM code is surfaced together with **both** the Option-I and Option-II names rather than a " +
		"confidently-wrong single answer. A non-ESMC Slow-Protocol subtype is rejected; a malformed TLV stops " +
		"the walk. No network, no device, transmits nothing, so it is Low risk. The input is the Slow-Protocol " +
		"payload (starting at the subtype byte, after the Ethernet header + EtherType 0x8809). ':' / '-' / '_' " +
		"/ whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (timing-network / SyncE recon; the frequency-sync companion to " +
		"ptpv2_decode). Wrap-vs-native: native — a byte/bit read + a TLV walk, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The ESMC frame (the Slow-Protocol payload, starting at the subtype byte 0x0A — after the Ethernet header + EtherType 0x8809) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   esmcDecodeHandler,
}

func esmcDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("esmc_decode: 'hex' is required")
	}
	res, err := esmc.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("esmc_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
