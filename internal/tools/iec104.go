// iec104.go — host-side IEC 60870-5-104 APDU decoder Spec.
// Wraps the internal/iec104 walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/iec104"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(iec104DecodeSpec)
}

var iec104DecodeSpec = Spec{
	Name: "iec104_decode",
	Description: "Decode an IEC 60870-5-104 APDU per IEC TC57. IEC 104 is the European " +
		"/ Asian utility-SCADA telecontrol protocol that runs over TCP/IP — the IP-" +
		"borne sibling of IEC 60870-5-101 (serial) and the de-facto counterpart to " +
		"North American DNP3. Operationally, IEC 104 is the wire format on the " +
		"substation / control-centre boundary in European and Asian power-grid " +
		"operators (TenneT, Amprion, Statnett, State Grid) and in rail / district-" +
		"heat / water-utility operators worldwide. The IEC 61850 process-bus side " +
		"carries GOOSE/MMS, but the station-bus side carrying telecontrol to the " +
		"SCADA master almost always speaks IEC 104 (TCP port 2404). Decodes:\n\n" +
		"- **APCI** (Application Protocol Control Information, 6 bytes): Start " +
		"(0x68 sync) + APDU Length (1-253, bytes after Length) + 4-byte Control " +
		"field.\n" +
		"- **Three frame formats** discriminated by the low 2 bits of Control " +
		"byte 0: **I-format** (Information, bit 0 = 0) carries an ASDU plus 15-" +
		"bit Send Sequence N(S) + 15-bit Receive Sequence N(R); **S-format** " +
		"(Supervisory, bits 0-1 = 01) carries only N(R) for ack-without-piggyback; " +
		"**U-format** (Unnumbered, bits 0-1 = 11) carries no ASDU and uses bits " +
		"2-7 of byte 2 to encode STARTDT / STOPDT / TESTFR as paired *act* + " +
		"*con* link-control commands.\n" +
		"- **U-format function-bit name set**: 0x04 STARTDT_act / 0x08 STARTDT_con " +
		"/ 0x10 STOPDT_act / 0x20 STOPDT_con / 0x40 TESTFR_act / 0x80 TESTFR_con.\n" +
		"- **ASDU** (I-format only, Application Service Data Unit): Type ID + " +
		"Variable Structure Qualifier (bit 7 SQ — sequence-of-elements vs " +
		"sequence-of-objects; bits 0-6 number of elements) + 2-byte Cause of " +
		"Transmission (6-bit cause + bit 6 P/N positive/negative confirm + bit 7 " +
		"T test indicator + 1-byte originator address) + 2-byte Common Address of " +
		"ASDU (uint16 LE; 0xFFFF = broadcast) + Information Objects (surfaced as " +
		"`information_objects_hex` for downstream per-TI walkers).\n" +
		"- **40+ entry Type Identification name table** (selected high-runners " +
		"across monitor-direction, control-direction, and file-transfer): 1 " +
		"M_SP_NA_1 / 3 M_DP_NA_1 / 5 M_ST_NA_1 / 7 M_BO_NA_1 / 9 M_ME_NA_1 / 11 " +
		"M_ME_NB_1 / 13 M_ME_NC_1 / 15 M_IT_NA_1 / 30 M_SP_TB_1 / 35 M_ME_TD_1 / " +
		"36 M_ME_TE_1 / 37 M_ME_TF_1 / 45 C_SC_NA_1 / 46 C_DC_NA_1 / 47 " +
		"C_RC_NA_1 / 48-50 C_SE_NA/NB/NC_1 / 51 C_BO_NA_1 / 58-59 C_SC/DC_TA_1 / " +
		"70 M_EI_NA_1 / 100 C_IC_NA_1 / 101 C_CI_NA_1 / 102 C_RD_NA_1 / 103 " +
		"C_CS_NA_1 / 104 C_TS_NA_1 / 105 C_RP_NA_1 / 106 C_CD_NA_1 / 107 " +
		"C_TS_TA_1 / 110-113 P_ME_*_1, P_AC_NA_1 / 120-126 F_FR/SR/SC/LS/AF/SG/" +
		"DR_*_1.\n" +
		"- **20-entry Cause of Transmission name table**: 1 per/cyc / 2 back / 3 " +
		"spont / 4 init / 5 req / 6 act / 7 actcon / 8 deact / 9 deactcon / 10 " +
		"actterm / 11 retrem / 12 retloc / 13 file / 20 inrogen (general " +
		"interrogation) / 21 inro1 / 22 inro2 / 37 reqcogen (counter " +
		"interrogation) / 44-47 unknown_type / cause / addr / ioa. The P/N and T " +
		"bits in byte 0 of the COT are surfaced as derived `cot_negative_confirm` " +
		"and `cot_test` fields.\n\n" +
		"Pure offline parser — operators paste IEC 104 bytes (starting at the " +
		"0x68 sync) from a `tcpdump -X port 2404` line or a Wireshark IEC 60870-" +
		"5-104 dissector view and get the documented APCI + ASDU breakdown.\n\n" +
		"Out of scope (deferred): transport framing (IEC 104 sits over TCP port " +
		"2404 by default; feed APDU bytes after the TCP-segment-header strip — " +
		"IEC 62351-3 transport-layer auth and IEC 62351-5 application-layer " +
		"security are higher-layer concerns); per-TI Information-Object decoders " +
		"(the per-Type payload for the 60+ catalogued Type IDs is dataset-" +
		"specific; bytes surfaced as `information_objects_hex` for future per-TI " +
		"walkers); multi-frame reassembly (IEC 104 has no transport-layer " +
		"fragmentation; per-APDU N(S)/N(R) sequencing surfaced but k/w window and " +
		"t0/t1/t2/t3 timer state are higher-level); CP56Time2a clock-sync decoding " +
		"(time-tagged TIs 30-40 / 58-59 / 107 / 126 carry the 7-byte CP56Time2a " +
		"inside `information_objects_hex` and are not pre-parsed).\n\n" +
		"Source: docs/catalog/gap-analysis.md (EU/Asian utility-SCADA dissector — " +
		"pairs with dnp3_decode for full bi-continental power-grid SCADA coverage; " +
		"complements the PTPv2 / IEC 61850 substation positioning; targets DEF " +
		"CON ICS Village CTFs + EU/Asia power-grid pentest engagements). Wrap-vs-" +
		"native: native — the IEC 60870-5-104 spec is fully public; APDUs have a " +
		"tight 6-byte APCI plus an optional 6-byte ASDU header followed by per-" +
		"TI Information Objects; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"IEC 60870-5-104 APDU bytes starting at the 0x68 sync (after TCP-segment-header strip; default TCP port 2404). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   iec104DecodeHandler,
}

func iec104DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("iec104_decode: 'hex' is required")
	}
	res, err := iec104.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("iec104_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
