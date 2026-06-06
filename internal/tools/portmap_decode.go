// portmap_decode.go — host-side ONC RPC portmapper / rpcbind v2 decoder
// Spec, delegating to internal/portmap.
//
// Wrap-vs-native: native — an ONC RPC header (xid / msg type / call or
// reply body of 32-bit XDR fields) + the short portmap procedures;
// byte-field reads + bounded walks, stdlib only. The RPC-enumeration
// (rpcinfo -p) recon decoder: a DUMP reply lists the host's registered
// RPC services + ports. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/portmap"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(portmapDecodeSpec)
}

var portmapDecodeSpec = Spec{
	Name: "portmap_decode",
	Description: "Decode **ONC RPC portmapper / rpcbind v2** messages (Sun RPC program 100000, UDP/TCP 111). " +
		"Enumerating the portmapper is a textbook **LAN-reconnaissance** step (the `rpcinfo -p` technique): " +
		"the **DUMP reply** lists every RPC program a host has registered — **NFS**, **mountd**, **NIS/yp**, " +
		"nlockmgr, statd — with the program number, version, transport and **port**, mapping out the host's " +
		"RPC attack surface; a **GETPORT call** reveals which specific service a client is locating. The " +
		"RPC-enumeration complement to the project's other service-recon decoders.\n\n" +
		"Decodes the ONC RPC header (xid, **CALL** vs **REPLY**) and: for a **CALL** the RPC version, the " +
		"**program** (named — portmapper / nfs / mountd / ypserv / …), program version, the **procedure** " +
		"(named for portmap: NULL / SET / UNSET / GETPORT / DUMP / CALLIT) and auth flavor, plus the GETPORT " +
		"query (target program + version + transport); for a **REPLY** the accept status and the result. " +
		"The **DUMP reply mapping list** (program + version + tcp/udp + port for every registered service) " +
		"is the recon headline.\n\n" +
		"No confidently-wrong output: an RPC reply does not carry the program/procedure it answers (the " +
		"client correlates by xid), so a reply body is typed by **structure** — a DUMP list is reported only " +
		"when it parses exhaustively to a clean value-follows terminator with sane transports, and a bare " +
		"4-byte accepted result as a GETPORT port (an all-zero one is noted as byte-identical to an empty " +
		"DUMP); anything else is surfaced as raw hex. No network, no device, transmits nothing, so it is Low " +
		"risk. The input is the RPC payload without any TCP record marker. ':' / '-' / '_' / whitespace " +
		"separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (Sun-RPC / rpcbind service enumeration recon). Wrap-vs-native: " +
		"native — a byte-field read + bounded XDR walks, stdlib only, no new go.mod dep. Verified " +
		"field-for-field against scapy's ONC RPC + portmap layers.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The ONC RPC portmapper message (the UDP/TCP-111 payload, without any TCP record marker) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   portmapDecodeHandler,
}

func portmapDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("portmap_decode: 'hex' is required")
	}
	res, err := portmap.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("portmap_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
