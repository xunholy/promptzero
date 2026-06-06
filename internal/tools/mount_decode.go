// mount_decode.go — host-side NFS MOUNT-protocol (RPC program 100005)
// decoder Spec, delegating to internal/mount.
//
// Wrap-vs-native: native — an ONC RPC header + a short MOUNT body (an XDR
// path, or a status + file handle + auth-flavor list); byte-field reads +
// bounded XDR walks, stdlib only. The NFS-recon companion to portmap:
// surfaces the export path, the mount result, the file handle (FH-reuse
// surface) and the auth flavors (weak-auth detection). Offline read.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/mount"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(mountDecodeSpec)
}

var mountDecodeSpec = Spec{
	Name: "mount_decode",
	Description: "Decode the **NFS MOUNT protocol v3** (RFC 1813, ONC RPC program 100005, mountd) — the service " +
		"that hands a client the root **file handle** for an NFS export. The **NFS-reconnaissance** companion " +
		"to `portmap_decode` (rpcbind): after `rpcinfo` locates mountd, a captured MOUNT exchange exposes the " +
		"NFS attack surface — the exact **export path** a client mounts (`MNT` / `UMNT` call), the **result** " +
		"(a successful mount vs an **MNT3ERR_ACCES** denial — the export's access control in action), the " +
		"**file handle** the server returns (a captured / guessable NFS file handle enables the classic " +
		"**file-handle-reuse** attack), and the **auth flavors** the server accepts (**AUTH_NULL / AUTH_SYS** " +
		"are trivially spoofable — the root of most NFS compromises).\n\n" +
		"Decodes the ONC RPC header (xid, CALL vs REPLY), the **procedure** (NULL / MNT / DUMP / UMNT / " +
		"UMNTALL / EXPORT), the mount **path** on a call, and on a reply the **status** (the full mountstat3 " +
		"set), the **file handle** and the **auth flavor** list.\n\n" +
		"No confidently-wrong output: an RPC reply does not carry the procedure it answers, so a reply body " +
		"is typed as a MOUNT reply only when its first word is a defined mountstat3 code and the file-handle " +
		"+ flavor structure parses within the body — else it is surfaced raw. **EXPORT / DUMP (showmount)** " +
		"are deliberately not decoded: scapy does not model them, so they cannot be differentially verified " +
		"here. No network, no device, transmits nothing, so it is Low risk. The input is the RPC payload " +
		"without any TCP record marker. ':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (NFS MOUNT export / file-handle / weak-auth recon). " +
		"Wrap-vs-native: native — a byte-field read + bounded XDR walks, stdlib only, no new go.mod dep. " +
		"Verified field-for-field against scapy's NFS-MOUNT layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The NFS MOUNT-protocol RPC message (the mountd payload, without any TCP record marker) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   mountDecodeHandler,
}

func mountDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("mount_decode: 'hex' is required")
	}
	res, err := mount.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("mount_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
