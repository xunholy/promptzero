// nfs_decode.go — host-side ONC RPC NFS v3 (RFC 1813) call decoder Spec,
// delegating to internal/nfs.
//
// Wrap-vs-native: native — an ONC RPC header + an XDR procedure body
// (file handles + filenames + offsets); byte-field reads + bounded XDR
// walks, stdlib only. Completes the NFS-recon chain (portmap -> mount ->
// nfs): surfaces the filenames a client accesses + the read/write offsets
// from a captured NFS call stream. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/nfs"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(nfsDecodeSpec)
}

var nfsDecodeSpec = Spec{
	Name: "nfs_decode",
	Description: "Decode **ONC RPC NFS v3** (RFC 1813, program 100003) call messages — the file-access layer that " +
		"completes the project's **NFS-reconnaissance chain** after `portmap_decode` (rpcbind: locate the " +
		"service) and `mount_decode` (get the export root file handle). A captured NFS call stream is the " +
		"record of what a client actually does on the share: the **dir-operation calls carry filenames** — a " +
		"**LOOKUP / CREATE / REMOVE / RENAME / MKDIR / RMDIR** names the exact file being accessed (\"a client " +
		"is reading /etc/shadow off the export\"), and **READ / WRITE** expose the file handle + offset + " +
		"length being transferred. Decoding the calls surfaces the NFS access pattern from a passive " +
		"capture.\n\n" +
		"Decodes the ONC RPC header (xid, CALL vs REPLY), the **procedure name** (all 22 NFSv3 procedures), " +
		"and for calls the recon-bearing leading arguments: the **file handle**, the operand **filename(s)** " +
		"(two, for RENAME), and the **offset + count** for READ / WRITE.\n\n" +
		"No confidently-wrong output: arguments are decoded only for the calls whose leading XDR fields are " +
		"unambiguous; an NFS **reply** is large, procedure-specific and not self-identifying (the client " +
		"correlates by xid), so it is reported as its accept status + a recognised nfsstat3 code with the " +
		"body surfaced raw. No network, no device, transmits nothing, so it is Low risk. The input is the " +
		"RPC payload without any TCP record marker. ':' / '-' / '_' / whitespace separators and a '0x' " +
		"prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (NFS file-access / filename recon). Wrap-vs-native: native — a " +
		"byte-field read + bounded XDR walks, stdlib only, no new go.mod dep. Verified field-for-field " +
		"against scapy's NFS layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The NFS v3 RPC message (the NFS payload, without any TCP record marker) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   nfsDecodeHandler,
}

func nfsDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("nfs_decode: 'hex' is required")
	}
	res, err := nfs.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("nfs_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
