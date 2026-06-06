// nlm_decode.go — host-side ONC RPC NFS Lock Manager v4 (NLM, rpc.lockd)
// decoder Spec, delegating to internal/nlm.
//
// Wrap-vs-native: native — the shared internal/oncrpc header + an XDR lock
// argument (cookie, caller name, file handle, lock owner, offset/length);
// byte-field reads + bounded XDR walks, stdlib only. The fourth member of
// the Sun-RPC suite (portmap / mount / nfs / nlm). Surfaces who is locking
// what file across an NFS deployment. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/nlm"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(nlmDecodeSpec)
}

var nlmDecodeSpec = Spec{
	Name: "nlm_decode",
	Description: "Decode the **ONC RPC NFS Lock Manager protocol v4** (NLM, program 100021, **rpc.lockd**) — the " +
		"byte-range / advisory-locking sidecar of NFS. The fourth member of the project's Sun-RPC decoder " +
		"suite (`portmap_decode`, `mount_decode`, `nfs_decode`), sharing their `oncrpc` framing. rpc.lockd is " +
		"a long-standing remote attack surface, and a captured NLM exchange is recon in its own right: a " +
		"**LOCK / TEST / CANCEL / UNLOCK** call carries the **caller name** (the client host identity it " +
		"announces), the **file handle** being locked, the **lock owner** (a client / process identity " +
		"string), the locked **byte range** (offset + length) and whether the lock is **exclusive** — so an " +
		"NLM stream maps which hosts are contending for which files.\n\n" +
		"Decodes the ONC RPC header (xid, CALL vs REPLY), the **procedure name** (TEST / LOCK / CANCEL / " +
		"UNLOCK / GRANTED / *_MSG / *_RES / SHARE / UNSHARE / …) and, for the four core lock calls, the lock " +
		"argument (caller, file handle, owner, svid, offset, length, exclusive). A **reply** is decoded as " +
		"its cookie + the **nlm4_stats** result (GRANTED / DENIED / BLOCKED / DENIED_GRACE_PERIOD / …).\n\n" +
		"No confidently-wrong output: the lock argument is decoded for the four procedures whose XDR layout " +
		"is unambiguous; the async *_MSG / *_RES variants and SHARE / UNSHARE / FREE_ALL are named with their " +
		"body surfaced raw, and a reply status is reported only for a defined nlm4_stats code. No network, no " +
		"device, transmits nothing, so it is Low risk. The input is the RPC payload without any TCP record " +
		"marker. ':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (NFS lock-manager / rpc.lockd recon). Wrap-vs-native: native — " +
		"a byte-field read + bounded XDR walks, stdlib only, no new go.mod dep. Verified field-for-field " +
		"against scapy's NLM layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The NLM ONC RPC message (the lockd payload, without any TCP record marker) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   nlmDecodeHandler,
}

func nlmDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("nlm_decode: 'hex' is required")
	}
	res, err := nlm.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("nlm_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
