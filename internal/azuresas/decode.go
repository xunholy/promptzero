// SPDX-License-Identifier: AGPL-3.0-or-later

// Package azuresas decodes an Azure Storage Shared Access Signature (SAS) token —
// the `?sv=…&sp=…&se=…&sig=…` query string that grants delegated access to Azure
// Blob / Queue / Table / File storage — into its **blast radius**: the SAS type,
// the granted permissions (expanded to human operations), the validity window
// (start / expiry), the scope (service / resource type / resource), the allowed
// IP range and protocol, and any stored-access-policy reference. A leaked SAS
// token (in a URL, a config, a log, a repo) is real cloud-IR / pentest loot, and
// the first question is always "what can this token do, and until when?" — which
// this answers offline. Pure offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. A SAS token is a URL query string; decoding it is a query-param parse
// plus a lookup of Azure's documented single-letter field codes — stdlib
// net/url + maps. The HMAC signature (sig) cannot be verified without the
// account key, so it is reported present-but-opaque, not validated.
//
// # Verifiable / no confidently-wrong output
//
// The field codes and the permission-letter meanings are taken from the Microsoft
// Azure Storage SAS reference (Create service / account / user-delegation SAS),
// and the parse is anchored to that doc's worked example
// (sp=rw&st=…&se=…&sip=…&spr=https&sv=…&sr=b → Read+Write on a blob). Permission
// letters are **context-dependent** (e.g. p = Permissions/ACL for a blob but
// Process for a queue; r = Read for a blob but Query for a table), so they are
// expanded against the resource context derived from sr / ss / tn; a letter with
// no documented meaning in that context is surfaced raw, and an account SAS spans
// services so its letters are noted as service-dependent rather than asserted.
package azuresas

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Result is the decoded view of a SAS token.
type Result struct {
	// Type is "service SAS", "account SAS", or "user delegation SAS".
	Type string `json:"sas_type"`
	// Version is the signedVersion (sv) — the storage API version.
	Version string `json:"version,omitempty"`
	// Services lists the signed services (ss) for an account SAS.
	Services []string `json:"services,omitempty"`
	// ResourceTypes lists the signed resource types (srt) for an account SAS.
	ResourceTypes []string `json:"resource_types,omitempty"`
	// Resource is the signed resource (sr) for a service SAS.
	Resource string `json:"resource,omitempty"`
	// Permissions are the expanded signedPermissions (sp).
	Permissions []string `json:"permissions,omitempty"`
	// PermissionsRaw is the raw sp letters.
	PermissionsRaw string `json:"permissions_raw,omitempty"`
	// Start / Expiry are the validity window (st / se), ISO 8601 as given.
	Start  string `json:"start,omitempty"`
	Expiry string `json:"expiry,omitempty"`
	// IPRange is the allowed source IP / range (sip).
	IPRange string `json:"ip_range,omitempty"`
	// Protocol is the allowed protocol (spr).
	Protocol string `json:"protocol,omitempty"`
	// StoredAccessPolicy is the signed identifier (si) linking a stored policy.
	StoredAccessPolicy string `json:"stored_access_policy,omitempty"`
	// TableName is the table name (tn) for a Table SAS.
	TableName string `json:"table_name,omitempty"`
	// EncryptionScope is the signed encryption scope (ses).
	EncryptionScope string `json:"encryption_scope,omitempty"`
	// HasSignature is true when the opaque sig field is present.
	HasSignature bool `json:"has_signature"`
	// Note carries caveats (account-SAS permission semantics, unknown codes).
	Note string `json:"note,omitempty"`
}

// Decode parses a SAS token — a full URL, or a bare query string with or without
// a leading '?'. It must carry the SAS-defining fields (at least sv + se + sig,
// or sp), else it is rejected as not a SAS token.
func Decode(input string) (*Result, error) {
	q, err := extractQuery(strings.TrimSpace(input))
	if err != nil {
		return nil, err
	}
	if q.Get("sv") == "" && q.Get("sig") == "" && q.Get("sp") == "" {
		return nil, fmt.Errorf("azuresas: no SAS fields found (expected sv / sp / sig) — is this an Azure SAS token?")
	}

	res := &Result{
		Version:            q.Get("sv"),
		Resource:           signedResource[q.Get("sr")],
		Start:              q.Get("st"),
		Expiry:             q.Get("se"),
		IPRange:            q.Get("sip"),
		Protocol:           q.Get("spr"),
		StoredAccessPolicy: q.Get("si"),
		TableName:          q.Get("tn"),
		EncryptionScope:    q.Get("ses"),
		HasSignature:       q.Get("sig") != "",
		PermissionsRaw:     q.Get("sp"),
	}
	if res.Resource == "" && q.Get("sr") != "" {
		res.Resource = "unknown (sr=" + q.Get("sr") + ")"
	}

	res.Services = expandSet(q.Get("ss"), signedServices)
	res.ResourceTypes = expandSet(q.Get("srt"), signedResourceTypes)

	// Determine the SAS type.
	switch {
	case q.Get("skoid") != "" || q.Get("sktid") != "":
		res.Type = "user delegation SAS"
	case q.Get("ss") != "" || q.Get("srt") != "":
		res.Type = "account SAS"
	default:
		res.Type = "service SAS"
	}

	// Expand permissions against the resource context.
	ctx, certain := permissionContext(q)
	res.Permissions = expandPermissions(q.Get("sp"), ctx)
	if !certain && q.Get("sp") != "" {
		res.Note = "permission letters expanded with the common Blob/Container meaning; for a Queue/Table " +
			"or account SAS a letter's exact operation can differ (e.g. p = Process on a queue) — verify " +
			"against the resource type"
	}
	return res, nil
}

// extractQuery returns the query parameters from a full URL or a bare query
// string (with or without '?').
func extractQuery(s string) (url.Values, error) {
	if s == "" {
		return nil, fmt.Errorf("azuresas: empty input")
	}
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[i+1:]
	}
	v, err := url.ParseQuery(s)
	if err != nil {
		return nil, fmt.Errorf("azuresas: not a valid query string: %w", err)
	}
	return v, nil
}

// permissionContext picks the permission table for the SAS's resource and
// reports whether the context is certain (a definite sr / tn signal) vs inferred
// (account SAS spanning services, or a context-free token such as a queue SAS).
func permissionContext(q url.Values) (table map[byte]string, certain bool) {
	switch {
	case q.Get("tn") != "":
		return permTable, true
	case q.Get("sr") == "f" || q.Get("sr") == "s":
		return permFile, true
	case strings.HasPrefix(q.Get("sr"), "b") || q.Get("sr") == "c" || q.Get("sr") == "d":
		return permBlob, true // sr=b/bv/bs/c/d — definite blob/container/directory
	default: // account SAS (ss) or a context-free token: common Blob meaning, noted
		return permBlob, false
	}
}

// expandPermissions maps each permission letter via the context table, keeping
// the SAS letter order and surfacing unknown letters raw.
func expandPermissions(sp string, table map[byte]string) []string {
	if sp == "" {
		return nil
	}
	out := make([]string, 0, len(sp))
	for i := 0; i < len(sp); i++ {
		if name, ok := table[sp[i]]; ok {
			out = append(out, fmt.Sprintf("%c = %s", sp[i], name))
		} else {
			out = append(out, fmt.Sprintf("%c = (unknown in this context)", sp[i]))
		}
	}
	return out
}

// expandSet maps each letter of a multi-letter field (ss / srt) via a table,
// sorted for stable output.
func expandSet(field string, table map[byte]string) []string {
	if field == "" {
		return nil
	}
	out := make([]string, 0, len(field))
	for i := 0; i < len(field); i++ {
		if name, ok := table[field[i]]; ok {
			out = append(out, fmt.Sprintf("%c = %s", field[i], name))
		} else {
			out = append(out, fmt.Sprintf("%c = (unknown)", field[i]))
		}
	}
	sort.Strings(out)
	return out
}

// --- Azure SAS field-code tables (Microsoft Azure Storage SAS reference) ---

var signedServices = map[byte]string{'b': "Blob", 'q': "Queue", 't': "Table", 'f': "File"}

var signedResourceTypes = map[byte]string{'s': "Service", 'c': "Container", 'o': "Object"}

var signedResource = map[string]string{
	"b": "Blob", "bv": "Blob version", "bs": "Blob snapshot",
	"c": "Container", "d": "Directory", "f": "File", "s": "Share",
}

// permBlob is the permission table for Blob / Container / Directory resources.
var permBlob = map[byte]string{
	'r': "Read", 'a': "Add", 'c': "Create", 'w': "Write", 'd': "Delete",
	'x': "Delete version", 'y': "Permanent delete", 'l': "List", 't': "Tags",
	'f': "Find", 'm': "Move", 'e': "Execute", 'o': "Ownership",
	'p': "Permissions (ACL)", 'i': "Set immutability policy",
}

// permFile is the permission table for File / Share resources.
var permFile = map[byte]string{
	'r': "Read", 'c': "Create", 'w': "Write", 'd': "Delete", 'l': "List",
}

// permTable is the permission table for Table resources.
var permTable = map[byte]string{
	'r': "Query", 'a': "Add", 'u': "Update", 'd': "Delete",
}
